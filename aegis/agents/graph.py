from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from aegis.governance.policy import PolicyEngine
from aegis.memory.store import AuditLog, StructuredStore, VectorMemory
from aegis.schema.models import (
    ActionRisk,
    AuditEvent,
    CaseBrief,
    CaseRecord,
    CaseStatus,
    Evidence,
    Finding,
    RecommendedAction,
    Severity,
    utcnow,
)


SEVERITY_HINTS = {
    "critical": Severity.CRITICAL,
    "ransomware": Severity.CRITICAL,
    "cobalt": Severity.HIGH,
    "mimikatz": Severity.HIGH,
    "lsass": Severity.HIGH,
    "exfil": Severity.HIGH,
    "beacon": Severity.HIGH,
    "phishing": Severity.MEDIUM,
    "bruteforce": Severity.MEDIUM,
    "scan": Severity.LOW,
}


ATTCK = [
    ("T1059.001", "PowerShell", "Execution", ("powershell", "-enc", "iex(")),
    ("T1003.001", "LSASS Memory", "Credential Access", ("lsass", "mimikatz", "sekurlsa")),
    ("T1071.001", "Web Protocols", "Command and Control", ("beacon", "c2", "https://")),
    ("T1566.001", "Spearphishing Attachment", "Initial Access", ("macro", "invoice", ".xlsm", "phish")),
    ("T1486", "Data Encrypted for Impact", "Impact", ("encrypt", "ransom", ".locked")),
    ("T1048", "Exfiltration Over Alternative Protocol", "Exfiltration", ("exfil", "unusual outbound", "large upload")),
    ("T1110", "Brute Force", "Credential Access", ("failed logon", "bruteforce", "password spray")),
    ("T1021.001", "Remote Desktop Protocol", "Lateral Movement", ("rdp", "3389", "unusual logon")),
]


@dataclass
class GraphState:
    case: CaseRecord
    query: str = ""
    notes: list[str] = field(default_factory=list)
    retrieved: list[dict[str, Any]] = field(default_factory=list)
    telemetry: list[dict[str, Any]] = field(default_factory=list)


class AnalystGraph:
    """Constrained multi-agent loop.

    Nodes: ingest -> retrieve -> hunt -> hypothesize -> plan -> govern -> brief
    Policy is a separate node that can veto plan items. LLM is optional and
    never owns severity, ATT&CK mapping, or execution.
    """

    def __init__(
        self,
        store: StructuredStore,
        memory: VectorMemory,
        audit: AuditLog,
        policy: PolicyEngine,
    ) -> None:
        self.store = store
        self.memory = memory
        self.audit = audit
        self.policy = policy

    def run(self, case: CaseRecord, operator_note: str = "") -> CaseBrief:
        state = GraphState(case=case, query=operator_note or case.title)
        for node in (
            self._retrieve,
            self._hunt,
            self._hypothesize,
            self._plan,
            self._govern,
        ):
            state = node(state)
            self.audit.write(
                AuditEvent(
                    actor="graph",
                    action=node.__name__,
                    case_id=case.case_id,
                    detail={"note": state.notes[-1] if state.notes else ""},
                )
            )
        brief = self._brief(state)
        case.brief = brief
        case.status = brief.status
        case.severity = brief.severity
        self.store.upsert_case(case)
        return brief

    def _retrieve(self, state: GraphState) -> GraphState:
        blob = " ".join(
            [
                state.case.title,
                state.query,
                str(state.case.raw_alert),
            ]
        )
        state.retrieved = self.memory.search(blob, k=6)
        state.notes.append(f"retrieved {len(state.retrieved)} knowledge hits")
        return state

    def _hunt(self, state: GraphState) -> GraphState:
        alert = state.case.raw_alert
        filters = {}
        for key in ("host", "user", "hash"):
            if alert.get(key):
                filters[key] = alert[key]
        state.telemetry = self.store.query_telemetry(**filters)
        state.notes.append(f"hunt returned {len(state.telemetry)} telemetry rows")
        return state

    def _hypothesize(self, state: GraphState) -> GraphState:
        text = " ".join(
            [
                state.case.title.lower(),
                json_blob(state.case.raw_alert),
                " ".join(str(t) for t in state.telemetry),
            ]
        )
        findings: list[Finding] = []
        for tid, name, tactic, needles in ATTCK:
            hits = [n for n in needles if n in text]
            if hits:
                findings.append(
                    Finding(
                        technique_id=tid,
                        technique_name=name,
                        tactic=tactic,
                        confidence=min(0.92, 0.55 + 0.12 * len(hits)),
                        rationale=f"Matched indicators: {', '.join(hits)}",
                    )
                )
        state.case.brief = state.case.brief or CaseBrief(
            case_id=state.case.case_id,
            title=state.case.title,
            status=CaseStatus.INVESTIGATING,
            severity=infer_severity(text),
            confidence=0.5,
            narrative="",
            findings=findings,
        )
        state.case.brief.findings = findings
        state.case.brief.severity = infer_severity(text)
        state.case.brief.hypotheses = build_hypotheses(findings, state.case.raw_alert)
        state.notes.append(f"{len(findings)} ATT&CK mappings")
        return state

    def _plan(self, state: GraphState) -> GraphState:
        alert = state.case.raw_alert
        actions: list[RecommendedAction] = [
            RecommendedAction(
                title="Enrich file hash",
                description="Reputation lookup against allowlisted intel tool",
                risk=ActionRisk.READ,
                requires_approval=False,
                tool_name="enrich_hash",
                tool_args={"hash": alert.get("hash", "unknown")},
            ),
            RecommendedAction(
                title="Pull host telemetry",
                description="Structured store query for host / user activity",
                risk=ActionRisk.READ,
                requires_approval=False,
                tool_name="query_telemetry",
                tool_args={"host": alert.get("host"), "user": alert.get("user")},
            ),
        ]
        findings = state.case.brief.findings if state.case.brief else []
        ids = {f.technique_id for f in findings}
        if {"T1003.001", "T1486", "T1071.001"} & ids and alert.get("host"):
            actions.append(
                RecommendedAction(
                    title="Isolate host",
                    description=f"Propose EDR isolation for {alert.get('host')}",
                    risk=ActionRisk.DISRUPTIVE,
                    requires_approval=True,
                    tool_name="isolate_host",
                    tool_args={"host": alert.get("host")},
                )
            )
        if "T1110" in ids and alert.get("user"):
            actions.append(
                RecommendedAction(
                    title="Disable user",
                    description=f"Propose IdP disable for {alert.get('user')}",
                    risk=ActionRisk.DISRUPTIVE,
                    requires_approval=True,
                    tool_name="disable_user",
                    tool_args={"user": alert.get("user")},
                )
            )
        if alert.get("domain"):
            actions.append(
                RecommendedAction(
                    title="Block domain",
                    description=f"Propose DNS/proxy block for {alert.get('domain')}",
                    risk=ActionRisk.DISRUPTIVE,
                    requires_approval=True,
                    tool_name="block_domain",
                    tool_args={"domain": alert.get("domain")},
                )
            )
        assert state.case.brief
        state.case.brief.recommended_actions = actions
        state.notes.append(f"planned {len(actions)} actions")
        return state

    def _govern(self, state: GraphState) -> GraphState:
        assert state.case.brief
        state.case.brief = self.policy.gate_brief(state.case.brief)
        state.notes.append(f"policy violations={len(state.case.brief.policy_violations)}")
        return state

    def _brief(self, state: GraphState) -> CaseBrief:
        brief = state.case.brief
        assert brief
        conf = 0.4 + 0.1 * len(brief.findings) + 0.05 * len(state.telemetry)
        brief.confidence = min(0.93, conf)
        brief.evidence = [
            Evidence(source="alert", kind="detection", summary=state.case.title, raw=state.case.raw_alert),
            *[
                Evidence(
                    source="knowledge",
                    kind="intel",
                    summary=d["text"][:240],
                    raw=d.get("meta", {}),
                )
                for d in state.retrieved[:3]
            ],
            *[
                Evidence(
                    source="telemetry",
                    kind="edr",
                    summary=f"{t.get('host')} {t.get('process')} {t.get('command_line')}",
                    raw=t,
                )
                for t in state.telemetry[:5]
            ],
        ]
        brief.narrative = render_narrative(brief, state)
        brief.status = (
            CaseStatus.AWAITING_APPROVAL
            if any(a.requires_approval for a in brief.recommended_actions)
            else CaseStatus.TRIAGED
        )
        brief.last_updated = utcnow()
        return brief


def infer_severity(text: str) -> Severity:
    for needle, sev in SEVERITY_HINTS.items():
        if needle in text:
            return sev
    return Severity.MEDIUM


def build_hypotheses(findings: list[Finding], alert: dict) -> list[str]:
    if not findings:
        return ["Benign admin activity or noisy detection — collect more evidence before containment."]
    hypos = [f"Activity aligns to {f.technique_id} {f.technique_name} ({f.tactic})" for f in findings[:3]]
    if alert.get("user") and alert.get("host"):
        hypos.append(
            f"Account {alert['user']} on {alert['host']} is the current blast-radius center."
        )
    return hypos


def render_narrative(brief: CaseBrief, state: GraphState) -> str:
    techniques = ", ".join(f"{f.technique_id} {f.technique_name}" for f in brief.findings) or "none mapped"
    return (
        f"Case {brief.case_id} is assessed {brief.severity.value} with confidence {brief.confidence:.2f}. "
        f"ATT&CK mapping: {techniques}. "
        f"Hunt pulled {len(state.telemetry)} related telemetry rows and {len(state.retrieved)} knowledge hits. "
        f"{len([a for a in brief.recommended_actions if a.requires_approval])} action(s) sit behind an approval gate. "
        "Containment is simulated only; the sandbox will not touch production."
    )


def json_blob(obj: Any) -> str:
    import json

    return json.dumps(obj).lower()
