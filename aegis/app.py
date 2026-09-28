from __future__ import annotations

from aegis.agents.graph import AnalystGraph
from aegis.governance.policy import PolicyEngine
from aegis.ingest.seed import seed_all
from aegis.memory.store import AuditLog, StructuredStore, VectorMemory
from aegis.sandbox.runtime import ExecutionSandbox, SandboxDenied, default_tools
from aegis.schema.models import AuditEvent, CaseBrief, CaseRecord


class AegisRuntime:
    def __init__(self) -> None:
        self.store = StructuredStore()
        self.memory = VectorMemory()
        self.audit = AuditLog()
        self.policy = PolicyEngine()
        self.graph = AnalystGraph(self.store, self.memory, self.audit, self.policy)
        self.sandbox = ExecutionSandbox()
        for name, fn in default_tools().items():
            self.sandbox.register(name, fn)
        self.cases = seed_all(self.store, self.memory)

    def list_labels(self) -> list[str]:
        return [self._label(c) for c in self.store.list_cases()]

    def case_from_label(self, label: str) -> CaseRecord | None:
        import re

        match = re.search(r"case-[a-f0-9]+", label or "")
        if not match:
            return None
        return self.store.get_case(match.group(0))

    def analyze(self, label: str, note: str = "") -> CaseBrief:
        rec = self.case_from_label(label)
        if not rec:
            raise ValueError("case not found")
        self.audit.write(AuditEvent(actor="operator", action="analyze", case_id=rec.case_id, detail={"note": note}))
        return self.graph.run(rec, note)

    def execute(self, label: str, action_id: str, approved: bool) -> str:
        rec = self.case_from_label(label)
        if not rec or not rec.brief:
            return "Analyze the case before executing an action."
        action = next((a for a in rec.brief.recommended_actions if a.action_id == action_id), None)
        if not action:
            return "Action not found on this case."
        try:
            result = self.sandbox.execute(action, approved=approved)
        except SandboxDenied as exc:
            self.audit.write(
                AuditEvent(
                    actor="sandbox",
                    action="denied",
                    case_id=rec.case_id,
                    detail={"action_id": action_id, "reason": str(exc)},
                )
            )
            return f"DENIED: {exc}"
        action.executed = True
        action.approved = approved
        action.execution_result = result
        rec.brief.recommended_actions = [
            action if a.action_id == action_id else a for a in rec.brief.recommended_actions
        ]
        self.store.upsert_case(rec)
        self.audit.write(
            AuditEvent(
                actor="operator",
                action="execute",
                case_id=rec.case_id,
                detail={"action_id": action_id, "approved": approved, "result": result},
            )
        )
        return result

    @staticmethod
    def _label(c: CaseRecord) -> str:
        return f"{c.title} — {c.severity.value.upper()} · {c.status.value} · {c.case_id}"
