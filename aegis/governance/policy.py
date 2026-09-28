from __future__ import annotations

from aegis.schema.models import ActionRisk, CaseBrief, RecommendedAction, Severity

SEVERITY_RANK = {
    Severity.INFORMATIONAL: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}

# Deterministic rules. LLMs do not get a vote here.
DISRUPTIVE_TOOLS = {"isolate_host", "disable_user", "block_domain", "kill_process"}
PII_MARKERS = ("ssn", "social security", "passport", "credit card")


class PolicyEngine:
    """Governance is code. Narrative models propose; this engine disposes."""

    def evaluate_action(self, brief: CaseBrief, action: RecommendedAction) -> list[str]:
        violations: list[str] = []
        if action.tool_name in DISRUPTIVE_TOOLS and action.risk != ActionRisk.DISRUPTIVE:
            violations.append(f"{action.tool_name} must be tagged disruptive")
        if action.risk == ActionRisk.DISRUPTIVE and not action.requires_approval:
            violations.append(f"{action.tool_name} requires human approval")
        if SEVERITY_RANK[brief.severity] >= SEVERITY_RANK[Severity.HIGH] and brief.confidence < 0.45:
            violations.append("high/critical case with low confidence cannot auto-execute")
        blob = (action.title + " " + action.description).lower()
        if any(m in blob for m in PII_MARKERS):
            violations.append("action text appears to contain or request raw PII")
        return violations

    def gate_brief(self, brief: CaseBrief) -> CaseBrief:
        violations: list[str] = []
        gated: list[RecommendedAction] = []
        for action in brief.recommended_actions:
            v = self.evaluate_action(brief, action)
            if action.risk == ActionRisk.DISRUPTIVE:
                action.requires_approval = True
            if v:
                violations.extend(v)
                action.requires_approval = True
            gated.append(action)
        brief.recommended_actions = gated
        brief.policy_violations = violations
        return brief
