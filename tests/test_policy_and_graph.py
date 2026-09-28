from aegis.app import AegisRuntime
from aegis.governance.policy import PolicyEngine
from aegis.schema.models import ActionRisk, CaseBrief, CaseStatus, RecommendedAction, Severity


def test_disruptive_actions_require_approval():
    brief = CaseBrief(
        case_id="case-test",
        title="t",
        status=CaseStatus.INVESTIGATING,
        severity=Severity.HIGH,
        confidence=0.8,
        narrative="n",
        recommended_actions=[
            RecommendedAction(
                title="Isolate",
                description="isolate host",
                risk=ActionRisk.DISRUPTIVE,
                requires_approval=False,
                tool_name="isolate_host",
                tool_args={"host": "x"},
            )
        ],
    )
    gated = PolicyEngine().gate_brief(brief)
    assert gated.recommended_actions[0].requires_approval is True


def test_unknown_tool_is_denied():
    rt = AegisRuntime()
    labels = rt.list_labels()
    assert labels
    brief = rt.analyze(labels[0], "initial triage")
    assert brief.findings or brief.severity in Severity
    denied = rt.execute(labels[0], "missing-action", approved=True)
    assert "Action not found" in denied


def test_sandbox_blocks_unapproved_disruptive():
    rt = AegisRuntime()
    label = rt.list_labels()[0]
    brief = rt.analyze(label, "containment check")
    disruptive = next(a for a in brief.recommended_actions if a.requires_approval)
    result = rt.execute(label, disruptive.action_id, approved=False)
    assert result.startswith("DENIED")
    ok = rt.execute(label, disruptive.action_id, approved=True)
    assert "SIMULATED" in ok or "READ" in ok
