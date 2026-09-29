from __future__ import annotations

import re

import gradio as gr

from aegis.app import AegisRuntime
from aegis.schema.models import CaseBrief


CSS = """
:root { --aegis-navy: #11243a; --aegis-blue: #356b98; --aegis-red: #a94444; }
.gradio-container { max-width: 1600px !important; }
.aegis-header { border: 1px solid #344e68; border-radius: 14px; padding: 22px 26px;
  background: linear-gradient(120deg, #10243a, #24465f); color: #f2f6fb; }
.aegis-header h1 { color: #ffffff !important; letter-spacing: .08em; margin-bottom: 6px; }
.aegis-header p { color: #dce7f2 !important; margin-bottom: 4px; }
.aegis-guide { border-left: 4px solid #5689b5; padding: 10px 14px; border-radius: 8px;
  background: rgba(85, 133, 177, .10); }
.aegis-guide p { margin: 0; }
.aegis-section h3 { letter-spacing: .02em; }
.aegis-container { line-height: 1.5; }
.aegis-container .prose { line-height: 1.55; }
"""


def format_brief(brief: CaseBrief | None) -> str:
    if not brief:
        return "_Select a case and run Analyze._"
    findings = "\n".join(
        f"- `{f.technique_id}` **{f.technique_name}** ({f.tactic}) — {f.rationale} [{f.confidence:.2f}]"
        for f in brief.findings
    ) or "- none"
    hypos = "\n".join(f"- {h}" for h in brief.hypotheses) or "- none"
    actions = "\n".join(
        f"- `{a.action_id}` **{a.title}** [{a.risk.value}] "
        f"{'APPROVAL REQUIRED' if a.requires_approval else 'read-ok'} "
        f"{'\u2713 executed' if a.executed else ''}\n  {a.description}"
        for a in brief.recommended_actions
    ) or "- none"
    evidence = "\n".join(f"- ({e.source}/{e.kind}) {e.summary}" for e in brief.evidence[:8]) or "- none"
    violations = "\n".join(f"- {v}" for v in brief.policy_violations) or "- none"
    approvals = sum(a.requires_approval and not a.executed for a in brief.recommended_actions)
    return f"""# {brief.title}

**{brief.severity.value.upper()} severity** · **{brief.status.value.replace('_', ' ').title()}** ·
Rule-based confidence **{brief.confidence:.2f}** · Case `{brief.case_id}`

> **Decision status:** {approvals} disruptive action(s) awaiting explicit approval.
> Recommendations do not authorize execution; containment results are simulated.

## Analyst assessment
{brief.narrative}

## Evidence reviewed
{evidence}

## ATT&CK mapping
{findings}

## Working hypotheses
{hypos}

## Proposed next actions
{actions}

## Policy checks
{violations}
"""


def action_choices(brief: CaseBrief | None) -> list[str]:
    if not brief:
        return []
    rows = []
    for a in brief.recommended_actions:
        gate = "APPROVAL REQUIRED" if a.requires_approval else "read-ok"
        done = " · executed" if a.executed else ""
        rows.append(f"{a.title} [{a.risk.value} · {gate}{done}] · {a.action_id}")
    return rows


def action_id_from_choice(choice: str) -> str:
    if not choice:
        return ""
    match = re.search(r"act-[a-f0-9]+", choice)
    return match.group(0) if match else ""


def format_meta(brief: CaseBrief | None) -> str:
    if not brief:
        return "Analyze a case to see severity, ATT&CK mapping, and approval requirements."
    techs = ", ".join(f.technique_id for f in brief.findings) or "\u2014"
    pending = [a for a in brief.recommended_actions if a.requires_approval and not a.executed]
    return (
        f"severity: {brief.severity.value}\n"
        f"confidence: {brief.confidence:.2f}\n"
        f"status: {brief.status.value}\n"
        f"techniques: {techs}\n"
        f"approval_queue: {len(pending)}\n"
        f"policy_violations: {len(brief.policy_violations)}"
    )


def build_ui() -> gr.Blocks:
    rt = AegisRuntime()

    with gr.Blocks(title="Aegis Analyst", elem_classes=["aegis-container"]) as demo:
        gr.Markdown(
            "# AEGIS ANALYST\n"
            "**GOVERNED SECURITY OPERATIONS**  ·  Paper-only response simulation\n\n"
            "Investigate seeded cases, review evidence, and make explicit response decisions. "
            "Policy—not the analyst narrative—controls which simulated actions can run.",
            elem_classes=["aegis-header"],
        )
        gr.Markdown(
            "**WORKFLOW**  01 · Select and analyze a case  →  "
            "02 · Review evidence and proposed actions  →  "
            "03 · Run a read-only action, deny, or explicitly approve a simulated response.",
            elem_classes=["aegis-guide"],
        )
        with gr.Row():
            with gr.Column(scale=1):
                gr.Markdown("### 01 · Incident queue", elem_classes=["aegis-section"])
                labels = rt.list_labels()
                queue = gr.Dropdown(
                    choices=labels,
                    value=labels[0] if labels else None,
                    label="Open case",
                    interactive=True,
                )
                refresh = gr.Button("Refresh queue")
                note = gr.Textbox(label="Investigation note (optional)", placeholder="Add context or a question for this investigation.")
                analyze_btn = gr.Button("Analyze selected case", variant="primary")
                with gr.Accordion("Local audit trail · expand to inspect decisions", open=False):
                    audit_box = gr.Textbox(label="Recent audit events", lines=9, interactive=False)
            with gr.Column(scale=2):
                gr.Markdown("### 02 · Investigation brief", elem_classes=["aegis-section"])
                brief_md = gr.Markdown("_Select a case and choose Analyze selected case to see its evidence, ATT&CK mapping, and proposed response._")
                with gr.Accordion("Case dialogue · optional deterministic summary", open=False):
                    chat = gr.Chatbot(label="Analyst dialogue", height=220)
                    chat_in = gr.Textbox(label="Case question", placeholder="Re-analyze to apply a new investigation note.")
                    chat_send = gr.Button("Send")
            with gr.Column(scale=1):
                gr.Markdown("### 03 · Decision and controls", elem_classes=["aegis-section"])
                meta = gr.Textbox(label="Case status · rule-based indicators", lines=7, interactive=False)
                action_pick = gr.Dropdown(
                    label="Recommended action",
                    choices=[],
                    interactive=True,
                    info="Read-only actions can run directly. Disruptive actions require explicit approval.",
                )
                with gr.Row():
                    run_read = gr.Button("Run without approval")
                    approve = gr.Button("Approve + simulate", variant="primary")
                deny = gr.Button("Deny selected action")
                exec_out = gr.Textbox(label="Execution decision · simulated result", lines=6, interactive=False)
                gr.Markdown(
                    "**Execution boundary:** unapproved disruptive actions are denied. "
                    "An approved containment request remains a simulation; it does not isolate a real host."
                )

        def refresh_queue(selected: str | None = None):
            labels = rt.list_labels()
            value = selected if selected in labels else None
            if value is None:
                cid = re.search(r"case-[a-f0-9]+", selected or "")
                if cid:
                    value = next((row for row in labels if cid.group(0) in row), None)
            if value is None:
                value = labels[0] if labels else None
            return gr.update(choices=labels, value=value)

        def empty_actions():
            return gr.update(choices=[], value=None)

        def do_analyze(label, operator_note, history):
            history = history or []
            if not label:
                return "_Pick a case._", "No case loaded.", history, audit_text(), empty_actions(), refresh_queue(label)
            try:
                brief = rt.analyze(label, operator_note)
            except Exception as exc:
                err = f"Analyze failed: {exc}"
                history = history + [
                    {"role": "user", "content": operator_note or "(analyze)"},
                    {"role": "assistant", "content": err},
                ]
                return err, err, history, audit_text(), empty_actions(), refresh_queue(label)
            msg = f"Analyzed {brief.case_id} as {brief.severity.value} ({brief.confidence:.2f})."
            history = history + [
                {"role": "user", "content": operator_note or "(analyze)"},
                {"role": "assistant", "content": msg},
            ]
            choices = action_choices(brief)
            action_update = gr.update(choices=choices, value=choices[0] if choices else None)
            return format_brief(brief), format_meta(brief), history, audit_text(), action_update, refresh_queue(label)

        def do_chat(label, text, history):
            history = history or []
            if not label or not text:
                return history, ""
            rec = rt.case_from_label(label)
            if not rec or not rec.brief:
                brief = rt.analyze(label, text)
            else:
                brief = rec.brief
            answer = (
                f"{brief.narrative}\n\n"
                f"Techniques: {', '.join(f.technique_id for f in brief.findings) or 'none'}. "
                f"Ask me to analyze again if you changed the operator note."
            )
            history = history + [
                {"role": "user", "content": text},
                {"role": "assistant", "content": answer},
            ]
            return history, ""

        def audit_text() -> str:
            events = rt.audit.tail(18)
            return "\n".join(
                f"{e.ts.isoformat(timespec='seconds')} {e.actor} {e.action} {e.case_id or ''}" for e in events
            )

        def run_action(label, choice, approved_flag):
            aid = action_id_from_choice(choice)
            if not label or not aid:
                return (
                    "Analyze a case and select an action first.",
                    audit_text(), gr.update(), gr.update(), gr.update(),
                )
            result = rt.execute(label, aid, approved=approved_flag)
            rec = rt.case_from_label(label)
            brief = rec.brief if rec else None
            choices = action_choices(brief)
            selected = choice if choice in choices else (choices[0] if choices else None)
            return (
                result,
                audit_text(),
                format_brief(brief),
                format_meta(brief),
                gr.update(choices=choices, value=selected),
            )

        refresh.click(lambda: refresh_queue(), outputs=queue)
        analyze_btn.click(
            do_analyze,
            [queue, note, chat],
            [brief_md, meta, chat, audit_box, action_pick, queue],
        )
        chat_send.click(do_chat, [queue, chat_in, chat], [chat, chat_in])
        decision_outputs = [exec_out, audit_box, brief_md, meta, action_pick]
        run_read.click(lambda l, a: run_action(l, a, False), [queue, action_pick], decision_outputs)
        approve.click(lambda l, a: run_action(l, a, True), [queue, action_pick], decision_outputs)
        deny.click(lambda: "Operator denied. No sandbox call issued.", outputs=exec_out)

    return demo


def main() -> None:
    demo = build_ui()
    demo.launch(theme=gr.themes.Soft(), css=CSS)


if __name__ == "__main__":
    main()
