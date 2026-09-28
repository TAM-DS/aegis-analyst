from __future__ import annotations

import re

import gradio as gr

from aegis.app import AegisRuntime
from aegis.schema.models import CaseBrief


CSS = """
.aegis-header {font-family: ui-sans-serif, system-ui; letter-spacing: 0.04em;}
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
    return f"""# {brief.title}

**Case** `{brief.case_id}`  
**Status** `{brief.status.value}` · **Severity** `{brief.severity.value}` · **Confidence** `{brief.confidence:.2f}`

## Narrative
{brief.narrative}

## Hypotheses
{hypos}

## ATT&CK
{findings}

## Recommended actions
{actions}

## Evidence
{evidence}

## Policy gate
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
        return "No case loaded."
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

    with gr.Blocks(title="Aegis Analyst") as demo:
        gr.Markdown(
            "# AEGIS ANALYST\n"
            "Governed senior SOC analyst — multi-agent reasoner with a deterministic policy engine. "
            "Disruptive actions never execute without an approval gate. Execution is sandboxed and simulated."
        )
        with gr.Row():
            with gr.Column(scale=1):
                gr.Markdown("### Case queue")
                labels = rt.list_labels()
                queue = gr.Dropdown(
                    choices=labels,
                    value=labels[0] if labels else None,
                    label="Open case",
                    interactive=True,
                )
                refresh = gr.Button("Refresh queue")
                note = gr.Textbox(label="Operator note", placeholder="What do you want the analyst to weigh?")
                analyze_btn = gr.Button("Analyze case", variant="primary")
                gr.Markdown("### Audit tail")
                audit_box = gr.Textbox(label="Recent audit events", lines=14)
            with gr.Column(scale=2):
                gr.Markdown("### Case brief")
                brief_md = gr.Markdown("_Select a case, then click Analyze case._")
                chat = gr.Chatbot(label="Analyst dialogue", height=280)
                chat_in = gr.Textbox(label="Ask the analyst about the open case")
                chat_send = gr.Button("Send")
            with gr.Column(scale=1):
                gr.Markdown("### Structured metadata")
                meta = gr.Textbox(label="Live case fields", lines=10)
                action_pick = gr.Dropdown(
                    label="Recommended action",
                    choices=[],
                    interactive=True,
                    info="Pick an action, then Run, Approve, or Deny. No ID paste.",
                )
                with gr.Row():
                    run_read = gr.Button("Run")
                    approve = gr.Button("Approve + execute", variant="primary")
                deny = gr.Button("Deny")
                exec_out = gr.Textbox(label="Sandbox result", lines=6)

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
                return "Analyze a case and select an action first."
            return rt.execute(label, aid, approved=approved_flag)

        refresh.click(lambda: refresh_queue(), outputs=queue)
        analyze_btn.click(
            do_analyze,
            [queue, note, chat],
            [brief_md, meta, chat, audit_box, action_pick, queue],
        )
        chat_send.click(do_chat, [queue, chat_in, chat], [chat, chat_in])
        run_read.click(lambda l, a: run_action(l, a, False), [queue, action_pick], exec_out)
        approve.click(lambda l, a: run_action(l, a, True), [queue, action_pick], exec_out)
        deny.click(lambda: "Operator denied. No sandbox call issued.", outputs=exec_out)

    return demo


def main() -> None:
    demo = build_ui()
    demo.launch(theme=gr.themes.Soft(), css=CSS)


if __name__ == "__main__":
    main()
