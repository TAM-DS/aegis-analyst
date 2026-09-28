# AEGIS ANALYST

Governed senior SOC analyst agent with a three-panel operator console.

This is not RAG over a CVE list. Aegis is a constrained multi-agent decision system for the part of SOC work that burns juniors: triage, hypothesis, ATT&CK mapping, action planning, and the moment someone almost isolates the wrong host.

The model may narrate. It does not get to execute. Policy is code.

## Why this exists

SOC queues punish hesitation and punish reckless containment equally. Most "AI for security" demos hide that tradeoff behind a chat box.

Aegis makes the tradeoff visible:

- **Monster-light** (default): deterministic analyst graph. No API key. Reproducible briefs.
- **Monster-heavy** (optional later): LLM only for narrative polish. Severity, ATT&CK, approval, and sandbox stay deterministic.
- **Governance**: disruptive tools always require an operator gate.
- **Sandbox**: allowlisted simulated actions. No shell, no network, no prod side effects.
- **Audit**: every graph node and every execute/deny is appended to `data/audit/events.jsonl`.

This continues the same thesis as `monster-heavy`, `agent-foundry`, and `secure-agent-execution-environment`: capability without a boundary is not a product.

## Architecture

```
alert + operator note
        |
        v
   ingest / seed
        |
        v
 retrieve (lexical memory) -> hunt (SQLite telemetry)
        |
        v
 hypothesize (ATT&CK rules) -> plan (actions)
        |
        v
 govern (policy engine) -- veto / force approval
        |
        v
 brief + operator UI
        |
        v
 sandbox execute (only if allowlisted + approved)
        |
        v
 audit log
```

Stores:

- **Structured**: SQLite cases + telemetry (`data/aegis.db`)
- **Vector-ish**: in-process lexical overlap memory (deliberately not a magic embedding demo)
- **Audit**: append-only JSONL

## Operator UI

Gradio Blocks, three panels:

| Left | Center | Right |
| --- | --- | --- |
| Case queue, operator note, audit tail | Case brief + analyst dialogue | Severity, confidence, ATT&CK, action IDs, approve/deny |

## Run locally (macOS + PyCharm)

```bash
cd aegis-analyst
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python app.py
```

PyCharm: open the folder as a project, set the venv as the interpreter, run `app.py`.

Open the local Gradio URL. Pick a seeded case. Click **Analyze case**. Copy an action id from the brief. Use **Run** for read tools or **Approve + execute** for isolation / disable / block.

Seeded cases:

- Encoded PowerShell + LSASS + beacon
- Spearphish invoice macro
- VPN password spray
- Legal share encryption / ransomware pattern

## Tests

```bash
python -m pytest tests/ -q
```

These tests exist to prove the hiring point: unapproved disruptive actions are denied by the sandbox.

## What a reviewer should notice

1. Agents are a state machine with named nodes, not a single prompt.
2. Policy is not a system prompt. It is Python that can force `requires_approval`.
3. Tools cannot be invented at runtime. Unknown tools are denied.
4. Execution is simulated on purpose. That is the product, not a missing feature.
5. The UI is an operator console, not a chatbot skin.

## Repo intent

Portfolio system for Tracy Manning / TAM-DS. Built to be cloned, run, and attacked by a hiring manager in one sitting.
