# AEGIS | Governed AI Security Operations

**An AI security analyst that can recommend containment—but cannot authorize itself to execute it.**

AEGIS is a runnable security operations prototype that turns seeded alerts and telemetry into an analyst brief, maps indicators to MITRE ATT&CK, proposes response actions, and puts disruptive actions behind a human-approval gate.

> **The model may narrate. It does not execute. Policy is code.**

**The architectural question:** How do you accelerate security analysis without giving an AI-driven workflow uncontrolled authority over production systems?

AEGIS answers with a deterministic analyst graph, a separate Python policy engine, an allowlisted execution sandbox, explicit operator controls, and an audit trail. The current implementation runs without an LLM or API key. It makes no real EDR, identity-provider, or network changes.

## The incident: a recommendation is not authorization

A seeded case suggests ransomware activity on a legal file server. Its indicators map to **MITRE ATT&CK T1486 — Data Encrypted for Impact**. AEGIS produces a case brief and recommends isolating the host.

That recommendation matters. So does the potential business disruption of taking the wrong machine offline.

The operator selects **Isolate host** and clicks **Run** before approving it.

```text
DENIED: approval required for isolate_host
```

No isolation tool is invoked. The recommendation does not grant itself execution authority.

When the operator chooses **Approve + execute**, the allowlisted sandbox returns a *simulation*:

```text
[SIMULATED] EDR isolation requested for fs-legal-02.
Ticket opened. Host remains reachable until SOC confirms.
```

The distinction is deliberate: **an isolation request is not proof that a host has been isolated.** AEGIS reports what its simulated tool actually did, not what a security analyst might wish had happened.

The operator can also **Deny** the recommendation, with no sandbox call.

## See the control boundary

These are screenshots of the actual three-panel operator console, not conceptual mockups.

| 01 · Analyze | 02 · Enforce |
| --- | --- |
| ![Critical case analyzed with ATT&CK T1486 and a recommended action](docs/screenshots/01-analyze.png) | ![Unapproved isolation request denied by the sandbox](docs/screenshots/02-deny-or-run-denied.png) |
| The analyst graph creates an evidence-backed brief and proposes a response. | The operator attempts a disruptive action; the approval gate denies execution. |

| 03 · Authorize and simulate | 04 · Investigate |
| --- | --- |
| ![Operator-approved simulated isolation result](docs/screenshots/03-approve-simulated.png) | ![Analyst dialogue for the open security case](docs/screenshots/04-analysis-chat.png) |
| The approved action reaches an allowlisted simulation—not a production EDR. | The operator can inspect the case and continue analysis in context. |

**Console layout**

- **Left:** case queue, operator note, and audit tail.
- **Center:** case brief and analyst dialogue.
- **Right:** severity, confidence, ATT&CK findings, recommended actions, and Run / Approve / Deny controls.

## What the system does

| Capability | Implementation | Why it matters |
| --- | --- | --- |
| Case investigation | A named, deterministic analyst graph retrieves lexical context, hunts SQLite telemetry, maps indicators to ATT&CK, and builds a brief. | The investigative workflow is inspectable and reproducible without depending on model output. |
| Response planning | The graph proposes read actions and, where indicated, disruptive actions such as host isolation. | Analysis produces concrete next steps without silently executing them. |
| Policy enforcement | A separate Python policy engine flags violations and forces approval for disruptive recommendations. | The approval requirement is enforced in code rather than requested in a prompt. |
| Execution boundary | An allowlisted sandbox rejects unknown tools and unapproved actions that require approval. | The runtime limits which simulated capabilities can be invoked. |
| Operator control | The UI exposes Run, Approve + execute, and Deny. | A human makes the explicit decision to authorize a disruptive action. |
| Auditability | Graph steps and runtime execution/denial events are written to a JSONL audit log. | A reviewer can trace the simulated workflow and its decisions. |

**Seeded investigation scenarios**

- Encoded PowerShell, LSASS access, and beaconing (`T1059.001`, `T1003.001`, `T1071.001`).
- Spearphishing through an invoice attachment (`T1566.001`).
- VPN password spraying (`T1110`).
- File-share encryption consistent with a ransomware pattern (`T1486`).

These are seeded demonstration cases. ATT&CK mapping and the displayed confidence values are rule-based and heuristic; they are not independently validated detections or statistically calibrated probabilities.

## Architecture: intelligence, policy, and execution are separate

```text
Alert + operator note
        |
        v
  Analyst graph
  retrieve --> hunt --> hypothesize --> plan
        |         |          |            |
  lexical     SQLite      ATT&CK      proposed
  memory      telemetry   rules       actions
        |
        v
  Python policy engine
  classify / flag / require approval
        |
        v
  Case brief + three-panel operator console
        |
        +--> Deny ----------------------> No tool call
        |
        +--> Run without approval -----> Sandbox denies
        |
        +--> Approve + execute --------> Allowlisted sandbox
                                              |
                                              v
                                        Simulated result
                                              |
                                              v
                                           Audit log
```

**Data and runtime components**

- **Structured store:** SQLite for cases and telemetry (`data/aegis.db`).
- **Retrieval:** in-process lexical overlap search; no embedding model or vector database is required.
- **Analyst graph:** explicit Python stages rather than an opaque, all-purpose prompt.
- **Governance:** `PolicyEngine` evaluates recommended actions and marks disruptive actions as requiring approval.
- **Sandbox:** registered, allowlisted Python tools for read operations and simulated response actions; no shell, outbound network calls, or production integrations.
- **Audit:** append-style JSONL events at `data/audit/events.jsonl`. This is a local demonstration log, not a tamper-evident enterprise audit service.

The policy engine and sandbox have different responsibilities. Policy evaluates the *recommendation*; the sandbox enforces its tool allowlist and the approval flag at the *execution boundary*. Neither relies on an LLM's promise to behave.

### Monster-light now; Monster-heavy is a possible extension

**Implemented:** the default, deterministic Monster-light analyst workflow. It runs locally without an API key. Severity inference, ATT&CK mapping, action planning, governance, and simulated execution are implemented in Python.

**Potential extension, not a shipped capability:** an LLM could help phrase the analyst narrative. It would not receive ownership of severity rules, approval decisions, tool registration, or execution.

This is the same larger design question explored by the Monster projects: what may an intelligent system propose, what may it execute, and which controls must sit between the two?

## Engineering decisions and trade-offs

### Why simulate containment instead of wiring in a real EDR?

A public portfolio repo should be safe to run and inspect. The default `isolate_host` tool returns a simulated request, not a CrowdStrike or SentinelOne API call. The result explicitly says the host remains reachable. Real containment would require an owned environment, authorized integrations, change control, and verification of actual execution state.

**Trade-off:** reviewers can exercise the control path safely, but this prototype does not demonstrate a production EDR integration or confirm real-world containment.

### Why use an explicit Python graph rather than add LangGraph?

The workflow already has named stages—retrieve, hunt, hypothesize, plan, and govern—with audit events for each. A new orchestration dependency would need to solve a concrete problem, not merely change the branding of the implementation.

**Trade-off:** the graph is easy to follow, but it does not claim distributed orchestration, durable retries, or production-scale agent scheduling.

### Why lexical retrieval instead of a vectorized CVE catalog?

The demonstration is about acting responsibly on a live-looking incident, not answering general vulnerability questions. Lexical context and structured telemetry support a small, reproducible investigation without embedding infrastructure.

**Trade-off:** retrieval is deliberately narrow. It is not a production threat-intelligence or semantic-search system.

## Validation and failure modes

The repository includes automated tests for its core governance demonstration. The tests in `tests/test_policy_and_graph.py` exercise:

| Test | Expected behavior |
| --- | --- |
| A disruptive action is initially marked as not requiring approval. | The policy engine forces `requires_approval=True`. |
| A caller supplies an action ID that is not on the analyzed case. | The runtime rejects the request with `Action not found`. |
| A disruptive action is submitted without approval. | The sandbox returns `DENIED`; the same action can reach a simulated result when approved. |

These tests demonstrate specific controls; they are **not** a comprehensive security assessment. In particular, this prototype does not implement authenticated approval identities, production authorization, tamper-evident logging, or independent confirmation of real containment. The demo's approval input should not be mistaken for an enterprise-grade authorization service.

**The key failure mode addressed:** a correct-looking recommendation must not bypass the action boundary simply because an agent produced it.

## Run locally

Requirements: Python 3 and the dependencies in `requirements.txt`. The commands below use a macOS/Linux shell.

```bash
git clone https://github.com/TAM-DS/aegis-analyst.git
cd aegis-analyst
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python app.py
```

Open **http://127.0.0.1:7860**.

1. Choose a case by title in the queue and select **Analyze case**.
2. Inspect the brief, findings, confidence, and recommended actions.
3. Select a read action and use **Run**, or select **Isolate host** and attempt **Run** before approval.
4. Confirm the disruptive action is denied. Then choose **Approve + execute** to see the simulated result, or **Deny** to take no action.
5. Inspect the audit tail.

Run the included tests:

```bash
pip install pytest
python -m pytest tests/ -q
```

In PyCharm or Cursor, select `.venv` as the interpreter and run `app.py`.

## The architectural takeaway

AEGIS is not intended to demonstrate an autonomous SOC or replace an experienced analyst. It demonstrates a narrower and more important boundary: **an AI-driven workflow may assemble evidence and recommend a disruptive response, but the system—not the model—controls whether that response can execute.**

That principle applies beyond security operations. Whether an agent wants to isolate a server or place a trade, capability is only useful when authority, verification, and accountability are designed into the workflow.

**A recommendation is not authorization. A simulated request is not a completed action.**
