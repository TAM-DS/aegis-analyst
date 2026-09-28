from __future__ import annotations

from aegis.memory.store import StructuredStore, VectorMemory
from aegis.schema.models import CaseRecord, new_id

KNOWLEDGE = [
    (
        "kb-lsass",
        "LSASS memory access followed by outbound HTTPS to a rare domain is a high-fidelity credential theft + C2 pattern (T1003.001, T1071.001).",
        {"attck": "T1003.001"},
    ),
    (
        "kb-phish-macro",
        "Invoice-themed XLSM macros that spawn powershell -enc remain a common initial access path (T1566.001, T1059.001).",
        {"attck": "T1566.001"},
    ),
    (
        "kb-ransom",
        "Mass file rename plus ransom note and backup store access is impact, not just execution. Isolate early (T1486).",
        {"attck": "T1486"},
    ),
    (
        "kb-spray",
        "Password spray is noisy. Disable only after confirming the account is not a shared break-glass identity (T1110).",
        {"attck": "T1110"},
    ),
    (
        "kb-policy",
        "Aegis policy: disruptive tools always require a human approval gate. Simulated execution never implies production change.",
        {"type": "policy"},
    ),
]

TELEMETRY = [
    {
        "event_id": "tel-001",
        "host": "wrk-finance-14",
        "user": "j.patel",
        "process": "powershell.exe",
        "command_line": "powershell -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA",
        "dest_ip": "185.243.112.44",
        "dest_port": 443,
        "hash": "eicar-bad",
        "ts": "2026-09-28T12:04:11Z",
        "tags": "encoded,beacon",
    },
    {
        "event_id": "tel-002",
        "host": "wrk-finance-14",
        "user": "j.patel",
        "process": "lsass.exe",
        "command_line": "unknown handle duplication toward lsass",
        "dest_ip": "",
        "dest_port": 0,
        "hash": "",
        "ts": "2026-09-28T12:04:19Z",
        "tags": "credential-access",
    },
    {
        "event_id": "tel-003",
        "host": "dc-01",
        "user": "svc-backup",
        "process": "winword.exe",
        "command_line": "WINWORD.EXE Invoice_Q3_Final.xlsm",
        "dest_ip": "",
        "dest_port": 0,
        "hash": "macro-doc-01",
        "ts": "2026-09-27T18:11:02Z",
        "tags": "macro,phish",
    },
    {
        "event_id": "tel-004",
        "host": "vpn-gw",
        "user": "a.chen",
        "process": "sshd",
        "command_line": "failed logon burst 48 attempts",
        "dest_ip": "203.0.113.9",
        "dest_port": 22,
        "hash": "",
        "ts": "2026-09-28T07:40:00Z",
        "tags": "bruteforce",
    },
    {
        "event_id": "tel-005",
        "host": "fs-legal-02",
        "user": "SYSTEM",
        "process": "unknown.exe",
        "command_line": "encrypt share\\\\legal\\matters",
        "dest_ip": "",
        "dest_port": 0,
        "hash": "ransom-bad",
        "ts": "2026-09-28T03:12:44Z",
        "tags": "ransom,encrypt",
    },
]

ALERTS = [
    {
        "title": "Encoded PowerShell + LSASS access on wrk-finance-14",
        "source": "EDR",
        "raw": {
            "host": "wrk-finance-14",
            "user": "j.patel",
            "hash": "eicar-bad",
            "domain": "cdn-updates-live.net",
            "process": "powershell.exe",
            "signal": "powershell -enc plus lsass handle + rare beacon",
        },
    },
    {
        "title": "Spearphish invoice macro from external sender",
        "source": "Email Gateway",
        "raw": {
            "host": "dc-01",
            "user": "svc-backup",
            "hash": "macro-doc-01",
            "domain": "invoices-secure-files.com",
            "process": "winword.exe",
            "signal": "macro invoice.xlsm spawned child process",
        },
    },
    {
        "title": "Password spray against VPN gateway",
        "source": "IdP / VPN",
        "raw": {
            "host": "vpn-gw",
            "user": "a.chen",
            "hash": "",
            "domain": "",
            "process": "sshd",
            "signal": "failed logon bruteforce 48 attempts",
        },
    },
    {
        "title": "Possible ransomware encryption on legal file share",
        "source": "File Integrity",
        "raw": {
            "host": "fs-legal-02",
            "user": "SYSTEM",
            "hash": "ransom-bad",
            "domain": "",
            "process": "unknown.exe",
            "signal": "encrypt share ransomware note pattern",
        },
    },
]


def seed_all(store: StructuredStore, memory: VectorMemory) -> list[CaseRecord]:
    if store.list_cases():
        for doc_id, text, meta in KNOWLEDGE:
            memory.add(doc_id, text, meta)
        return store.list_cases()

    store.insert_telemetry(TELEMETRY)
    for doc_id, text, meta in KNOWLEDGE:
        memory.add(doc_id, text, meta)

    cases: list[CaseRecord] = []
    for alert in ALERTS:
        rec = CaseRecord(
            case_id=new_id("case"),
            title=alert["title"],
            source=alert["source"],
            raw_alert=alert["raw"],
        )
        store.upsert_case(rec)
        cases.append(rec)
    return cases
