from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any

from aegis.schema.models import AuditEvent, CaseRecord, CaseStatus, Severity

ROOT = Path(__file__).resolve().parents[2]
DB_PATH = ROOT / "data" / "aegis.db"
AUDIT_PATH = ROOT / "data" / "audit" / "events.jsonl"


class StructuredStore:
    """SQLite case + telemetry store. This is the source of truth."""

    def __init__(self, path: Path = DB_PATH) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        self.path = path
        self._init()

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.path), timeout=30)
        conn.row_factory = sqlite3.Row
        return conn

    def _init(self) -> None:
        with self._conn() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS cases (
                    case_id TEXT PRIMARY KEY,
                    title TEXT NOT NULL,
                    source TEXT NOT NULL,
                    raw_alert TEXT NOT NULL,
                    status TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    brief TEXT
                );
                CREATE TABLE IF NOT EXISTS telemetry (
                    event_id TEXT PRIMARY KEY,
                    host TEXT,
                    user TEXT,
                    process TEXT,
                    command_line TEXT,
                    dest_ip TEXT,
                    dest_port INTEGER,
                    hash TEXT,
                    ts TEXT,
                    tags TEXT
                );
                """
            )

    def upsert_case(self, rec: CaseRecord) -> None:
        with self._conn() as conn:
            conn.execute(
                """
                INSERT INTO cases(case_id,title,source,raw_alert,status,severity,created_at,brief)
                VALUES(?,?,?,?,?,?,?,?)
                ON CONFLICT(case_id) DO UPDATE SET
                    title=excluded.title,
                    status=excluded.status,
                    severity=excluded.severity,
                    brief=excluded.brief
                """,
                (
                    rec.case_id,
                    rec.title,
                    rec.source,
                    json.dumps(rec.raw_alert),
                    rec.status.value,
                    rec.severity.value,
                    rec.created_at.isoformat(),
                    rec.brief.model_dump_json() if rec.brief else None,
                ),
            )

    def get_case(self, case_id: str) -> CaseRecord | None:
        with self._conn() as conn:
            row = conn.execute("SELECT * FROM cases WHERE case_id=?", (case_id,)).fetchone()
        if not row:
            return None
        return self._row_to_case(row)

    def list_cases(self) -> list[CaseRecord]:
        with self._conn() as conn:
            rows = conn.execute("SELECT * FROM cases ORDER BY created_at DESC").fetchall()
        return [self._row_to_case(r) for r in rows]

    def _row_to_case(self, row: sqlite3.Row) -> CaseRecord:
        from aegis.schema.models import CaseBrief

        brief = CaseBrief.model_validate_json(row["brief"]) if row["brief"] else None
        return CaseRecord(
            case_id=row["case_id"],
            title=row["title"],
            source=row["source"],
            raw_alert=json.loads(row["raw_alert"]),
            status=CaseStatus(row["status"]),
            severity=Severity(row["severity"]),
            created_at=row["created_at"],
            brief=brief,
        )

    def insert_telemetry(self, rows: list[dict[str, Any]]) -> None:
        with self._conn() as conn:
            conn.executemany(
                """
                INSERT OR REPLACE INTO telemetry
                (event_id,host,user,process,command_line,dest_ip,dest_port,hash,ts,tags)
                VALUES(:event_id,:host,:user,:process,:command_line,:dest_ip,:dest_port,:hash,:ts,:tags)
                """,
                rows,
            )

    def query_telemetry(self, **filters: Any) -> list[dict[str, Any]]:
        clauses: list[str] = []
        params: list[Any] = []
        for key, val in filters.items():
            if val is None or val == "":
                continue
            clauses.append(f"{key} = ?")
            params.append(val)
        where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
        with self._conn() as conn:
            rows = conn.execute(f"SELECT * FROM telemetry{where} LIMIT 50", params).fetchall()
        return [dict(r) for r in rows]


class VectorMemory:
    """Tiny lexical memory. Intentional: retrieval is evidence, not magic embeddings."""

    def __init__(self) -> None:
        self.docs: list[dict[str, Any]] = []

    def add(self, doc_id: str, text: str, meta: dict[str, Any] | None = None) -> None:
        tokens = set(self._tok(text))
        self.docs.append({"id": doc_id, "text": text, "tokens": tokens, "meta": meta or {}})

    def search(self, query: str, k: int = 5) -> list[dict[str, Any]]:
        q = set(self._tok(query))
        scored = []
        for d in self.docs:
            overlap = len(q & d["tokens"])
            if overlap:
                scored.append({**d, "score": overlap / max(len(q), 1)})
        scored.sort(key=lambda x: x["score"], reverse=True)
        return scored[:k]

    @staticmethod
    def _tok(text: str) -> list[str]:
        return [t.lower() for t in text.replace("/", " ").replace("-", " ").split() if len(t) > 2]


class AuditLog:
    def __init__(self, path: Path = AUDIT_PATH) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        self.path = path

    def write(self, event: AuditEvent) -> None:
        line = event.model_dump_json() + "\n"
        try:
            with self.path.open("a", encoding="utf-8") as f:
                f.write(line)
        except OSError:
            fallback = Path("/tmp/aegis-audit.jsonl")
            with fallback.open("a", encoding="utf-8") as f:
                f.write(line)
            self.path = fallback

    def tail(self, n: int = 40) -> list[AuditEvent]:
        if not self.path.exists():
            return []
        lines = self.path.read_text(encoding="utf-8").splitlines()[-n:]
        return [AuditEvent.model_validate_json(line) for line in lines]
