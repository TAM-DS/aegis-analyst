from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, Field


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def new_id(prefix: str) -> str:
    return f"{prefix}-{uuid4().hex[:10]}"


class Severity(str, Enum):
    INFORMATIONAL = "informational"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class CaseStatus(str, Enum):
    NEW = "new"
    TRIAGED = "triaged"
    INVESTIGATING = "investigating"
    AWAITING_APPROVAL = "awaiting_approval"
    CONTAINED = "contained"
    CLOSED = "closed"
    REJECTED = "rejected"


class ActionRisk(str, Enum):
    READ = "read"
    WRITE = "write"
    DISRUPTIVE = "disruptive"


class Evidence(BaseModel):
    evidence_id: str = Field(default_factory=lambda: new_id("ev"))
    source: str
    kind: str
    summary: str
    raw: dict[str, Any] = Field(default_factory=dict)
    collected_at: datetime = Field(default_factory=utcnow)


class Finding(BaseModel):
    technique_id: str
    technique_name: str
    tactic: str
    confidence: float
    rationale: str


class RecommendedAction(BaseModel):
    action_id: str = Field(default_factory=lambda: new_id("act"))
    title: str
    description: str
    risk: ActionRisk
    requires_approval: bool
    tool_name: str
    tool_args: dict[str, Any] = Field(default_factory=dict)
    approved: bool | None = None
    executed: bool = False
    execution_result: str | None = None


class CaseBrief(BaseModel):
    case_id: str
    title: str
    status: CaseStatus
    severity: Severity
    confidence: float
    narrative: str
    hypotheses: list[str] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    recommended_actions: list[RecommendedAction] = Field(default_factory=list)
    evidence: list[Evidence] = Field(default_factory=list)
    policy_violations: list[str] = Field(default_factory=list)
    last_updated: datetime = Field(default_factory=utcnow)


class AuditEvent(BaseModel):
    event_id: str = Field(default_factory=lambda: new_id("aud"))
    ts: datetime = Field(default_factory=utcnow)
    actor: str
    action: str
    case_id: str | None = None
    detail: dict[str, Any] = Field(default_factory=dict)


class CaseRecord(BaseModel):
    case_id: str
    title: str
    source: str
    raw_alert: dict[str, Any]
    status: CaseStatus = CaseStatus.NEW
    severity: Severity = Severity.MEDIUM
    created_at: datetime = Field(default_factory=utcnow)
    brief: CaseBrief | None = None
