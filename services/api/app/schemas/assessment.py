from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict


class AssessmentEvidenceOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    type: str
    target_ip: str | None = None
    port: int | None = None
    protocol: str | None = None
    service: str | None = None
    reason: str | None = None
    source: str | None = None
    matched_name: str | None = None
    scan_id: int | None = None
    observed_at: datetime | None = None


class CheckResultOut(BaseModel):
    check_id: str
    label: str
    status: Literal["pass", "warn", "fail"]
    detail: str
    recommendation: str
    evidence: list[AssessmentEvidenceOut] | None = None


class AssessmentReportOut(BaseModel):
    score: int
    pass_count: int
    warn_count: int
    fail_count: int
    checks: list[CheckResultOut]


class ConflictReportOut(BaseModel):
    policy_a_id: int
    policy_b_id: int
    conflict_type: str
    description: str
