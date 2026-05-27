from typing import Literal

from pydantic import BaseModel


class CheckResultOut(BaseModel):
    check_id: str
    label: str
    status: Literal["pass", "warn", "fail"]
    detail: str
    recommendation: str


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
