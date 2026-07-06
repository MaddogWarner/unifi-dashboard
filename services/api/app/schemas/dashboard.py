from datetime import datetime
from typing import Literal

from pydantic import BaseModel


class AttentionItemOut(BaseModel):
    severity: Literal["critical", "warning", "info"]
    category: Literal["connectivity", "assessment", "conflict", "cve", "syslog", "threat"]
    title: str
    detail: str
    link: str
    timestamp: datetime | None = None


class DashboardStatusOut(BaseModel):
    unifi_reachable: bool
    assessment_score: int | None
    last_policy_sync: datetime | None
    last_syslog_event: datetime | None
    threat_events_24h: int


class DashboardAttentionOut(BaseModel):
    generated_at: datetime
    status: DashboardStatusOut
    items: list[AttentionItemOut]
