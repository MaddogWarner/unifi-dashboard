from datetime import datetime

from pydantic import BaseModel, ConfigDict


class ThreatFeedSourceOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    name: str
    url: str
    enabled: bool
    last_polled_at: datetime | None
    last_entry_count: int
    last_error: str | None
    created_at: datetime


class ThreatFeedCreate(BaseModel):
    name: str
    url: str


class ThreatFeedUpdate(BaseModel):
    name: str | None = None
    url: str | None = None
    enabled: bool | None = None


class ThreatFeedZoneRuleOut(BaseModel):
    ruleset: str
    group_count: int
    rule_count: int


class ThreatFeedStatusOut(BaseModel):
    enabled: bool
    apply_mode: str
    last_updated: datetime | None
    total_entries: int
    pending_count: int
    zone_rules: list[ThreatFeedZoneRuleOut]


class ThreatFeedEntryOut(BaseModel):
    id: int
    cidr: str
    feed_source_name: str
    added_at: datetime


class ThreatFeedEntryList(BaseModel):
    total: int
    items: list[ThreatFeedEntryOut]


class ThreatFeedPendingRuleOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    ruleset: str
    chunk_index: int
    action: str
    group_name: str
    rule_name: str
    entry_count: int
    status: str
    error: str | None
    created_at: datetime
    decided_at: datetime | None
    applied_at: datetime | None
