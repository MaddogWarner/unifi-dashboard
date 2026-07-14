from datetime import datetime

from pydantic import BaseModel, ConfigDict


class ThreatFeedSourceOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    name: str
    url: str
    source_type: str
    enabled: bool
    misp_verify_ssl: bool = False
    last_polled_at: datetime | None
    last_entry_count: int
    last_error: str | None
    created_at: datetime


class ThreatFeedCreate(BaseModel):
    name: str
    url: str
    source_type: str = "url"
    api_key: str | None = None
    misp_verify_ssl: bool = False


class ThreatFeedUpdate(BaseModel):
    name: str | None = None
    url: str | None = None
    enabled: bool | None = None
    api_key: str | None = None
    misp_verify_ssl: bool | None = None


class ThreatFeedZoneRuleOut(BaseModel):
    ruleset: str
    direction: str
    group_count: int
    rule_count: int


class ThreatFeedStatusOut(BaseModel):
    enabled: bool
    apply_mode: str
    direction_mode: str
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
    direction: str
    action: str
    group_name: str
    rule_name: str
    entry_count: int
    status: str
    error: str | None
    created_at: datetime
    decided_at: datetime | None
    applied_at: datetime | None


class ThreatFeedHitsFeedOut(BaseModel):
    feed: str
    hits: int
    unique_sources: int


class ThreatFeedHitsSourceOut(BaseModel):
    ip: str
    hits: int
    feed: str
    last_seen: datetime
    top_dst_port: int | None


class ThreatFeedHitsDailyOut(BaseModel):
    date: str
    hits: int


class ThreatFeedHitsOut(BaseModel):
    window_days: int
    generated_at: datetime
    total_hits: int
    unique_sources: int
    feeds: list[ThreatFeedHitsFeedOut]
    top_sources: list[ThreatFeedHitsSourceOut]
    daily: list[ThreatFeedHitsDailyOut]
