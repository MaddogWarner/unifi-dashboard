from datetime import datetime

from pydantic import BaseModel, ConfigDict


class FirewallPolicyOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    unifi_id: str
    name: str
    action: str
    src_zone: str | None
    dst_zone: str | None
    enabled: bool
    protocol: str | None
    schedule: str | None
    synced_at: datetime
    hit_count: int = 0


class FirewallRuleOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    unifi_id: str
    name: str
    action: str
    ruleset: str | None
    rule_index: int | None
    enabled: bool
    src_address: str | None
    dst_address: str | None
    protocol: str | None
    dst_port: str | None
    synced_at: datetime


class FirewallLogOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    timestamp: datetime
    rule_name: str | None
    action: str
    src_ip: str | None
    dst_ip: str | None
    src_port: int | None
    dst_port: int | None
    protocol: str | None
    interface: str | None
    direction: str | None
    matched_policy_id: int | None
    raw_line: str


class FirewallZoneOut(BaseModel):
    name: str
    networks: list[str] = []
    policy_count: int = 0


class PolicySnapshotOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    snapshot_type: str
    snapshot_hash: str
    created_at: datetime


class DriftDiffOut(BaseModel):
    from_snapshot: int
    to_snapshot: int
    added: list[dict]
    removed: list[dict]
    changed: list[dict]


class DriftLatestOut(BaseModel):
    latest_snapshot: PolicySnapshotOut | None
    previous_snapshot: PolicySnapshotOut | None
    diff: DriftDiffOut | None
