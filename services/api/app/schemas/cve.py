from datetime import datetime

from pydantic import BaseModel, ConfigDict


class CVEAlertOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    cve_id: str
    title: str | None
    description: str | None
    severity: str
    cvss_score: float | None
    published_at: datetime | None
    source: str
    ubiquiti_bulletin_url: str | None
    acknowledged_at: datetime | None
    affected_devices: list[str] = []
    created_at: datetime


class CVEListResponse(BaseModel):
    total: int
    items: list[CVEAlertOut]


class DeviceInventoryOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    name: str | None
    model: str | None
    firmware_version: str | None
    ip_address: str | None
    synced_at: datetime | None
    active_cves: list[str] = []
