from datetime import datetime

from pydantic import BaseModel, ConfigDict


class ThreatEventOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    timestamp: datetime
    signature_id: str | None
    signature_name: str | None
    category: str | None
    severity: str | None
    src_ip: str | None
    dst_ip: str | None
    action: str | None


class IdsStatusOut(BaseModel):
    enabled: bool
    mode: str | None
    categories: list[str]
    sensitivity: str | None
    synced_at: datetime | None
    gaps: list[str]
