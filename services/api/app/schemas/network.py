from datetime import datetime

from pydantic import BaseModel, ConfigDict


class NetworkOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    unifi_id: str
    name: str
    vlan_id: int | None
    zone: str | None
    subnet: str | None
    purpose: str | None
    enabled: bool
    synced_at: datetime
