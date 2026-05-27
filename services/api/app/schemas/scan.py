from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class ScanRequest(BaseModel):
    target: str
    ports: str = Field(default="22,80,443,8080", max_length=256)
    scan_type: Literal["connect", "syn", "udp"] = "connect"
    triggered_by: str | None = Field(default=None, max_length=128)


class ScanTriggerOut(BaseModel):
    scan_id: int


class ScanResultOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    target_ip: str
    scan_type: str
    ports_requested: str
    status: str
    result_json: str | None
    nmap_output: str | None
    triggered_by: str | None
    created_at: datetime
    completed_at: datetime | None


class ScannerPortOut(BaseModel):
    port: int
    protocol: str
    state: str
    service: str
    reason: str
