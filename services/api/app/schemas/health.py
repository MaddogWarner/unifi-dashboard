from pydantic import BaseModel


class HealthOut(BaseModel):
    status: str
    unifi_reachable: bool
    db_ok: bool
