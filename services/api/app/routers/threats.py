import json
from datetime import datetime

from fastapi import APIRouter, Depends, Query
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models.network import IdsConfig
from app.models.threat import ThreatEvent
from app.schemas.threat import IdsStatusOut, ThreatEventOut

router = APIRouter()


@router.get("/events", response_model=list[ThreatEventOut])
async def list_threats(
    skip: int = 0,
    limit: int = Query(default=100, le=1000),
    src_ip: str | None = None,
    from_ts: datetime | None = None,
    to_ts: datetime | None = None,
    db: AsyncSession = Depends(get_db),
) -> list[ThreatEventOut]:
    stmt = select(ThreatEvent)
    if src_ip:
        stmt = stmt.where(ThreatEvent.src_ip == src_ip)
    if from_ts:
        stmt = stmt.where(ThreatEvent.timestamp >= from_ts)
    if to_ts:
        stmt = stmt.where(ThreatEvent.timestamp <= to_ts)
    result = await db.scalars(stmt.order_by(ThreatEvent.timestamp.desc()).offset(skip).limit(limit))
    return list(result.all())


@router.get("/ids-status", response_model=IdsStatusOut)
async def ids_status(db: AsyncSession = Depends(get_db)) -> IdsStatusOut:
    config = await db.scalar(select(IdsConfig).order_by(IdsConfig.synced_at.desc()).limit(1))
    if config is None:
        return IdsStatusOut(
            enabled=False,
            mode=None,
            categories=[],
            sensitivity=None,
            synced_at=None,
            gaps=["IDS/IPS configuration has not been synced from UniFi."],
        )
    categories = json.loads(config.categories or "[]")
    gaps = []
    if not config.enabled:
        gaps.append("IDS/IPS is disabled.")
    if config.mode != "ips":
        gaps.append("IPS prevention mode is not active.")
    return IdsStatusOut(
        enabled=config.enabled,
        mode=config.mode,
        categories=categories,
        sensitivity=config.sensitivity,
        synced_at=config.synced_at,
        gaps=gaps,
    )
