import asyncio
from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.collectors.cve_collector import run_cve_collector_once
from app.database import get_db
from app.models.cve import CVEAlert, CVEDeviceLink, DeviceInventory
from app.schemas.cve import CVEAlertOut, CVEListResponse, DeviceInventoryOut

router = APIRouter()


@router.get("/alerts", response_model=CVEListResponse)
async def get_cve_alerts(
    severity: str | None = None,
    acknowledged: bool | None = False,
    skip: int = 0,
    limit: int = Query(default=50, le=200),
    db: AsyncSession = Depends(get_db),
) -> CVEListResponse:
    stmt = select(CVEAlert)
    if severity:
        stmt = stmt.where(CVEAlert.severity == severity.upper())
    if acknowledged is False:
        stmt = stmt.where(CVEAlert.acknowledged_at.is_(None))
    total = (await db.execute(select(func.count()).select_from(stmt.subquery()))).scalar() or 0
    alerts = (
        await db.scalars(stmt.order_by(CVEAlert.cvss_score.desc().nullslast()).offset(skip).limit(limit))
    ).all()
    items = []
    for alert in alerts:
        device_names = (
            await db.scalars(
                select(DeviceInventory.name)
                .join(CVEDeviceLink, CVEDeviceLink.device_id == DeviceInventory.id)
                .where(CVEDeviceLink.cve_id == alert.cve_id)
            )
        ).all()
        items.append(
            CVEAlertOut.model_validate(
                {**alert.__dict__, "affected_devices": [name for name in device_names if name]}
            )
        )
    return CVEListResponse(total=total, items=items)


@router.post("/alerts/{alert_id}/acknowledge")
async def acknowledge_cve(alert_id: int, db: AsyncSession = Depends(get_db)) -> dict[str, bool]:
    alert = await db.get(CVEAlert, alert_id)
    if not alert:
        raise HTTPException(404, "CVE alert not found")
    alert.acknowledged_at = datetime.now(UTC)
    await db.commit()
    return {"ok": True}


@router.get("/devices", response_model=list[DeviceInventoryOut])
async def get_devices(db: AsyncSession = Depends(get_db)) -> list[DeviceInventoryOut]:
    devices = (await db.scalars(select(DeviceInventory).order_by(DeviceInventory.name))).all()
    result = []
    for device in devices:
        cve_ids = (
            await db.scalars(select(CVEDeviceLink.cve_id).where(CVEDeviceLink.device_id == device.id))
        ).all()
        result.append(
            DeviceInventoryOut.model_validate({**device.__dict__, "active_cves": list(cve_ids)})
        )
    return result


@router.post("/refresh")
async def refresh_cve() -> dict[str, str | bool]:
    asyncio.create_task(run_cve_collector_once())
    return {"ok": True, "message": "CVE refresh triggered"}
