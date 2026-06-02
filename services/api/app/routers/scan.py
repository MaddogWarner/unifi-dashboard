import asyncio
import json
from datetime import UTC, datetime

import httpx
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from app.audit import audit_event
from app.auth import current_active_user
from app.config import settings
from app.database import async_session_factory, get_db
from app.models.scan import ScanResult
from app.models.user import User
from app.schemas.scan import ScanRequest, ScanResultOut, ScanTriggerOut

router = APIRouter()


async def _run_scan(scan_id: int, request: ScanRequest) -> None:
    async with async_session_factory() as session:
        scan = await session.get(ScanResult, scan_id)
        if scan is None:
            return
        scan.status = "running"
        await session.commit()
    try:
        async with httpx.AsyncClient(timeout=130) as client:
            response = await client.post(
                f"{settings.scanner_base_url}/scan",
                json={"target": request.target, "ports": request.ports, "scan_type": request.scan_type},
            )
            response.raise_for_status()
            payload = response.json()
        status = "done"
        result_json = json.dumps(payload)
        output = None
    except Exception as exc:
        status = "error"
        result_json = json.dumps({"error": str(exc)})
        output = str(exc)
    async with async_session_factory() as session:
        scan = await session.get(ScanResult, scan_id)
        if scan is None:
            return
        scan.status = status
        scan.result_json = result_json
        scan.nmap_output = output
        scan.completed_at = datetime.now(UTC)
        await session.commit()


@router.post("/", response_model=ScanTriggerOut)
async def trigger_scan(
    request: ScanRequest,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(current_active_user),
) -> ScanTriggerOut:
    scan = ScanResult(
        target_ip=request.target,
        scan_type=request.scan_type,
        ports_requested=request.ports,
        status="pending",
        triggered_by=request.triggered_by,
        created_at=datetime.now(UTC),
    )
    db.add(scan)
    await db.commit()
    await db.refresh(scan)
    audit_event(
        "scan.triggered",
        user=user,
        scan_id=scan.id,
        target=request.target,
        scan_type=request.scan_type,
        ports=request.ports,
    )
    asyncio.create_task(_run_scan(scan.id, request))
    return ScanTriggerOut(scan_id=scan.id)


@router.get("/{scan_id}", response_model=ScanResultOut)
async def get_scan(scan_id: int, db: AsyncSession = Depends(get_db)) -> ScanResultOut:
    scan = await db.get(ScanResult, scan_id)
    if scan is None:
        raise HTTPException(404, "Scan result not found")
    return scan
