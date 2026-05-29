import logging

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models.firewall import FirewallPolicy, FirewallPortForward, FirewallRule
from app.models.network import IdsConfig, Network
from app.models.scan import ScanResult
from app.schemas.assessment import AssessmentReportOut, CheckResultOut, ConflictReportOut
from app.services.assessment import run_checks
from app.services.policy_engine import detect_conflicts

router = APIRouter()
log = logging.getLogger(__name__)


@router.get("/", response_model=AssessmentReportOut)
async def assessment(db: AsyncSession = Depends(get_db)) -> AssessmentReportOut:
    try:
        policies = list((await db.scalars(select(FirewallPolicy))).all())
        rules = list((await db.scalars(select(FirewallRule))).all())
        port_forwards = list((await db.scalars(select(FirewallPortForward))).all())
        networks = list((await db.scalars(select(Network))).all())
        ids_config = await db.scalar(select(IdsConfig).order_by(IdsConfig.synced_at.desc()).limit(1))
        last_scan = await db.scalar(
            select(ScanResult)
            .where(ScanResult.status == "done")
            .order_by(ScanResult.completed_at.desc(), ScanResult.created_at.desc())
        )
        checks = await run_checks(policies, rules, port_forwards, networks, ids_config, last_scan)
        pass_count = sum(1 for check in checks if check.status == "pass")
        warn_count = sum(1 for check in checks if check.status == "warn")
        fail_count = sum(1 for check in checks if check.status == "fail")
        score = max(0, int(((pass_count + warn_count * 0.5) / len(checks)) * 100))
        return AssessmentReportOut(
            score=score,
            pass_count=pass_count,
            warn_count=warn_count,
            fail_count=fail_count,
            checks=[CheckResultOut(**check.__dict__) for check in checks],
        )
    except Exception as exc:
        log.exception("Failed to generate security assessment")
        raise HTTPException(status_code=500, detail="Security assessment is temporarily unavailable") from exc


@router.get("/conflicts", response_model=list[ConflictReportOut])
async def conflicts(db: AsyncSession = Depends(get_db)) -> list[ConflictReportOut]:
    policies = list((await db.scalars(select(FirewallPolicy))).all())
    return [ConflictReportOut(**report.__dict__) for report in detect_conflicts(policies)]
