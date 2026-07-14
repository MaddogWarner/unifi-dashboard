import json
import logging
from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models.assessment import AssessmentRun
from app.models.firewall import FirewallPolicy
from app.schemas.assessment import AssessmentHistoryOut, AssessmentReportOut, ConflictReportOut
from app.services.assessment import build_report
from app.services.policy_engine import detect_conflicts

router = APIRouter()
log = logging.getLogger(__name__)


@router.get("/history", response_model=list[AssessmentHistoryOut])
async def history(
    days: int = Query(default=30, ge=1, le=365), db: AsyncSession = Depends(get_db)
) -> list[AssessmentHistoryOut]:
    rows = (
        await db.scalars(
            select(AssessmentRun)
            .where(AssessmentRun.created_at >= datetime.now(UTC) - timedelta(days=days))
            .order_by(AssessmentRun.created_at)
        )
    ).all()
    return [
        AssessmentHistoryOut(
            created_at=row.created_at,
            score=row.score,
            pass_count=row.pass_count,
            warn_count=row.warn_count,
            fail_count=row.fail_count,
            checks=json.loads(row.checks_json),
        )
        for row in rows
    ]


@router.get("/", response_model=AssessmentReportOut)
async def assessment(db: AsyncSession = Depends(get_db)) -> AssessmentReportOut:
    try:
        return await build_report(db)
    except Exception as exc:
        log.exception("Failed to generate security assessment")
        raise HTTPException(status_code=500, detail="Security assessment is temporarily unavailable") from exc


@router.get("/conflicts", response_model=list[ConflictReportOut])
async def conflicts(db: AsyncSession = Depends(get_db)) -> list[ConflictReportOut]:
    policies = list((await db.scalars(select(FirewallPolicy))).all())
    return [ConflictReportOut(**report.__dict__) for report in detect_conflicts(policies)]
