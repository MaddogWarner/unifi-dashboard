import asyncio
import hashlib
import json
import logging
from datetime import UTC, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import async_session_factory
from app.models.assessment import AssessmentRun
from app.services.assessment import build_report

log = logging.getLogger(__name__)
INITIAL_DELAY_SECONDS = 90
ASSESSMENT_HISTORY_INTERVAL_SECONDS = 30 * 60


async def record_assessment(db: AsyncSession, *, now: datetime | None = None) -> bool:
    created_at = now or datetime.now(UTC)
    report = await build_report(db)
    checks = [{"check_id": check.check_id, "label": check.label, "status": check.status} for check in report.checks]
    status_hash = hashlib.sha256(
        "|".join(sorted(f"{check['check_id']}:{check['status']}" for check in checks)).encode()
    ).hexdigest()
    latest = await db.scalar(select(AssessmentRun).order_by(AssessmentRun.created_at.desc()).limit(1))
    if latest:
        latest_at = latest.created_at
        if latest_at.tzinfo is None:
            latest_at = latest_at.replace(tzinfo=UTC)
        if latest.status_hash == status_hash and latest_at > created_at - timedelta(hours=24):
            return False
    db.add(
        AssessmentRun(
            created_at=created_at,
            score=report.score,
            pass_count=report.pass_count,
            warn_count=report.warn_count,
            fail_count=report.fail_count,
            status_hash=status_hash,
            checks_json=json.dumps(checks, separators=(",", ":")),
        )
    )
    await db.commit()
    return True


async def run_assessment_history_cycle() -> None:
    async with async_session_factory() as db:
        try:
            await record_assessment(db)
        except Exception:
            await db.rollback()
            log.exception("Assessment history recording failed")


async def run_assessment_history_loop() -> None:
    await asyncio.sleep(INITIAL_DELAY_SECONDS)
    while True:
        await run_assessment_history_cycle()
        await asyncio.sleep(ASSESSMENT_HISTORY_INTERVAL_SECONDS)
