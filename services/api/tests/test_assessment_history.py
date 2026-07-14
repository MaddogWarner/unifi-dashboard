import asyncio
from datetime import UTC, datetime, timedelta
from unittest.mock import patch

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from app.collectors.assessment_history import record_assessment
from app.database import Base
from app.models.assessment import AssessmentRun
from app.schemas.assessment import AssessmentReportOut, CheckResultOut


def _report(status: str = "pass", score: int = 100) -> AssessmentReportOut:
    return AssessmentReportOut(
        score=score,
        pass_count=1 if status == "pass" else 0,
        warn_count=1 if status == "warn" else 0,
        fail_count=1 if status == "fail" else 0,
        checks=[
            CheckResultOut(
                check_id="test",
                label="Test",
                status=status,
                detail="detail",
                recommendation="recommendation",
            )
        ],
    )


def test_recorder_change_only_and_heartbeat() -> None:
    async def scenario() -> None:
        engine = create_async_engine("sqlite+aiosqlite:///:memory:")
        try:
            async with engine.begin() as connection:
                await connection.run_sync(Base.metadata.create_all)
            factory = async_sessionmaker(engine, expire_on_commit=False)
            now = datetime.now(UTC)
            async with factory() as db:
                with patch("app.collectors.assessment_history.build_report", return_value=_report()):
                    assert await record_assessment(db, now=now)
                    assert not await record_assessment(db, now=now + timedelta(hours=1))
                    assert await record_assessment(db, now=now + timedelta(hours=25))
                with patch(
                    "app.collectors.assessment_history.build_report",
                    return_value=_report("fail", 0),
                ):
                    assert await record_assessment(db, now=now + timedelta(hours=26))
                count = await db.scalar(select(func.count()).select_from(AssessmentRun))
                assert count == 3
        finally:
            await engine.dispose()

    asyncio.run(scenario())
