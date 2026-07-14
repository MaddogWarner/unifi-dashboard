import asyncio
from datetime import UTC, datetime, timedelta

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from app.collectors.retention import prune_table
from app.database import Base
from app.models.firewall import FirewallLog


def _log(timestamp: datetime) -> FirewallLog:
    return FirewallLog(timestamp=timestamp, action="drop", raw_line="test")


def test_pruning_removes_old_rows_in_batches_and_keeps_new_rows() -> None:
    async def scenario() -> None:
        engine = create_async_engine("sqlite+aiosqlite:///:memory:")
        try:
            async with engine.begin() as connection:
                await connection.run_sync(Base.metadata.create_all)
            factory = async_sessionmaker(engine, expire_on_commit=False)
            now = datetime.now(UTC)
            async with factory() as db:
                db.add_all(
                    [_log(now - timedelta(days=31)) for _ in range(5)]
                    + [_log(now - timedelta(days=29))]
                )
                await db.commit()
                deleted, _ = await prune_table(
                    db, "firewall_logs", "timestamp", 30, batch_size=2, now=now
                )
                remaining = await db.scalar(select(func.count()).select_from(FirewallLog))
                assert deleted == 5
                assert remaining == 1
        finally:
            await engine.dispose()

    asyncio.run(scenario())


def test_zero_days_disables_pruning() -> None:
    async def scenario() -> None:
        engine = create_async_engine("sqlite+aiosqlite:///:memory:")
        try:
            async with engine.begin() as connection:
                await connection.run_sync(Base.metadata.create_all)
            factory = async_sessionmaker(engine, expire_on_commit=False)
            async with factory() as db:
                db.add(_log(datetime.now(UTC) - timedelta(days=365)))
                await db.commit()
                deleted, cutoff = await prune_table(db, "firewall_logs", "timestamp", 0)
                remaining = await db.scalar(select(func.count()).select_from(FirewallLog))
                assert (deleted, cutoff) == (0, None)
                assert remaining == 1
        finally:
            await engine.dispose()

    asyncio.run(scenario())
