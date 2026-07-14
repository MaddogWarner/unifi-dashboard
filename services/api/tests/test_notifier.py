import asyncio
from datetime import UTC, datetime, timedelta

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.database import Base
from app.models.notification import NotificationState
from app.schemas.dashboard import AttentionItemOut
from app.services.notifier import fingerprint, process_attention


def _item(severity: str = "critical") -> AttentionItemOut:
    return AttentionItemOut(
        severity=severity,
        category="connectivity",
        title=f"{severity} test item",
        detail="Test detail",
        link="/settings",
    )


async def _session() -> tuple[AsyncSession, object]:
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    return factory(), engine


def test_first_seen_active_and_flap_guard_behaviour() -> None:
    async def scenario() -> None:
        db, engine = await _session()
        calls: list[str] = []

        async def sender(item, generated_at, settings):
            calls.append(item.title)
            return True

        try:
            now = datetime.now(UTC)
            critical = _item()
            settings = {"notifications.severity_threshold": "critical"}
            await process_attention(db, [critical], now, settings, sender, now=now)
            await process_attention(db, [critical], now, settings, sender, now=now + timedelta(minutes=5))
            await process_attention(db, [], now, settings, sender, now=now + timedelta(minutes=10))
            await process_attention(db, [critical], now, settings, sender, now=now + timedelta(minutes=30))
            await process_attention(db, [], now, settings, sender, now=now + timedelta(minutes=40))
            await process_attention(db, [critical], now, settings, sender, now=now + timedelta(hours=2))
            assert calls == [critical.title, critical.title]
        finally:
            await db.close()
            await engine.dispose()

    asyncio.run(scenario())


def test_threshold_and_failed_send_state() -> None:
    async def scenario() -> None:
        db, engine = await _session()
        calls: list[str] = []

        async def failed_sender(item, generated_at, settings):
            calls.append(item.title)
            return False

        try:
            now = datetime.now(UTC)
            warning = _item("warning")
            await process_attention(
                db,
                [warning],
                now,
                {"notifications.severity_threshold": "critical"},
                failed_sender,
                now=now,
            )
            assert calls == []
            await process_attention(db, [], now, {}, failed_sender, now=now + timedelta(minutes=1))
            await process_attention(
                db,
                [warning],
                now,
                {"notifications.severity_threshold": "warning"},
                failed_sender,
                now=now + timedelta(hours=2),
            )
            row = await db.get(NotificationState, fingerprint(warning))
            assert calls == [warning.title]
            assert row is not None and row.last_notified_at is None
        finally:
            await db.close()
            await engine.dispose()

    asyncio.run(scenario())
