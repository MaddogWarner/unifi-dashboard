import asyncio
import logging
from datetime import UTC, datetime, timedelta

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import async_session_factory
from app.models.settings import AppSetting

log = logging.getLogger(__name__)

INITIAL_DELAY_SECONDS = 60
RETENTION_INTERVAL_SECONDS = 6 * 60 * 60
BATCH_SIZE = 5000
RETENTION_TARGETS = (
    ("retention.firewall_logs_days", "firewall_logs", "timestamp"),
    ("retention.threat_events_days", "threat_events", "timestamp"),
    ("retention.scan_results_days", "scan_results", "created_at"),
    ("retention.assessment_runs_days", "assessment_runs", "created_at"),
)


async def prune_table(
    db: AsyncSession,
    table: str,
    timestamp_column: str,
    days: int,
    *,
    batch_size: int = BATCH_SIZE,
    now: datetime | None = None,
) -> tuple[int, datetime | None]:
    if days == 0:
        return 0, None

    cutoff = (now or datetime.now(UTC)) - timedelta(days=days)
    total = 0
    while True:
        result = await db.execute(
            text(
                f"DELETE FROM {table} WHERE id IN "  # noqa: S608 - identifiers are module constants
                f"(SELECT id FROM {table} WHERE {timestamp_column} < :cutoff LIMIT :batch_size)"
            ),
            {"cutoff": cutoff, "batch_size": batch_size},
        )
        deleted = result.rowcount or 0
        await db.commit()
        total += deleted
        if deleted < batch_size:
            break
    return total, cutoff


async def run_retention_cycle() -> None:
    for setting_key, table, timestamp_column in RETENTION_TARGETS:
        try:
            async with async_session_factory() as db:
                setting = await db.get(AppSetting, setting_key)
                days = int(setting.value) if setting else 0
                deleted, cutoff = await prune_table(db, table, timestamp_column, days)
                if deleted and cutoff:
                    log.info(
                        "Retention pruned table=%s rows=%s cutoff=%s",
                        table,
                        deleted,
                        cutoff.isoformat(),
                    )
        except Exception:
            log.exception("Retention pruning failed for table=%s", table)


async def run_retention_loop() -> None:
    await asyncio.sleep(INITIAL_DELAY_SECONDS)
    while True:
        await run_retention_cycle()
        await asyncio.sleep(RETENTION_INTERVAL_SECONDS)
