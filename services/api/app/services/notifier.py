import asyncio
import hashlib
import logging
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime, timedelta

import httpx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import async_session_factory
from app.models.notification import NotificationState
from app.models.settings import AppSetting
from app.schemas.dashboard import AttentionItemOut
from app.services.attention import build_attention

log = logging.getLogger(__name__)

NOTIFIER_INTERVAL_SECONDS = 5 * 60
FLAP_GUARD = timedelta(hours=1)
Sender = Callable[[AttentionItemOut, datetime, dict[str, str]], Awaitable[bool]]


def fingerprint(item: AttentionItemOut) -> str:
    return hashlib.sha256(f"{item.category}|{item.title}".encode()).hexdigest()


async def get_settings(db: AsyncSession) -> dict[str, str]:
    rows = (await db.scalars(select(AppSetting))).all()
    return {row.key: row.value for row in rows}


def _proxy(settings: dict[str, str]) -> str | None:
    if settings.get("http_proxy.enabled", "false").lower() != "true":
        return None
    return settings.get("http_proxy.url") or None


async def send_ntfy(
    item: AttentionItemOut, generated_at: datetime, settings: dict[str, str]
) -> bool:
    del generated_at
    url = settings.get("notifications.ntfy_url", "")
    if not url:
        return False
    headers = {
        "Title": item.title,
        "Priority": "urgent" if item.severity == "critical" else "high",
        "Tags": "rotating_light" if item.severity == "critical" else "warning",
    }
    token = settings.get("notifications.ntfy_token", "")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    try:
        async with httpx.AsyncClient(proxy=_proxy(settings), timeout=10) as client:
            response = await client.post(url, content=item.detail, headers=headers)
            response.raise_for_status()
        return True
    except Exception as exc:
        status = exc.response.status_code if isinstance(exc, httpx.HTTPStatusError) else None
        log.warning("ntfy notification failed status=%s error=%s", status, type(exc).__name__)
        return False


async def send_webhook(
    item: AttentionItemOut, generated_at: datetime, settings: dict[str, str]
) -> bool:
    url = settings.get("notifications.webhook_url", "")
    if not url:
        return False
    payload = {
        "severity": item.severity,
        "category": item.category,
        "title": item.title,
        "detail": item.detail,
        "link": item.link,
        "generated_at": generated_at.isoformat(),
    }
    try:
        async with httpx.AsyncClient(proxy=_proxy(settings), timeout=10) as client:
            response = await client.post(url, json=payload)
            response.raise_for_status()
        return True
    except Exception as exc:
        status = exc.response.status_code if isinstance(exc, httpx.HTTPStatusError) else None
        log.warning("Webhook notification failed status=%s error=%s", status, type(exc).__name__)
        return False


async def send_configured(
    item: AttentionItemOut, generated_at: datetime, settings: dict[str, str]
) -> bool:
    results = await asyncio.gather(
        send_ntfy(item, generated_at, settings),
        send_webhook(item, generated_at, settings),
    )
    return any(results)


async def process_attention(
    db: AsyncSession,
    items: list[AttentionItemOut],
    generated_at: datetime,
    settings: dict[str, str],
    sender: Sender = send_configured,
    *,
    now: datetime | None = None,
) -> None:
    observed_at = now or datetime.now(UTC)
    present = {fingerprint(item) for item in items}
    active_rows = (
        await db.scalars(select(NotificationState).where(NotificationState.active.is_(True)))
    ).all()
    for row in active_rows:
        if row.fingerprint not in present:
            row.active = False

    threshold = settings.get("notifications.severity_threshold", "critical")
    eligible = {"critical"} if threshold == "critical" else {"critical", "warning"}
    for item in items:
        item_fingerprint = fingerprint(item)
        row = await db.get(NotificationState, item_fingerprint)
        newly_active = row is None or not row.active
        if row is None:
            row = NotificationState(
                fingerprint=item_fingerprint,
                severity=item.severity,
                title=item.title,
                first_seen=observed_at,
                active=True,
            )
            db.add(row)
        else:
            row.active = True
            row.severity = item.severity
            row.title = item.title
        last_notified = row.last_notified_at
        if last_notified and last_notified.tzinfo is None:
            last_notified = last_notified.replace(tzinfo=UTC)
        outside_guard = last_notified is None or observed_at - last_notified >= FLAP_GUARD
        if newly_active and item.severity in eligible and outside_guard:
            if await sender(item, generated_at, settings):
                row.last_notified_at = observed_at
    await db.commit()


async def run_notifier_cycle() -> None:
    async with async_session_factory() as db:
        settings = await get_settings(db)
        if settings.get("notifications.enabled", "false").lower() != "true":
            return
        attention = await build_attention(db)
        await process_attention(db, attention.items, attention.generated_at, settings)


async def run_notifier_loop() -> None:
    while True:
        try:
            await run_notifier_cycle()
        except Exception:
            log.exception("Notification evaluation failed")
        await asyncio.sleep(NOTIFIER_INTERVAL_SECONDS)
