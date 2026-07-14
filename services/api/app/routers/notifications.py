from datetime import UTC, datetime

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.audit import audit_event
from app.auth import current_active_user
from app.database import get_db
from app.models.user import User
from app.schemas.dashboard import AttentionItemOut
from app.services.notifier import get_settings, send_ntfy, send_webhook

router = APIRouter()


@router.post("/test", response_model=list[dict[str, str | bool | None]])
async def test_notifications(
    db: AsyncSession = Depends(get_db),
    user: User = Depends(current_active_user),
) -> list[dict[str, str | bool | None]]:
    settings = await get_settings(db)
    generated_at = datetime.now(UTC)
    item = AttentionItemOut(
        severity="critical",
        category="connectivity",
        title="Test notification from UniFi Security Dashboard",
        detail="Test notification from UniFi Security Dashboard",
        link="/settings",
    )
    results: list[dict[str, str | bool | None]] = []
    for channel, url_key, sender in (
        ("ntfy", "notifications.ntfy_url", send_ntfy),
        ("webhook", "notifications.webhook_url", send_webhook),
    ):
        if not settings.get(url_key):
            results.append({"channel": channel, "ok": False, "error": "Not configured"})
            continue
        ok = await sender(item, generated_at, settings)
        results.append(
            {"channel": channel, "ok": ok, "error": None if ok else "Delivery failed"}
        )
    audit_event("notifications.test", user=user, results=results)
    return results
