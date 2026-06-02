import logging
from typing import Any

from app.models.user import User

log = logging.getLogger("app.audit")

SENSITIVE_KEY_PARTS = ("password", "token", "secret", "api_key")


def _safe_detail_value(key: str, value: Any) -> str:
    if any(part in key.lower() for part in SENSITIVE_KEY_PARTS):
        return "<redacted>"
    return str(value)


def audit_event(action: str, user: User | None = None, **details: Any) -> None:
    actor = user.email if user else "anonymous"
    user_id = str(user.id) if user else "-"
    safe_details = {
        key: _safe_detail_value(key, value)
        for key, value in details.items()
        if value is not None
    }
    log.info(
        "action=%s actor=%s user_id=%s details=%s",
        action,
        actor,
        user_id,
        safe_details,
    )
