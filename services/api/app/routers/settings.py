import json
from urllib.parse import urlparse

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.audit import audit_event
from app.auth import current_active_user
from app.collectors.threat_feed_collector import VALID_RULE_ACTIONS, validate_outbound_url
from app.database import get_db
from app.models.settings import AppSetting
from app.models.user import User
from app.schemas.settings import SettingsUpdate

router = APIRouter()
SECRET_SETTINGS = {"notifications.ntfy_token"}
SECRET_MASK = "********"

VALID_SETTINGS = {
    "unifi.host",
    "unifi.api_key",
    "unifi.site",
    "unifi.verify_ssl",
    "cve_monitoring.enabled",
    "cve_monitoring.poll_interval_hours",
    "threat_feed.enabled",
    "threat_feed.poll_interval_hours",
    "threat_feed.zones",
    "threat_feed.apply_mode",
    "threat_feed.direction_mode",
    "threat_feed.rule_action",
    "http_proxy.enabled",
    "http_proxy.url",
    "retention.firewall_logs_days",
    "retention.threat_events_days",
    "retention.scan_results_days",
    "notifications.enabled",
    "notifications.severity_threshold",
    "notifications.ntfy_url",
    "notifications.ntfy_token",
    "notifications.webhook_url",
}


def _mask_secrets(settings: dict[str, str]) -> dict[str, str]:
    return {
        key: SECRET_MASK if key in SECRET_SETTINGS and value else value
        for key, value in settings.items()
    }


def _preserve_secret(key: str, value: str) -> bool:
    return key in SECRET_SETTINGS and value == SECRET_MASK


def _validate_settings(settings: dict[str, str]) -> None:
    unknown = set(settings) - VALID_SETTINGS
    if unknown:
        raise HTTPException(400, f"Unknown setting key: {', '.join(sorted(unknown))}")
    if "unifi.host" in settings:
        val = settings["unifi.host"]
        if not val:
            raise HTTPException(400, "unifi.host must not be empty")
        parsed = urlparse(val)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise HTTPException(400, "unifi.host must be an http or https URL")
    if "unifi.api_key" in settings and not settings["unifi.api_key"]:
        raise HTTPException(400, "unifi.api_key must not be empty")
    if "unifi.site" in settings and not settings["unifi.site"]:
        raise HTTPException(400, "unifi.site must not be empty")
    if "unifi.verify_ssl" in settings and settings["unifi.verify_ssl"].lower() not in {"true", "false"}:
        raise HTTPException(400, "unifi.verify_ssl must be true or false")
    for key in (
        "cve_monitoring.enabled",
        "threat_feed.enabled",
        "http_proxy.enabled",
        "notifications.enabled",
    ):
        if key in settings and settings[key].lower() not in {"true", "false"}:
            raise HTTPException(400, f"{key} must be true or false")
    for key in ("cve_monitoring.poll_interval_hours", "threat_feed.poll_interval_hours"):
        if key not in settings:
            continue
        try:
            value = int(settings[key])
        except ValueError as exc:
            raise HTTPException(400, f"{key} must be an integer") from exc
        minimum = 1 if key == "threat_feed.poll_interval_hours" else 6
        if value < minimum:
            raise HTTPException(400, f"{key} minimum is {minimum}")
    for key in (
        "retention.firewall_logs_days",
        "retention.threat_events_days",
        "retention.scan_results_days",
    ):
        if key not in settings:
            continue
        try:
            value = int(settings[key])
        except ValueError as exc:
            raise HTTPException(400, f"{key} must be an integer") from exc
        if not 0 <= value <= 3650:
            raise HTTPException(400, f"{key} must be between 0 and 3650")
    if "threat_feed.apply_mode" in settings and settings["threat_feed.apply_mode"] not in {
        "preview",
        "auto",
    }:
        raise HTTPException(400, "threat_feed.apply_mode must be preview or auto")
    if "threat_feed.direction_mode" in settings and settings["threat_feed.direction_mode"] not in {
        "inbound",
        "bidirectional",
    }:
        raise HTTPException(400, "threat_feed.direction_mode must be inbound or bidirectional")
    if "threat_feed.rule_action" in settings and settings["threat_feed.rule_action"] not in VALID_RULE_ACTIONS:
        raise HTTPException(
            400, f"threat_feed.rule_action must be one of {', '.join(sorted(VALID_RULE_ACTIONS))}"
        )
    if "threat_feed.zones" in settings:
        try:
            zones = json.loads(settings["threat_feed.zones"])
        except json.JSONDecodeError as exc:
            raise HTTPException(400, "threat_feed.zones must be a JSON array") from exc
        if not isinstance(zones, list) or not all(isinstance(z, str) and z.strip() for z in zones):
            raise HTTPException(400, "threat_feed.zones must be a JSON array of non-empty strings")
    if "http_proxy.url" in settings and settings["http_proxy.url"]:
        parsed = urlparse(settings["http_proxy.url"])
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise HTTPException(400, "http_proxy.url must be an HTTP or HTTPS proxy URL")
    if (
        "notifications.severity_threshold" in settings
        and settings["notifications.severity_threshold"] not in {"critical", "warning"}
    ):
        raise HTTPException(400, "notifications.severity_threshold must be critical or warning")
    for key in ("notifications.ntfy_url", "notifications.webhook_url"):
        if key in settings and settings[key]:
            try:
                validate_outbound_url(settings[key], allow_private=True)
            except ValueError as exc:
                raise HTTPException(400, f"{key}: {exc}") from exc


@router.get("/", response_model=dict[str, str])
async def get_settings(db: AsyncSession = Depends(get_db)) -> dict[str, str]:
    rows = (await db.scalars(select(AppSetting))).all()
    return _mask_secrets({row.key: row.value for row in rows})


@router.put("/", response_model=dict[str, str])
async def update_settings(
    body: SettingsUpdate,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(current_active_user),
) -> dict[str, str]:
    _validate_settings(body.settings)
    for key, value in body.settings.items():
        row = await db.get(AppSetting, key)
        if _preserve_secret(key, value):
            continue
        if row:
            row.value = value
        else:
            db.add(AppSetting(key=key, value=value))
    await db.commit()
    audit_event("settings.updated", user=user, keys=",".join(sorted(body.settings)))
    rows = (await db.scalars(select(AppSetting))).all()
    return _mask_secrets({row.key: row.value for row in rows})
