import json
from urllib.parse import urlparse

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models.settings import AppSetting
from app.schemas.settings import SettingsUpdate

router = APIRouter()

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
    "http_proxy.enabled",
    "http_proxy.url",
}


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
    for key in ("cve_monitoring.enabled", "threat_feed.enabled", "http_proxy.enabled"):
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
    if "threat_feed.apply_mode" in settings and settings["threat_feed.apply_mode"] not in {
        "preview",
        "auto",
    }:
        raise HTTPException(400, "threat_feed.apply_mode must be preview or auto")
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


@router.get("/", response_model=dict[str, str])
async def get_settings(db: AsyncSession = Depends(get_db)) -> dict[str, str]:
    rows = (await db.scalars(select(AppSetting))).all()
    return {row.key: row.value for row in rows}


@router.put("/", response_model=dict[str, str])
async def update_settings(
    body: SettingsUpdate, db: AsyncSession = Depends(get_db)
) -> dict[str, str]:
    _validate_settings(body.settings)
    for key, value in body.settings.items():
        row = await db.get(AppSetting, key)
        if row:
            row.value = value
        else:
            db.add(AppSetting(key=key, value=value))
    await db.commit()
    rows = (await db.scalars(select(AppSetting))).all()
    return {row.key: row.value for row in rows}
