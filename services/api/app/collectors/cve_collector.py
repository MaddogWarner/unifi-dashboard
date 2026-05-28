import asyncio
import gzip
import json
import logging
import re
from datetime import UTC, datetime
from typing import Any

import httpx
from sqlalchemy import delete, select, update
from sqlalchemy.dialects.postgresql import insert

from app.config import settings
from app.database import async_session_factory
from app.models.cve import CVEAlert, CVEDeviceLink, DeviceInventory
from app.models.settings import AppSetting
from app.services import unifi_client

log = logging.getLogger(__name__)

NVD_MODIFIED_URL = "https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-modified.json.gz"
UI_RELEASES_URL = "https://community.ui.com/releases"


async def _get_setting(key: str, default: str = "") -> str:
    async with async_session_factory() as session:
        row = await session.get(AppSetting, key)
        return row.value if row else default


def _parse_datetime(value: str | None) -> datetime | None:
    if not value:
        return None
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _json(data: Any) -> str:
    return json.dumps(data, sort_keys=True, default=str)


def _ubiquiti_cpes(cve: dict) -> list[str]:
    cpes: list[str] = []
    for config in cve.get("configurations", []):
        for node in config.get("nodes", []):
            for match in node.get("cpeMatch", []):
                criteria = match.get("criteria", "")
                if ":ui:" in criteria:
                    cpes.append(criteria)
    return cpes


def _best_metric(cve: dict) -> tuple[float | None, str | None]:
    metrics = cve.get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        metric_items = metrics.get(key) or []
        if not metric_items:
            continue
        cvss = metric_items[0].get("cvssData", {})
        score = cvss.get("baseScore")
        severity = cvss.get("baseSeverity") or metric_items[0].get("baseSeverity")
        return float(score) if score is not None else None, severity
    return None, None


async def _run_nvd_poll(proxy: str | None) -> None:
    async with httpx.AsyncClient(proxy=proxy, timeout=60) as client:
        response = await client.get(NVD_MODIFIED_URL)
        response.raise_for_status()
    data = json.loads(gzip.decompress(response.content))

    async with async_session_factory() as session:
        for item in data.get("vulnerabilities", []):
            cve = item.get("cve", {})
            cve_id = cve.get("id")
            if not cve_id:
                continue
            score, severity = _best_metric(cve)
            if score is None or score < 7.0:
                continue
            cpes = _ubiquiti_cpes(cve)
            if not cpes:
                continue
            description = next(
                (d.get("value", "") for d in cve.get("descriptions", []) if d.get("lang") == "en"),
                cve_id,
            )
            await session.execute(
                insert(CVEAlert)
                .values(
                    cve_id=cve_id,
                    title=description[:200],
                    description=description,
                    severity=(severity or "HIGH").upper(),
                    cvss_score=score,
                    published_at=_parse_datetime(cve.get("published")),
                    source="nvd",
                    affected_cpe=",".join(cpes),
                    raw_json=_json(cve),
                )
                .on_conflict_do_nothing(index_elements=["cve_id"])
            )
        await session.commit()


async def _run_bulletin_scrape(proxy: str | None) -> None:
    async with httpx.AsyncClient(proxy=proxy, timeout=30) as client:
        response = await client.get(UI_RELEASES_URL)
        response.raise_for_status()
        paths = set(re.findall(r'href="(/releases/Security-Advisory-Bulletin[^"]+)"', response.text))
        for path in paths:
            url = f"https://community.ui.com{path}"
            page = await client.get(url)
            page.raise_for_status()
            for cve_id in set(re.findall(r"CVE-\d{4}-\d+", page.text)):
                async with async_session_factory() as session:
                    existing = await session.scalar(select(CVEAlert).where(CVEAlert.cve_id == cve_id))
                    if existing:
                        await session.execute(
                            update(CVEAlert)
                            .where(CVEAlert.cve_id == cve_id, CVEAlert.source == "nvd")
                            .values(source="ubiquiti", ubiquiti_bulletin_url=url)
                        )
                    else:
                        session.add(
                            CVEAlert(
                                cve_id=cve_id,
                                title=cve_id,
                                description="Ubiquiti security advisory bulletin",
                                severity="HIGH",
                                source="ubiquiti",
                                ubiquiti_bulletin_url=url,
                            )
                        )
                    await session.commit()


async def _update_device_inventory() -> None:
    devices = await unifi_client.get_devices()
    now = datetime.now(UTC)
    async with async_session_factory() as session:
        for device in devices:
            uid = device.get("_id") or device.get("id") or device.get("mac")
            if not uid:
                continue
            existing = await session.scalar(select(DeviceInventory).where(DeviceInventory.unifi_id == uid))
            if existing is None:
                existing = DeviceInventory(unifi_id=uid)
                session.add(existing)
            existing.name = device.get("name") or device.get("hostname")
            existing.model = device.get("model")
            existing.firmware_version = device.get("version")
            existing.ip_address = device.get("ip")
            existing.site = settings.unifi_site
            existing.raw_json = _json(device)
            existing.synced_at = now
        await session.commit()


async def _match_cves_to_devices() -> None:
    async with async_session_factory() as session:
        devices = (await session.scalars(select(DeviceInventory))).all()
        cves = (await session.scalars(select(CVEAlert))).all()
        await session.execute(delete(CVEDeviceLink))
        for cve in cves:
            cpe_lower = (cve.affected_cpe or "").lower()
            if not cpe_lower:
                continue
            for device in devices:
                model_lower = (device.model or "").lower().replace(" ", "_")
                name_lower = (device.name or "").lower().replace(" ", "_")
                if (model_lower and model_lower in cpe_lower) or (name_lower and name_lower in cpe_lower):
                    await session.execute(
                        insert(CVEDeviceLink)
                        .values(cve_id=cve.cve_id, device_id=device.id)
                        .on_conflict_do_nothing()
                    )
        await session.commit()


async def run_cve_collector_once() -> None:
    proxy_url = await _get_setting("http_proxy.url")
    proxy_enabled = (await _get_setting("http_proxy.enabled", "false")).lower() == "true"
    proxy = proxy_url if proxy_enabled and proxy_url else None
    await _run_nvd_poll(proxy)
    await _run_bulletin_scrape(proxy)
    await _update_device_inventory()
    await _match_cves_to_devices()


async def run_cve_collector() -> None:
    while True:
        interval_hours = 24
        enabled = False
        try:
            enabled = (await _get_setting("cve_monitoring.enabled", "false")).lower() == "true"
            interval_hours = max(int(await _get_setting("cve_monitoring.poll_interval_hours", "24")), 1)
            if enabled:
                await run_cve_collector_once()
        except Exception:
            log.exception("CVE collector error")
        await asyncio.sleep(interval_hours * 3600 if enabled else 60)
