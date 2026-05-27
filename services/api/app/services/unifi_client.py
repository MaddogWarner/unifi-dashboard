import asyncio
import logging
from typing import Any

import httpx

from app.config import settings

log = logging.getLogger(__name__)

_BASE_V1 = f"{settings.unifi_host}/proxy/network/api/s/{settings.unifi_site}"
_BASE_V2 = f"{settings.unifi_host}/proxy/network/integration/v1/sites/{settings.unifi_site}"
_HEADERS = {"X-API-KEY": settings.unifi_api_key, "Accept": "application/json"}


def _client() -> httpx.AsyncClient:
    return httpx.AsyncClient(headers=_HEADERS, verify=settings.unifi_verify_ssl, timeout=15)


async def _get(url: str) -> Any:
    async with _client() as client:
        response = await client.get(url)
        if response.status_code == 429:
            await asyncio.sleep(float(response.headers.get("Retry-After", "5")))
            response = await client.get(url)
        response.raise_for_status()
        return response.json()


async def get_firewall_policies() -> list[dict]:
    try:
        data = await _get(f"{_BASE_V2}/firewall-policies")
        return data.get("data", data) if isinstance(data, dict) else data
    except httpx.HTTPStatusError as exc:
        if exc.response.status_code == 404:
            log.warning("firewall-policies v2 not available; falling back to legacy rules only")
            return []
        raise


async def get_firewall_rules() -> list[dict]:
    data = await _get(f"{_BASE_V1}/rest/firewallrule")
    return data.get("data", [])


async def get_networks() -> list[dict]:
    data = await _get(f"{_BASE_V1}/rest/networkconf")
    return data.get("data", [])


async def get_ids_config() -> dict:
    data = await _get(f"{_BASE_V1}/rest/setting/ips")
    items = data.get("data", [])
    return items[0] if items else {}


async def get_threat_events(limit: int = 500) -> list[dict]:
    data = await _get(f"{_BASE_V1}/stat/event?_limit={limit}")
    events = data.get("data", [])
    return [event for event in events if event.get("key", "").startswith("EVT_IPS_")]


async def get_zones() -> list[dict]:
    try:
        data = await _get(f"{_BASE_V2}/firewall-zones")
        return data.get("data", data) if isinstance(data, dict) else data
    except httpx.HTTPStatusError as exc:
        if exc.response.status_code == 404:
            return []
        raise


async def get_sites() -> list[dict]:
    data = await _get(f"{settings.unifi_host}/proxy/network/integration/v1/sites")
    return data.get("data", data) if isinstance(data, dict) else data


async def check_connectivity() -> bool:
    try:
        await get_sites()
        return True
    except Exception:
        log.exception("UniFi connectivity check failed")
        return False
