import asyncio
import logging
from typing import Any

import httpx
from sqlalchemy import select

from app.config import settings
from app.database import async_session_factory
from app.models.settings import AppSetting

log = logging.getLogger(__name__)


async def _load_config() -> tuple[str, str, str, bool]:
    """Returns (base_v1, base_v2, api_key, verify_ssl). DB values override env vars."""
    async with async_session_factory() as session:
        rows = {
            r.key: r.value
            for r in (
                await session.scalars(
                    select(AppSetting).where(
                        AppSetting.key.in_(
                            ["unifi.host", "unifi.api_key", "unifi.site", "unifi.verify_ssl"]
                        )
                    )
                )
            ).all()
        }
    host = rows.get("unifi.host") or settings.unifi_host
    api_key = rows.get("unifi.api_key") or settings.unifi_api_key
    site = rows.get("unifi.site") or settings.unifi_site
    verify = rows.get("unifi.verify_ssl", str(settings.unifi_verify_ssl)).lower() == "true"
    return (
        f"{host}/proxy/network/api/s/{site}",
        f"{host}/proxy/network/integration/v1/sites/{site}",
        api_key,
        verify,
    )


def _client(api_key: str, verify: bool) -> httpx.AsyncClient:
    return httpx.AsyncClient(
        headers={"X-API-KEY": api_key, "Accept": "application/json"},
        verify=verify,
        timeout=15,
    )


def _raise_with_body(exc: httpx.HTTPStatusError) -> None:
    body = exc.response.text[:500].strip()
    msg = str(exc) + (f" — body: {body}" if body else "")
    raise httpx.HTTPStatusError(msg, request=exc.request, response=exc.response) from exc


async def _get(url: str, api_key: str, verify: bool) -> Any:
    async with _client(api_key, verify) as client:
        response = await client.get(url)
        if response.status_code == 429:
            await asyncio.sleep(float(response.headers.get("Retry-After", "5")))
            response = await client.get(url)
        try:
            response.raise_for_status()
        except httpx.HTTPStatusError as exc:
            _raise_with_body(exc)
        return response.json()


async def _request(method: str, url: str, api_key: str, verify: bool, payload: dict | None = None) -> Any:
    async with _client(api_key, verify) as client:
        response = await client.request(method, url, json=payload)
        if response.status_code == 429:
            await asyncio.sleep(float(response.headers.get("Retry-After", "5")))
            response = await client.request(method, url, json=payload)
        try:
            response.raise_for_status()
        except httpx.HTTPStatusError as exc:
            _raise_with_body(exc)
        if response.content:
            return response.json()
        return {}


def _data_items(data: Any) -> list[dict]:
    if isinstance(data, dict):
        items = data.get("data", data)
    else:
        items = data
    return items if isinstance(items, list) else [items]


def _first_item(data: Any) -> dict:
    items = _data_items(data)
    return items[0] if items else {}


async def get_firewall_policies() -> list[dict]:
    _base_v1, base_v2, api_key, verify = await _load_config()
    try:
        data = await _get(f"{base_v2}/firewall-policies", api_key, verify)
        return data.get("data", data) if isinstance(data, dict) else data
    except httpx.HTTPStatusError as exc:
        if exc.response.status_code == 404:
            log.warning("firewall-policies v2 not available; falling back to legacy rules only")
            return []
        raise


async def get_firewall_rules() -> list[dict]:
    base_v1, _base_v2, api_key, verify = await _load_config()
    data = await _get(f"{base_v1}/rest/firewallrule", api_key, verify)
    return data.get("data", [])


async def get_port_forwards() -> list[dict] | None:
    base_v1, _base_v2, api_key, verify = await _load_config()
    try:
        data = await _get(f"{base_v1}/rest/portforward", api_key, verify)
        return _data_items(data)
    except httpx.HTTPStatusError as exc:
        if exc.response.status_code == 404:
            log.warning("portforward v1 endpoint not available; skipping WAN exposure correlation")
            return None
        raise


async def get_devices() -> list[dict]:
    base_v1, _base_v2, api_key, verify = await _load_config()
    data = await _get(f"{base_v1}/stat/device", api_key, verify)
    return _data_items(data)


async def get_firewall_groups() -> list[dict]:
    base_v1, _base_v2, api_key, verify = await _load_config()
    data = await _get(f"{base_v1}/rest/firewallgroup", api_key, verify)
    return _data_items(data)


async def create_firewall_group(payload: dict) -> dict:
    base_v1, _base_v2, api_key, verify = await _load_config()
    try:
        data = await _request("POST", f"{base_v1}/rest/firewallgroup", api_key, verify, payload)
        return _first_item(data)
    except httpx.HTTPStatusError as exc:
        if exc.response.status_code != 400:
            raise
        # Group may already exist in UniFi from a prior failed attempt; reuse it if so.
        groups = await get_firewall_groups()
        existing = next((g for g in groups if g.get("name") == payload.get("name")), None)
        if existing:
            log.warning(
                "Firewall group '%s' already exists in UniFi (id=%s); reusing",
                payload.get("name"),
                existing.get("_id"),
            )
            return existing
        raise


async def update_firewall_group(group_id: str, payload: dict) -> dict:
    base_v1, _base_v2, api_key, verify = await _load_config()
    data = await _request("PUT", f"{base_v1}/rest/firewallgroup/{group_id}", api_key, verify, payload)
    return _first_item(data)


async def delete_firewall_group(group_id: str) -> None:
    base_v1, _base_v2, api_key, verify = await _load_config()
    await _request("DELETE", f"{base_v1}/rest/firewallgroup/{group_id}", api_key, verify)


async def create_firewall_rule(payload: dict) -> dict:
    base_v1, _base_v2, api_key, verify = await _load_config()
    data = await _request("POST", f"{base_v1}/rest/firewallrule", api_key, verify, payload)
    return _first_item(data)


async def update_firewall_rule(rule_id: str, payload: dict) -> dict:
    base_v1, _base_v2, api_key, verify = await _load_config()
    data = await _request("PUT", f"{base_v1}/rest/firewallrule/{rule_id}", api_key, verify, payload)
    return _first_item(data)


async def delete_firewall_rule(rule_id: str) -> None:
    base_v1, _base_v2, api_key, verify = await _load_config()
    await _request("DELETE", f"{base_v1}/rest/firewallrule/{rule_id}", api_key, verify)


async def get_networks() -> list[dict]:
    base_v1, _base_v2, api_key, verify = await _load_config()
    data = await _get(f"{base_v1}/rest/networkconf", api_key, verify)
    return data.get("data", [])


async def get_ids_config() -> dict:
    base_v1, _base_v2, api_key, verify = await _load_config()
    data = await _get(f"{base_v1}/rest/setting/ips", api_key, verify)
    items = data.get("data", [])
    return items[0] if items else {}


async def get_threat_events(limit: int = 500) -> list[dict]:
    base_v1, _base_v2, api_key, verify = await _load_config()
    data = await _get(f"{base_v1}/stat/event?_limit={limit}", api_key, verify)
    events = data.get("data", [])
    return [event for event in events if event.get("key", "").startswith("EVT_IPS_")]


async def get_zones() -> list[dict]:
    _base_v1, base_v2, api_key, verify = await _load_config()
    try:
        data = await _get(f"{base_v2}/firewall-zones", api_key, verify)
        return data.get("data", data) if isinstance(data, dict) else data
    except httpx.HTTPStatusError as exc:
        if exc.response.status_code == 404:
            return []
        raise


async def get_sites() -> list[dict]:
    _base_v1, base_v2, api_key, verify = await _load_config()
    # sites endpoint is at the v2 root (no site segment) — strip the site suffix
    host = base_v2.split("/proxy/network/integration/v1/sites/")[0]
    data = await _get(f"{host}/proxy/network/integration/v1/sites", api_key, verify)
    return data.get("data", data) if isinstance(data, dict) else data


async def check_connectivity() -> bool:
    try:
        await get_sites()
        return True
    except Exception:
        log.exception("UniFi connectivity check failed")
        return False
