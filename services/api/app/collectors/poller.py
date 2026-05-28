import asyncio
import hashlib
import json
import logging
import re
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.database import async_session_factory
from app.models.firewall import FirewallPolicy, FirewallRule, PolicySnapshot
from app.models.network import IdsConfig, Network
from app.models.threat import ThreatEvent
from app.services import unifi_client

log = logging.getLogger(__name__)

IDS_ENABLE_FIELDS = (
    "enabled",
    "ips_enabled",
    "ids_enabled",
    "intrusion_prevention_enabled",
    "intrusion_prevention",
    "threat_management_enabled",
    "threat_management",
)
IDS_MODE_FIELDS = (
    "mode",
    "ids_mode",
    "ips_mode",
    "detection_mode",
    "intrusion_prevention_mode",
    "threat_management_mode",
    "protection_mode",
    "prevention_mode",
    "action",
    "action_mode",
    "security_mode",
    "threat_detection_mode",
)
IDS_PREVENTION_VALUES = {
    "ips",
    "prevent",
    "prevention",
    "block",
    "blocked",
    "drop",
    "notify_block",
    "notify_and_block",
    "alert_block",
    "alert_and_block",
    "detect_block",
    "detect_and_block",
}
IDS_DETECTION_VALUES = {"ids", "detect", "detection", "notify", "alert"}
TRUTHY_VALUES = {"1", "true", "yes", "on", "enabled", "enable"}
FALSY_VALUES = {"0", "false", "no", "off", "disabled", "disable", ""}


def _json(data: Any) -> str:
    return json.dumps(data, sort_keys=True, default=str)


def _normalise_token(value: Any) -> str:
    return _normalise_key(str(value).strip()).replace(" ", "_")


def _normalise_key(value: str) -> str:
    value = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", value)
    return value.replace("-", "_").lower()


def _is_truthy(value: Any) -> bool | None:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value != 0
    if value is None:
        return None
    normalised = _normalise_token(value)
    if normalised in TRUTHY_VALUES:
        return True
    if normalised in FALSY_VALUES:
        return False
    return None


def _find_values(data: Any, keys: set[str]) -> list[Any]:
    values = []
    if isinstance(data, dict):
        for key, value in data.items():
            if _normalise_key(key) in keys:
                values.append(value)
            values.extend(_find_values(value, keys))
    elif isinstance(data, list):
        for item in data:
            values.extend(_find_values(item, keys))
    return values


def _has_configured_collection(data: Any) -> bool:
    keys = {
        "categories",
        "enabled_categories",
        "active_categories",
        "active_detections",
        "detections",
        "networks",
        "network_ids",
        "networkconf_ids",
        "selected_networks",
    }
    return any(bool(value) for value in _find_values(data, keys))


def _normalise_ids_mode(config: dict) -> str | None:
    mode_values = _find_values(config, {_normalise_key(key) for key in IDS_MODE_FIELDS})
    for value in mode_values:
        token = _normalise_token(value)
        if token in IDS_PREVENTION_VALUES:
            return "ips"
    for value in mode_values:
        token = _normalise_token(value)
        if token in IDS_DETECTION_VALUES:
            return "ids"
    for value in mode_values:
        if value:
            return str(value)
    return None


def normalise_ids_config(config: dict) -> dict[str, Any]:
    mode = _normalise_ids_mode(config)
    enabled_values = _find_values(config, {_normalise_key(key) for key in IDS_ENABLE_FIELDS})
    explicit_enabled = next(
        (state for state in (_is_truthy(value) for value in enabled_values) if state is not None),
        None,
    )
    sensitivity = next(
        (str(value) for value in _find_values(config, {"sensitivity"}) if value),
        None,
    )
    categories = next(
        (
            value
            for value in _find_values(
                config,
                {"categories", "enabled_categories", "active_categories"},
            )
            if isinstance(value, list)
        ),
        [],
    )
    configured = bool(mode or sensitivity or categories or _has_configured_collection(config))
    enabled = bool(explicit_enabled if explicit_enabled is not None else configured)
    return {
        "enabled": enabled,
        "mode": mode if enabled else None,
        "categories": categories,
        "sensitivity": sensitivity,
        "raw_json": _json(config),
    }


async def _upsert_policies(session: AsyncSession, policies: list[dict]) -> None:
    now = datetime.now(UTC)
    for policy in policies:
        uid = policy.get("_id") or policy.get("id")
        if not uid:
            continue
        existing = await session.scalar(
            select(FirewallPolicy).where(FirewallPolicy.unifi_id == uid)
        )
        if existing is None:
            existing = FirewallPolicy(unifi_id=uid)
            session.add(existing)
        src = policy.get("src") if isinstance(policy.get("src"), dict) else {}
        dst = policy.get("dst") if isinstance(policy.get("dst"), dict) else {}
        existing.name = policy.get("name", "")
        existing.action = (policy.get("action") or "").upper()
        existing.src_zone = src.get("zone") or policy.get("src_zone")
        existing.dst_zone = dst.get("zone") or policy.get("dst_zone")
        existing.enabled = policy.get("enabled", True)
        existing.protocol = policy.get("protocol")
        existing.schedule = policy.get("schedule")
        existing.raw_json = _json(policy)
        existing.synced_at = now


async def _upsert_rules(session: AsyncSession, rules: list[dict]) -> None:
    now = datetime.now(UTC)
    for rule in rules:
        uid = rule.get("_id") or rule.get("id")
        if not uid:
            continue
        existing = await session.scalar(select(FirewallRule).where(FirewallRule.unifi_id == uid))
        if existing is None:
            existing = FirewallRule(unifi_id=uid)
            session.add(existing)
        existing.name = rule.get("name", "")
        existing.action = (rule.get("action") or "").upper()
        existing.ruleset = rule.get("ruleset")
        existing.rule_index = rule.get("rule_index")
        existing.enabled = rule.get("enabled", True)
        existing.src_address = rule.get("src_address") or rule.get("src_networkconf_id")
        existing.dst_address = rule.get("dst_address") or rule.get("dst_networkconf_id")
        existing.protocol = rule.get("protocol")
        existing.dst_port = rule.get("dst_port")
        existing.raw_json = _json(rule)
        existing.synced_at = now


async def _upsert_networks(session: AsyncSession, networks: list[dict]) -> None:
    now = datetime.now(UTC)
    for network in networks:
        uid = network.get("_id") or network.get("id")
        if not uid:
            continue
        existing = await session.scalar(select(Network).where(Network.unifi_id == uid))
        if existing is None:
            existing = Network(unifi_id=uid)
            session.add(existing)
        existing.name = network.get("name", "")
        existing.vlan_id = network.get("vlan") or network.get("vlan_id")
        existing.zone = network.get("zone") or network.get("networkgroup")
        existing.subnet = network.get("subnet") or network.get("ip_subnet")
        existing.purpose = network.get("purpose")
        existing.enabled = network.get("enabled", True)
        existing.raw_json = _json(network)
        existing.synced_at = now


async def _upsert_ids_config(session: AsyncSession, config: dict) -> None:
    now = datetime.now(UTC)
    existing = await session.scalar(select(IdsConfig).order_by(IdsConfig.synced_at.desc()).limit(1))
    if existing is None:
        existing = IdsConfig(id=1)
        session.add(existing)
    log.info("IDS config from UniFi: %s", config)
    normalised = normalise_ids_config(config)
    existing.mode = normalised["mode"]
    existing.enabled = normalised["enabled"]
    existing.categories = _json(normalised["categories"])
    existing.sensitivity = normalised["sensitivity"]
    existing.raw_json = normalised["raw_json"]
    existing.synced_at = now
    await session.execute(delete(IdsConfig).where(IdsConfig.id != existing.id))


async def _upsert_threats(session: AsyncSession, events: list[dict]) -> None:
    for event in events:
        timestamp = datetime.fromtimestamp(event.get("time", 0) / 1000, UTC) if event.get("time") else datetime.now(UTC)
        existing = await session.scalar(
            select(ThreatEvent).where(
                ThreatEvent.timestamp == timestamp,
                ThreatEvent.signature_id == str(event.get("signature_id") or event.get("key") or ""),
                ThreatEvent.src_ip == event.get("src_ip"),
                ThreatEvent.dst_ip == event.get("dst_ip"),
            )
        )
        if existing is not None:
            continue
        session.add(
            ThreatEvent(
                timestamp=timestamp,
                signature_id=str(event.get("signature_id") or event.get("key") or ""),
                signature_name=event.get("signature") or event.get("msg"),
                category=event.get("category"),
                severity=event.get("severity"),
                src_ip=event.get("src_ip"),
                dst_ip=event.get("dst_ip"),
                action=event.get("action"),
                raw_json=_json(event),
            )
        )


async def _check_drift(session: AsyncSession, policies: list[dict]) -> None:
    canonical = json.dumps(
        sorted(policies, key=lambda item: item.get("_id") or item.get("id") or ""),
        sort_keys=True,
    )
    snapshot_hash = hashlib.sha256(canonical.encode()).hexdigest()
    latest = await session.scalar(
        select(PolicySnapshot)
        .where(PolicySnapshot.snapshot_type == "zone_policies")
        .order_by(PolicySnapshot.created_at.desc())
    )
    if latest is None or latest.snapshot_hash != snapshot_hash:
        session.add(
            PolicySnapshot(
                snapshot_type="zone_policies",
                snapshot_hash=snapshot_hash,
                snapshot_json=canonical,
                created_at=datetime.now(UTC),
            )
        )
        log.info("Policy drift detected; new snapshot saved")


async def _fetch_and_apply(
    session: AsyncSession, label: str, fetcher, applier
) -> list[dict] | dict | None:
    try:
        payload = await fetcher()
        await applier(session, payload)
        return payload
    except Exception:
        log.exception("Failed to sync %s", label)
        return None


async def run_poll_loop() -> None:
    while True:
        async with async_session_factory() as session:
            async with session.begin():
                policies = await _fetch_and_apply(
                    session, "firewall policies", unifi_client.get_firewall_policies, _upsert_policies
                )
                if isinstance(policies, list):
                    await _check_drift(session, policies)
                await _fetch_and_apply(session, "firewall rules", unifi_client.get_firewall_rules, _upsert_rules)
                await _fetch_and_apply(session, "networks", unifi_client.get_networks, _upsert_networks)
                await _fetch_and_apply(session, "IDS config", unifi_client.get_ids_config, _upsert_ids_config)
                await _fetch_and_apply(session, "threat events", unifi_client.get_threat_events, _upsert_threats)
        await asyncio.sleep(settings.poll_interval_seconds)
