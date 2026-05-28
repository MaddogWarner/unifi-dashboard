import asyncio
import hashlib
import ipaddress
import json
import logging
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlparse

import httpx
from sqlalchemy import delete, select
from sqlalchemy.dialects.postgresql import insert

from app.database import async_session_factory
from app.models.settings import AppSetting
from app.models.threatfeed import (
    ThreatFeedEntry,
    ThreatFeedPendingRule,
    ThreatFeedRule,
    ThreatFeedSource,
)
from app.services import unifi_client

log = logging.getLogger(__name__)

CHUNK_SIZE = 500
VALID_RULESETS = {"WAN_IN", "WAN_LOCAL", "LAN_IN", "LAN_OUT", "LAN_LOCAL", "GUEST_IN"}


async def _get_setting(key: str, default: str = "") -> str:
    async with async_session_factory() as session:
        row = await session.get(AppSetting, key)
        return row.value if row else default


def _json(data: Any) -> str:
    return json.dumps(data, sort_keys=True, default=str)


def _hash_payload(data: Any) -> str:
    return hashlib.sha256(_json(data).encode()).hexdigest()


def validate_outbound_url(url: str) -> None:
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("URL must be http or https")
    host = parsed.hostname.lower()
    if host in {"localhost", "metadata.google.internal"}:
        raise ValueError("local or metadata endpoints are not allowed")
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return
    if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved:
        raise ValueError("private, local, multicast, or reserved IP feed URLs are not allowed")


async def _fetch_feed(url: str, proxy: str | None) -> list[str]:
    validate_outbound_url(url)
    async with httpx.AsyncClient(proxy=proxy, timeout=60) as client:
        response = await client.get(url)
        response.raise_for_status()

    entries: list[str] = []
    content_type = response.headers.get("content-type", "")
    if "json" in content_type or url.endswith(".json"):
        data = response.json()
        if isinstance(data, list):
            for item in data:
                if isinstance(item, dict):
                    cidr = item.get("cidr") or item.get("ip")
                    if cidr:
                        entries.append(str(cidr).strip())
    else:
        for line in response.text.splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            entries.append(stripped.split()[0])

    valid = set()
    for entry in entries:
        try:
            valid.add(str(ipaddress.ip_network(entry, strict=False)))
        except ValueError:
            continue
    return sorted(valid)


async def _poll_all_feeds(proxy: str | None) -> None:
    async with async_session_factory() as session:
        sources = (
            await session.scalars(select(ThreatFeedSource).where(ThreatFeedSource.enabled.is_(True)))
        ).all()

    for source in sources:
        try:
            entries = await _fetch_feed(source.url, proxy)
            async with async_session_factory() as session:
                await session.execute(
                    delete(ThreatFeedEntry).where(ThreatFeedEntry.feed_source_id == source.id)
                )
                for cidr in entries:
                    await session.execute(
                        insert(ThreatFeedEntry)
                        .values(cidr=cidr, feed_source_id=source.id)
                        .on_conflict_do_nothing()
                    )
                src = await session.get(ThreatFeedSource, source.id)
                if src:
                    src.last_polled_at = datetime.now(UTC)
                    src.last_entry_count = len(entries)
                    src.last_error = None
                await session.commit()
        except Exception as exc:
            async with async_session_factory() as session:
                src = await session.get(ThreatFeedSource, source.id)
                if src:
                    src.last_error = str(exc)
                    src.last_polled_at = datetime.now(UTC)
                    await session.commit()


def _rule_payloads(ruleset: str, idx: int, chunk: list[str]) -> tuple[dict, dict]:
    group_name = f"ThreatFeed-{ruleset}-{idx}"
    rule_name = f"Block-ThreatFeed-{ruleset}-{idx}"
    group_payload = {
        "name": group_name,
        "group_type": "address-group",
        "group_members": chunk,
    }
    rule_payload = {
        "name": rule_name,
        "action": "drop",
        "enabled": True,
        "ruleset": ruleset,
        "rule_index": 10,
        "src_firewallgroup_ids": [],
        "dst_address": "",
        "src_address": "",
        "protocol": "all",
        "logging": True,
    }
    return group_payload, rule_payload


async def _queue_pending_rule(
    *,
    ruleset: str,
    idx: int,
    action: str,
    entry_count: int,
    group_payload: dict,
    rule_payload: dict,
    existing: ThreatFeedRule | None,
    payload_hash: str,
) -> None:
    payload = {"group": group_payload, "rule": rule_payload}
    async with async_session_factory() as session:
        already_pending = await session.scalar(
            select(ThreatFeedPendingRule).where(
                ThreatFeedPendingRule.ruleset == ruleset,
                ThreatFeedPendingRule.chunk_index == idx,
                ThreatFeedPendingRule.action == action,
                ThreatFeedPendingRule.payload_hash == payload_hash,
                ThreatFeedPendingRule.status == "pending",
            )
        )
        if already_pending:
            return
        session.add(
            ThreatFeedPendingRule(
                ruleset=ruleset,
                chunk_index=idx,
                action=action,
                group_name=group_payload["name"],
                rule_name=rule_payload["name"],
                group_unifi_id=existing.group_unifi_id if existing else None,
                rule_unifi_id=existing.rule_unifi_id if existing else None,
                entry_count=entry_count,
                payload_hash=payload_hash,
                payload_json=_json(payload),
            )
        )
        await session.commit()


async def _record_rule(
    ruleset: str,
    idx: int,
    group_id: str,
    rule_id: str | None,
    payload_hash: str,
) -> None:
    async with async_session_factory() as session:
        existing = await session.scalar(
            select(ThreatFeedRule).where(
                ThreatFeedRule.ruleset == ruleset, ThreatFeedRule.chunk_index == idx
            )
        )
        if existing is None:
            session.add(
                ThreatFeedRule(
                    ruleset=ruleset,
                    chunk_index=idx,
                    group_unifi_id=group_id,
                    rule_unifi_id=rule_id,
                    payload_hash=payload_hash,
                )
            )
        else:
            existing.group_unifi_id = group_id
            existing.rule_unifi_id = rule_id
            existing.payload_hash = payload_hash
        await session.commit()


async def _delete_record(rule_id: int) -> None:
    async with async_session_factory() as session:
        await session.execute(delete(ThreatFeedRule).where(ThreatFeedRule.id == rule_id))
        await session.commit()


async def _apply_change(
    *,
    ruleset: str,
    idx: int,
    action: str,
    payload: dict,
    existing: ThreatFeedRule | None,
    group_unifi_id: str | None,
    rule_unifi_id: str | None,
    payload_hash: str,
) -> None:
    group_payload = payload["group"]
    rule_payload = payload["rule"]
    group_id = group_unifi_id or (existing.group_unifi_id if existing else None)
    rule_id = rule_unifi_id or (existing.rule_unifi_id if existing else None)
    if action == "delete":
        if rule_id:
            await unifi_client.delete_firewall_rule(rule_id)
        if group_id:
            await unifi_client.delete_firewall_group(group_id)
        if existing:
            await _delete_record(existing.id)
        return
    if action == "update":
        if not group_id:
            raise ValueError("Cannot update a threat feed group without a UniFi group ID")
        await unifi_client.update_firewall_group(group_id, group_payload)
        await _record_rule(ruleset, idx, group_id, rule_id, payload_hash)
        return
    group = await unifi_client.create_firewall_group(group_payload)
    group_id = group.get("_id") or group.get("id")
    if not group_id:
        raise ValueError("UniFi did not return a firewall group ID")
    rule_payload["src_firewallgroup_ids"] = [group_id]
    rule = await unifi_client.create_firewall_rule(rule_payload)
    rule_id = rule.get("_id") or rule.get("id")
    await _record_rule(ruleset, idx, group_id, rule_id, payload_hash)


async def apply_pending_rule(pending_id: int) -> ThreatFeedPendingRule:
    async with async_session_factory() as session:
        pending = await session.get(ThreatFeedPendingRule, pending_id)
        if pending is None:
            raise ValueError("Pending rule not found")
        if pending.status != "pending":
            raise ValueError("Pending rule has already been decided")
        existing = await session.scalar(
            select(ThreatFeedRule).where(
                ThreatFeedRule.ruleset == pending.ruleset,
                ThreatFeedRule.chunk_index == pending.chunk_index,
            )
        )
        payload = json.loads(pending.payload_json)
        pending.status = "approved"
        pending.decided_at = datetime.now(UTC)
        await session.commit()
        detached = pending

    try:
        await _apply_change(
            ruleset=detached.ruleset,
            idx=detached.chunk_index,
            action=detached.action,
            payload=payload,
            existing=existing,
            group_unifi_id=detached.group_unifi_id,
            rule_unifi_id=detached.rule_unifi_id,
            payload_hash=detached.payload_hash,
        )
    except Exception as exc:
        async with async_session_factory() as session:
            failed = await session.get(ThreatFeedPendingRule, pending_id)
            if failed:
                failed.status = "failed"
                failed.error = str(exc)
                await session.commit()
                return failed
        raise

    async with async_session_factory() as session:
        applied = await session.get(ThreatFeedPendingRule, pending_id)
        if applied is None:
            raise ValueError("Pending rule not found after apply")
        applied.status = "applied"
        applied.applied_at = datetime.now(UTC)
        await session.commit()
        await session.refresh(applied)
        return applied


async def reject_pending_rule(pending_id: int) -> ThreatFeedPendingRule:
    async with async_session_factory() as session:
        pending = await session.get(ThreatFeedPendingRule, pending_id)
        if pending is None:
            raise ValueError("Pending rule not found")
        if pending.status != "pending":
            raise ValueError("Pending rule has already been decided")
        pending.status = "rejected"
        pending.decided_at = datetime.now(UTC)
        await session.commit()
        await session.refresh(pending)
        return pending


async def _apply_to_unifi(zones: list[str], apply_mode: str) -> None:
    target_zones = [zone for zone in zones if zone in VALID_RULESETS]
    async with async_session_factory() as session:
        rows = (await session.scalars(select(ThreatFeedEntry))).all()
        existing_rules = (await session.scalars(select(ThreatFeedRule))).all()

    all_ips = sorted({row.cidr for row in rows})
    chunks = [all_ips[i : i + CHUNK_SIZE] for i in range(0, len(all_ips), CHUNK_SIZE)]
    existing_by_key = {(rule.ruleset, rule.chunk_index): rule for rule in existing_rules}
    needed_keys = {(zone, idx) for zone in target_zones for idx in range(len(chunks))}

    for key, rule in existing_by_key.items():
        if key not in needed_keys:
            group_payload, rule_payload = _rule_payloads(rule.ruleset, rule.chunk_index, [])
            payload_hash = _hash_payload({"delete": key, "group_id": rule.group_unifi_id})
            if apply_mode == "auto":
                await _apply_change(
                    ruleset=rule.ruleset,
                    idx=rule.chunk_index,
                    action="delete",
                    payload={"group": group_payload, "rule": rule_payload},
                    existing=rule,
                    group_unifi_id=rule.group_unifi_id,
                    rule_unifi_id=rule.rule_unifi_id,
                    payload_hash=payload_hash,
                )
            else:
                await _queue_pending_rule(
                    ruleset=rule.ruleset,
                    idx=rule.chunk_index,
                    action="delete",
                    entry_count=0,
                    group_payload=group_payload,
                    rule_payload=rule_payload,
                    existing=rule,
                    payload_hash=payload_hash,
                )

    for zone in target_zones:
        for idx, chunk in enumerate(chunks):
            group_payload, rule_payload = _rule_payloads(zone, idx, chunk)
            payload = {"group": group_payload, "rule": rule_payload}
            payload_hash = _hash_payload(payload)
            existing = existing_by_key.get((zone, idx))
            if existing and existing.payload_hash == payload_hash:
                continue
            action = "update" if existing else "create"
            if apply_mode == "auto":
                await _apply_change(
                    ruleset=zone,
                    idx=idx,
                    action=action,
                    payload=payload,
                    existing=existing,
                    group_unifi_id=existing.group_unifi_id if existing else None,
                    rule_unifi_id=existing.rule_unifi_id if existing else None,
                    payload_hash=payload_hash,
                )
            else:
                await _queue_pending_rule(
                    ruleset=zone,
                    idx=idx,
                    action=action,
                    entry_count=len(chunk),
                    group_payload=group_payload,
                    rule_payload=rule_payload,
                    existing=existing,
                    payload_hash=payload_hash,
                )


async def _cleanup_unifi_rules() -> None:
    async with async_session_factory() as session:
        rules = (await session.scalars(select(ThreatFeedRule))).all()
    for rule in rules:
        try:
            if rule.rule_unifi_id:
                await unifi_client.delete_firewall_rule(rule.rule_unifi_id)
            await unifi_client.delete_firewall_group(rule.group_unifi_id)
        except Exception:
            log.exception("Failed to delete threat feed UniFi rule %s", rule.id)
    async with async_session_factory() as session:
        await session.execute(delete(ThreatFeedRule))
        await session.execute(delete(ThreatFeedEntry))
        await session.execute(
            delete(ThreatFeedPendingRule).where(ThreatFeedPendingRule.status == "pending")
        )
        await session.commit()


async def run_threat_feed_collector_once() -> None:
    enabled = (await _get_setting("threat_feed.enabled", "false")).lower() == "true"
    if not enabled:
        await _cleanup_unifi_rules()
        return
    proxy_url = await _get_setting("http_proxy.url", "")
    proxy_enabled = (await _get_setting("http_proxy.enabled", "false")).lower() == "true"
    apply_mode = await _get_setting("threat_feed.apply_mode", "preview")
    zones_json = await _get_setting("threat_feed.zones", '["WAN_IN", "WAN_LOCAL"]')
    zones = json.loads(zones_json)
    if not isinstance(zones, list):
        raise ValueError("threat_feed.zones must be a JSON array")
    await _poll_all_feeds(proxy_url if proxy_enabled and proxy_url else None)
    await _apply_to_unifi([str(zone) for zone in zones], "auto" if apply_mode == "auto" else "preview")


async def run_threat_feed_collector() -> None:
    while True:
        interval_hours = 24
        enabled = False
        try:
            enabled = (await _get_setting("threat_feed.enabled", "false")).lower() == "true"
            interval_hours = max(int(await _get_setting("threat_feed.poll_interval_hours", "24")), 1)
            if enabled:
                await run_threat_feed_collector_once()
            else:
                await _cleanup_unifi_rules()
        except Exception:
            log.exception("Threat feed collector error")
        await asyncio.sleep(interval_hours * 3600 if enabled else 60)
