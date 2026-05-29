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
THREAT_FEED_RULE_INDEX_START = 20000
THREAT_FEED_GROUP_PREFIX = "ThreatFeed-"
THREAT_FEED_RULE_PREFIX = "Block-ThreatFeed-"
VALID_RULESETS = {"WAN_IN", "WAN_LOCAL", "LAN_IN", "LAN_OUT", "LAN_LOCAL", "GUEST_IN"}

# Maps legacy v1 ruleset names to zone-based policy source zone names.
# WAN_IN and WAN_LOCAL both map to External because in the zone policy engine
# the distinction is made by destination zone, not ruleset name.
RULESET_TO_ZONE = {
    "WAN_IN": "External",
    "WAN_LOCAL": "External",
    "LAN_IN": "Internal",
    "LAN_LOCAL": "Internal",
    "LAN_OUT": "Internal",
    "GUEST_IN": "Guest",
}

# Module-level probe state — set once per process on first enforcement run.
_zone_policy_available: bool | None = None
_zone_id_cache: dict[str, str] = {}  # zone_name → _id


async def _get_setting(key: str, default: str = "") -> str:
    async with async_session_factory() as session:
        row = await session.get(AppSetting, key)
        return row.value if row else default


def _json(data: Any) -> str:
    return json.dumps(data, sort_keys=True, default=str)


def _hash_payload(data: Any) -> str:
    return hashlib.sha256(_json(data).encode()).hexdigest()


def _is_rule_index_collision(exc: Exception) -> bool:
    return isinstance(exc, httpx.HTTPStatusError) and "FirewallRuleIndexExisted" in str(exc)


def _unifi_id(item: dict | None) -> str | None:
    return (item or {}).get("_id") or (item or {}).get("id")


def _find_named(items: list[dict], name: str) -> dict | None:
    return next((item for item in items if item.get("name") == name), None)


def _is_not_found(exc: Exception) -> bool:
    return isinstance(exc, httpx.HTTPStatusError) and exc.response.status_code == 404


async def _ensure_zone_policy_probed() -> bool:
    global _zone_policy_available
    if _zone_policy_available is not None:
        return _zone_policy_available
    _zone_policy_available = await unifi_client.zone_policy_api_available()
    if _zone_policy_available:
        policies = await unifi_client.get_zone_policies()
        if policies:
            log.info(
                "Zone-based policy API available; first existing policy structure: %s",
                json.dumps(policies[0], default=str),
            )
        else:
            log.info("Zone-based policy API available (no existing zone policies)")
    else:
        log.warning(
            "Zone-based policy API (/rest/firewallpolicy) not available; "
            "threat feed will use legacy v1 firewall rules"
        )
    return _zone_policy_available


async def _resolve_zone_id(zone_name: str) -> str | None:
    global _zone_id_cache
    if not _zone_id_cache:
        zones = await unifi_client.get_zones_list()
        _zone_id_cache = {
            z["name"]: z.get("_id") or z.get("id")
            for z in zones
            if z.get("name")
        }
        if not _zone_id_cache:
            # /rest/zone unavailable — try extracting zone IDs from existing firewall policies
            log.info("Zone list API empty; attempting zone ID extraction from existing policies")
            policies = await unifi_client.get_zone_policies()
            for policy in policies:
                for direction in ("src", "dst", "source", "destination"):
                    obj = policy.get(direction, {})
                    if not isinstance(obj, dict):
                        continue
                    zid = obj.get("zone_id") or obj.get("zoneId")
                    zname = obj.get("zone") or obj.get("zoneName") or obj.get("zone_name")
                    if zid and zname and zname not in _zone_id_cache:
                        _zone_id_cache[zname] = zid
        if _zone_id_cache:
            log.info("Zone ID cache populated: %s", list(_zone_id_cache.keys()))
        else:
            log.warning("Zone list is empty; zone-based policies cannot reference zone IDs")
    zone_id = _zone_id_cache.get(zone_name)
    if not zone_id:
        log.warning("Zone '%s' not found in UniFi zone list; policy will be skipped", zone_name)
    return zone_id


async def _delete_firewall_rule_if_present(rule_id: str) -> None:
    try:
        await unifi_client.delete_firewall_rule(rule_id)
    except Exception as exc:
        if not _is_not_found(exc):
            raise
        log.info("Threat feed UniFi rule already missing id=%s", rule_id)


async def _delete_firewall_group_if_present(group_id: str) -> None:
    try:
        await unifi_client.delete_firewall_group(group_id)
    except Exception as exc:
        if not _is_not_found(exc):
            raise
        log.info("Threat feed UniFi group already missing id=%s", group_id)


async def _delete_zone_policy_if_present(policy_id: str) -> None:
    try:
        await unifi_client.delete_zone_policy(policy_id)
    except Exception as exc:
        if not _is_not_found(exc):
            raise
        log.info("Threat feed zone policy already missing id=%s", policy_id)


def _zone_policy_payload(zone_id: str, group_id: str, zone_name: str, idx: int) -> dict:
    """Build a zone-based firewall policy payload.

    Field names are based on the UniFi Network 10 /rest/firewallpolicy pattern.
    The exact structure is logged at INFO on first startup for on-device confirmation.
    """
    policy_name = f"{THREAT_FEED_RULE_PREFIX}{zone_name}-{idx}"
    return {
        "name": policy_name,
        "enabled": True,
        "action": "block",
        "ip_version": "IPv4",
        "source": {
            "zone_id": zone_id,
            "firewallgroup_ids": [group_id],
        },
        "destination": {},
        "logging": True,
    }


async def _get_or_create_zone_policy(zone_id: str, group_id: str, zone_name: str, idx: int) -> dict:
    policy_payload = _zone_policy_payload(zone_id, group_id, zone_name, idx)
    policies = await unifi_client.get_zone_policies()
    existing = _find_named(policies, policy_payload["name"])
    if existing:
        policy_id = _unifi_id(existing)
        log.info("Reusing existing zone policy %s id=%s", policy_payload["name"], policy_id)
        if policy_id:
            updated = {
                **policy_payload,
                "source": {**policy_payload["source"], "firewallgroup_ids": [group_id]},
            }
            return await unifi_client.update_zone_policy(policy_id, updated)
        return existing
    return await unifi_client.create_zone_policy(policy_payload)


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
        try:
            data = response.json()
        except json.JSONDecodeError:
            # JSONL — one JSON object per line (e.g. Spamhaus DROP v4)
            data = []
            for line in response.text.splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                try:
                    data.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
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
    group_name = f"{THREAT_FEED_GROUP_PREFIX}{ruleset}-{idx}"
    rule_name = f"{THREAT_FEED_RULE_PREFIX}{ruleset}-{idx}"
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
        "rule_index": THREAT_FEED_RULE_INDEX_START,
        "src_firewallgroup_ids": [],
        "protocol": "all",
        "logging": True,
    }
    return group_payload, rule_payload


async def _next_rule_index(ruleset: str, start: int = THREAT_FEED_RULE_INDEX_START) -> int:
    used_indexes = set()
    for rule in await unifi_client.get_firewall_rules():
        if rule.get("ruleset") != ruleset:
            continue
        try:
            used_indexes.add(int(rule.get("rule_index")))
        except (TypeError, ValueError):
            continue
    candidate = start
    while candidate in used_indexes:
        candidate += 1
    return candidate


async def _create_firewall_rule_with_available_index(rule_payload: dict, group_id: str) -> dict:
    payload = {
        **rule_payload,
        "rule_index": await _next_rule_index(str(rule_payload["ruleset"]), int(rule_payload["rule_index"])),
        "src_firewallgroup_ids": [group_id],
    }
    try:
        return await unifi_client.create_firewall_rule(payload)
    except Exception as exc:
        if not _is_rule_index_collision(exc):
            raise
        retry_payload = {
            **payload,
            "rule_index": await _next_rule_index(
                str(rule_payload["ruleset"]),
                int(payload["rule_index"]) + 1,
            ),
        }
        return await unifi_client.create_firewall_rule(retry_payload)


async def _get_or_create_firewall_group(group_payload: dict) -> dict:
    groups = await unifi_client.get_firewall_groups()
    existing = _find_named(groups, group_payload["name"])
    if existing:
        group_id = _unifi_id(existing)
        log.info("Reusing existing threat feed group %s id=%s", group_payload["name"], group_id)
        if group_id:
            return await unifi_client.update_firewall_group(group_id, group_payload)
        return existing
    return await unifi_client.create_firewall_group(group_payload)


async def _get_or_create_firewall_rule(rule_payload: dict, group_id: str) -> dict:
    rules = await unifi_client.get_firewall_rules()
    existing = _find_named(rules, rule_payload["name"])
    if existing:
        rule_id = _unifi_id(existing)
        log.info("Reusing existing threat feed rule %s id=%s", rule_payload["name"], rule_id)
        if rule_id:
            return await unifi_client.update_firewall_rule(
                rule_id,
                {**rule_payload, "src_firewallgroup_ids": [group_id]},
            )
        return existing
    return await _create_firewall_rule_with_available_index(rule_payload, group_id)


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
        # Remove stale failed/rejected records with the same key to avoid unique constraint
        # violations when a subsequent approval attempt also fails.
        await session.execute(
            delete(ThreatFeedPendingRule).where(
                ThreatFeedPendingRule.ruleset == ruleset,
                ThreatFeedPendingRule.chunk_index == idx,
                ThreatFeedPendingRule.action == action,
                ThreatFeedPendingRule.payload_hash == payload_hash,
                ThreatFeedPendingRule.status.in_(["failed", "rejected"]),
            )
        )
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
        await session.execute(
            insert(ThreatFeedRule)
            .values(
                ruleset=ruleset,
                chunk_index=idx,
                group_unifi_id=group_id,
                rule_unifi_id=rule_id,
                payload_hash=payload_hash,
            )
            .on_conflict_do_update(
                index_elements=["ruleset", "chunk_index"],
                set_={
                    "group_unifi_id": group_id,
                    "rule_unifi_id": rule_id,
                    "payload_hash": payload_hash,
                    "updated_at": datetime.now(UTC),
                },
            )
        )
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
            # Records with a v1 ruleset name used classic rules; others used zone policies.
            if ruleset in VALID_RULESETS:
                await _delete_firewall_rule_if_present(rule_id)
            else:
                await _delete_zone_policy_if_present(rule_id)
        if group_id:
            await _delete_firewall_group_if_present(group_id)
        if existing:
            await _delete_record(existing.id)
        return
    if action == "update":
        if not group_id:
            raise ValueError("Cannot update a threat feed group without a UniFi group ID")
        await unifi_client.update_firewall_group(group_id, group_payload)
        await _record_rule(ruleset, idx, group_id, rule_id, payload_hash)
        return
    group = await _get_or_create_firewall_group(group_payload)
    group_id = _unifi_id(group)
    if not group_id:
        raise ValueError("UniFi did not return a firewall group ID")
    use_zone_policies = await _ensure_zone_policy_probed()
    if use_zone_policies:
        zone_id = await _resolve_zone_id(ruleset)
        if zone_id:
            policy = await _get_or_create_zone_policy(zone_id, group_id, ruleset, idx)
            rule_id = _unifi_id(policy)
        else:
            rule_id = None
            log.warning(
                "Zone '%s' not resolved; zone policy not created for chunk %s (group created)",
                ruleset,
                idx,
            )
    else:
        rule = await _get_or_create_firewall_rule(rule_payload, group_id)
        rule_id = _unifi_id(rule)
        if not rule_id:
            raise ValueError("UniFi did not return a firewall rule ID")
    log.info(
        "Threat feed enforcement: group_id=%s rule_id=%s ruleset=%s chunk=%s",
        group_id,
        rule_id,
        ruleset,
        idx,
    )
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
    use_zone_policies = await _ensure_zone_policy_probed()
    if use_zone_policies:
        # Map v1 ruleset names to zone names; keep unknown names as-is; deduplicate preserving order.
        seen: set[str] = set()
        target_zones = []
        for zone in zones:
            mapped = RULESET_TO_ZONE.get(zone, zone)
            if mapped not in seen:
                seen.add(mapped)
                target_zones.append(mapped)
    else:
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
                if rule.ruleset in VALID_RULESETS:
                    await _delete_firewall_rule_if_present(rule.rule_unifi_id)
                else:
                    await _delete_zone_policy_if_present(rule.rule_unifi_id)
            await _delete_firewall_group_if_present(rule.group_unifi_id)
        except Exception:
            log.exception("Failed to delete threat feed UniFi rule %s", rule.id)

    # Sweep for orphaned classic rules
    for rule in await unifi_client.get_firewall_rules():
        rule_id = _unifi_id(rule)
        if rule_id and str(rule.get("name", "")).startswith(THREAT_FEED_RULE_PREFIX):
            await _delete_firewall_rule_if_present(rule_id)

    # Sweep for orphaned zone policies
    for policy in await unifi_client.get_zone_policies():
        policy_id = _unifi_id(policy)
        if policy_id and str(policy.get("name", "")).startswith(THREAT_FEED_RULE_PREFIX):
            await _delete_zone_policy_if_present(policy_id)

    # Sweep for orphaned groups
    for group in await unifi_client.get_firewall_groups():
        group_id = _unifi_id(group)
        if group_id and str(group.get("name", "")).startswith(THREAT_FEED_GROUP_PREFIX):
            await _delete_firewall_group_if_present(group_id)

    async with async_session_factory() as session:
        await session.execute(delete(ThreatFeedRule))
        await session.execute(delete(ThreatFeedEntry))
        await session.execute(delete(ThreatFeedPendingRule))
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
