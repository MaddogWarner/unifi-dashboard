import asyncio
import hashlib
import ipaddress
import json
import logging
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlparse

import httpx
from sqlalchemy import delete, select, update
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
VALID_RULE_ACTIONS = {"drop", "deny", "reject"}
RULESET_TO_DEST_ZONE = {
    "WAN_IN": ("Internal", "LAN"),
    "WAN_LOCAL": ("Gateway",),
    "LAN_IN": ("Internal", "LAN"),
    "LAN_OUT": ("Internal", "LAN"),
    "LAN_LOCAL": ("Gateway", "Internal", "LAN"),
    "GUEST_IN": ("Hotspot", "Guest"),
}
INBOUND_DIRECTION = "inbound"
OUTBOUND_DIRECTION = "outbound"
VALID_RULE_DIRECTIONS = {INBOUND_DIRECTION, OUTBOUND_DIRECTION}
VALID_DIRECTION_MODES = {"inbound", "bidirectional"}

# Module-level probe state — set once per process on first enforcement run.
_zone_policy_available: bool | None = None
_zone_id_cache: dict[str, str] = {}  # zone_name → _id
_external_zone_id: str | None = None  # cached External zone ID (source for all threat policies)


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


def _normalise_rule_action(value: str) -> str:
    action = value.strip().lower()
    if action in VALID_RULE_ACTIONS:
        return action
    log.warning("Invalid threat_feed.rule_action '%s'; falling back to 'drop'", value)
    return "drop"


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
            "Zone-based policy API (/v2/api/site/*/firewall-policies) not available; "
            "threat feed will use legacy v1 firewall rules"
        )
    return _zone_policy_available


async def _populate_zone_cache() -> None:
    global _zone_id_cache
    if _zone_id_cache:
        return
    zones = await unifi_client.get_zones_list()
    _zone_id_cache = {
        z["name"]: z.get("_id") or z.get("id")
        for z in zones
        if z.get("name")
    }
    if _zone_id_cache:
        log.info("Zone ID cache populated: %s", list(_zone_id_cache.keys()))
    else:
        log.warning("Zone list is empty; zone-based policies cannot reference zone IDs")


async def _resolve_zone_id(zone_name: str) -> str | None:
    await _populate_zone_cache()
    zone_id = _zone_id_cache.get(zone_name)
    if not zone_id:
        log.warning("Zone '%s' not found in UniFi zone list; policy will be skipped", zone_name)
    return zone_id


async def _get_external_zone_id() -> str | None:
    global _external_zone_id
    if _external_zone_id is None:
        await _populate_zone_cache()
        _external_zone_id = _zone_id_cache.get("External")
        if not _external_zone_id:
            log.warning("External zone not found; threat feed zone policies cannot be created")
    return _external_zone_id


def _normalise_target_zones(zones: list[str], available_zones: set[str]) -> list[str]:
    seen: set[str] = set()
    target_zones = []
    for zone in zones:
        candidates = RULESET_TO_DEST_ZONE.get(zone, (zone,))
        mapped = next((candidate for candidate in candidates if candidate in available_zones), None)
        if not mapped:
            log.warning(
                "'%s' does not map to a valid UniFi zone; skipping (re-select in Settings)",
                zone,
            )
            continue
        if mapped not in seen:
            seen.add(mapped)
            target_zones.append(mapped)
    return target_zones


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


def _zone_policy_name(dest_zone_name: str, idx: int, direction: str) -> str:
    if direction == OUTBOUND_DIRECTION:
        return f"{THREAT_FEED_RULE_PREFIX}{dest_zone_name}-Outbound-{idx}"
    return f"{THREAT_FEED_RULE_PREFIX}{dest_zone_name}-{idx}"


def _ip_zone_match(zone_id: str, chunk: list[str]) -> dict:
    return {
        "zone_id": zone_id,
        "matching_target": "IP",
        "matching_target_type": "SPECIFIC",
        "match_opposite_ips": False,
        "match_opposite_ports": False,
        "port_matching_type": "ANY",
        "ips": chunk,
    }


def _any_zone_match(zone_id: str) -> dict:
    return {
        "zone_id": zone_id,
        "matching_target": "ANY",
        "match_opposite_ports": False,
        "port_matching_type": "ANY",
    }


def _zone_policy_payload(
    external_zone_id: str,
    dest_zone_id: str,
    chunk: list[str],
    dest_zone_name: str,
    idx: int,
    direction: str,
) -> dict:
    # Confirmed structure from on-device probe of /proxy/network/v2/api/site/{site}/firewall-policies.
    # IPs are embedded directly in source.ips — no firewall group reference needed.
    # Bidirectional mode requires a second policy with the zone references reversed.
    if direction == OUTBOUND_DIRECTION:
        source = _any_zone_match(dest_zone_id)
        destination = _ip_zone_match(external_zone_id, chunk)
    else:
        source = _ip_zone_match(external_zone_id, chunk)
        destination = _any_zone_match(dest_zone_id)
    return {
        "name": _zone_policy_name(dest_zone_name, idx, direction),
        "enabled": True,
        "action": "BLOCK",
        "ip_version": "IPV4",
        "protocol": "all",
        "connection_state_type": "ALL",
        "connection_states": [],
        "create_allow_respond": False,
        "match_ip_sec": False,
        "match_opposite_protocol": False,
        "logging": True,
        "icmp_typename": "ANY",
        "icmp_v6_typename": "ANY",
        "schedule": {"mode": "ALWAYS"},
        "source": source,
        "destination": destination,
    }


async def _get_or_create_zone_policy(
    external_zone_id: str,
    dest_zone_id: str,
    chunk: list[str],
    dest_zone_name: str,
    idx: int,
    direction: str,
) -> dict:
    policy_payload = _zone_policy_payload(
        external_zone_id, dest_zone_id, chunk, dest_zone_name, idx, direction
    )
    policies = await unifi_client.get_zone_policies()
    existing = _find_named(policies, policy_payload["name"])
    if existing:
        policy_id = _unifi_id(existing)
        log.info("Reusing existing zone policy %s id=%s", policy_payload["name"], policy_id)
        if policy_id:
            # Update the IP list in-place; all other fields stay the same.
            return await unifi_client.update_zone_policy(policy_id, {**policy_payload, "_id": policy_id})
        return existing
    return await unifi_client.create_zone_policy(policy_payload)


def validate_outbound_url(url: str, allow_private: bool = False) -> None:
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
    blocked = ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved
    if not allow_private:
        blocked = blocked or ip.is_private
    if blocked:
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


async def _fetch_misp_feed(source: ThreatFeedSource) -> list[str]:
    validate_outbound_url(source.url, allow_private=True)
    endpoint = f"{source.url.rstrip('/')}/attributes/restSearch"
    headers = {
        "Authorization": source.api_key or "",
        "Accept": "application/json",
        "Content-Type": "application/json",
    }
    valid: set[str] = set()
    page_size = 500
    page = 1

    async with httpx.AsyncClient(verify=bool(source.misp_verify_ssl), timeout=60) as client:
        while True:
            body = {
                "returnFormat": "json",
                "type": ["ip-src", "ip-dst", "ip-src|port", "ip-dst|port", "cidr"],
                "to_ids": True,
                "enforceWarninglist": True,
                "limit": page_size,
                "page": page,
            }
            response = await client.post(endpoint, json=body, headers=headers)
            response.raise_for_status()
            data = response.json()
            attributes = data.get("response", {}).get("Attribute", []) or data.get("Attribute", [])
            if not isinstance(attributes, list):
                attributes = []
            for attr in attributes:
                if not isinstance(attr, dict):
                    continue
                value = str(attr.get("value", "")).strip()
                if not value:
                    continue
                if "|" in value:
                    value = value.split("|")[0]
                try:
                    valid.add(str(ipaddress.ip_network(value, strict=False)))
                except ValueError:
                    continue
            if len(attributes) < page_size:
                break
            page += 1

    return sorted(valid)


async def _poll_all_feeds(proxy: str | None) -> None:
    async with async_session_factory() as session:
        sources = (
            await session.scalars(select(ThreatFeedSource).where(ThreatFeedSource.enabled.is_(True)))
        ).all()

    for source in sources:
        try:
            if getattr(source, "source_type", "url") == "misp":
                entries = await _fetch_misp_feed(source)
            else:
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


def _rule_payloads(
    ruleset: str,
    idx: int,
    chunk: list[str],
    direction: str = INBOUND_DIRECTION,
    action: str = "drop",
) -> tuple[dict, dict]:
    group_name = f"{THREAT_FEED_GROUP_PREFIX}{ruleset}-{idx}"
    rule_name = _zone_policy_name(ruleset, idx, direction)
    group_payload = {
        "name": group_name,
        "group_type": "address-group",
        "group_members": chunk,
    }
    rule_payload = {
        "name": rule_name,
        "action": action,
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


def _find_rule_after_apply(rules: list[dict], rule_id: str, rule_name: str) -> dict | None:
    return next(
        (
            rule
            for rule in rules
            if _unifi_id(rule) == rule_id or rule.get("name") == rule_name
        ),
        None,
    )


async def _verify_firewall_rule_action(
    rule_id: str,
    rule_name: str,
    expected_action: str,
) -> str | None:
    stored = _find_rule_after_apply(await unifi_client.get_firewall_rules(), rule_id, rule_name)
    if not stored:
        message = (
            f"Console did not return threat feed rule '{rule_name}' after apply - "
            "check UniFi manually"
        )
        log.warning(message)
        return message
    stored_action = str(stored.get("action", "")).lower()
    if stored_action != expected_action.lower():
        message = (
            f"Console stored action '{stored.get('action')}', expected '{expected_action}' - "
            "set threat_feed.rule_action"
        )
        log.warning(message)
        return message
    return None


async def _queue_pending_rule(
    *,
    ruleset: str,
    idx: int,
    direction: str,
    action: str,
    entry_count: int,
    group_payload: dict,
    rule_payload: dict,
    chunk: list[str],
    existing: ThreatFeedRule | None,
    payload_hash: str,
) -> None:
    payload = {"group": group_payload, "rule": rule_payload, "chunk": chunk}
    async with async_session_factory() as session:
        # Remove stale failed/rejected records with the same key to avoid unique constraint
        # violations when a subsequent approval attempt also fails.
        await session.execute(
            delete(ThreatFeedPendingRule).where(
                ThreatFeedPendingRule.ruleset == ruleset,
                ThreatFeedPendingRule.chunk_index == idx,
                ThreatFeedPendingRule.direction == direction,
                ThreatFeedPendingRule.action == action,
                ThreatFeedPendingRule.payload_hash == payload_hash,
                ThreatFeedPendingRule.status.in_(["failed", "rejected"]),
            )
        )
        already_pending = await session.scalar(
            select(ThreatFeedPendingRule).where(
                ThreatFeedPendingRule.ruleset == ruleset,
                ThreatFeedPendingRule.chunk_index == idx,
                ThreatFeedPendingRule.direction == direction,
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
                direction=direction,
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
    direction: str,
    group_id: str | None,
    rule_id: str | None,
    payload_hash: str,
) -> None:
    # Zone policies do not use firewall groups. Store an empty sentinel so
    # approval remains resilient on deployed databases still carrying the old
    # NOT NULL constraint while migrations catch up.
    stored_group_id = group_id if group_id is not None else ""
    async with async_session_factory() as session:
        await session.execute(
            insert(ThreatFeedRule)
            .values(
                ruleset=ruleset,
                chunk_index=idx,
                direction=direction,
                group_unifi_id=stored_group_id,
                rule_unifi_id=rule_id,
                payload_hash=payload_hash,
            )
            .on_conflict_do_update(
                index_elements=["ruleset", "chunk_index", "direction"],
                set_={
                    "group_unifi_id": stored_group_id,
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
    direction: str,
    action: str,
    payload: dict,
    existing: ThreatFeedRule | None,
    group_unifi_id: str | None,
    rule_unifi_id: str | None,
    payload_hash: str,
) -> str | None:
    group_payload = payload["group"]
    rule_payload = payload["rule"]
    chunk: list[str] = payload.get("chunk", [])
    if direction not in VALID_RULE_DIRECTIONS:
        raise ValueError(f"Unsupported threat feed rule direction: {direction}")
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
        return None
    use_zone_policies = await _ensure_zone_policy_probed()
    if use_zone_policies:
        # Zone policies embed IPs directly — no firewall group needed.
        external_zone_id = await _get_external_zone_id()
        dest_zone_id = await _resolve_zone_id(ruleset)
        if not external_zone_id or not dest_zone_id:
            log.warning(
                "Zone IDs not resolved (external=%s dest=%s); skipping zone policy for %s chunk %s",
                external_zone_id,
                dest_zone_id,
                ruleset,
                idx,
            )
            return None
        if action == "update":
            # Update just replaces the IP list via a full PUT.
            if rule_id:
                policy = await _get_or_create_zone_policy(
                    external_zone_id, dest_zone_id, chunk, ruleset, idx, direction
                )
                rule_id = _unifi_id(policy)
            await _record_rule(ruleset, idx, direction, None, rule_id, payload_hash)
            return None
        policy = await _get_or_create_zone_policy(
            external_zone_id, dest_zone_id, chunk, ruleset, idx, direction
        )
        rule_id = _unifi_id(policy)
        log.info(
            "Threat feed enforcement (zone policy): rule_id=%s zone=%s direction=%s chunk=%s",
            rule_id,
            ruleset,
            direction,
            idx,
        )
        await _record_rule(ruleset, idx, direction, None, rule_id, payload_hash)
        return None
    # Classic rules path (fallback when zone policy API unavailable).
    if direction != INBOUND_DIRECTION:
        raise ValueError("Bidirectional threat feed enforcement requires zone policy support")
    if action == "update":
        if not group_id:
            raise ValueError("Cannot update a threat feed group without a UniFi group ID")
        await unifi_client.update_firewall_group(group_id, group_payload)
        verify_error = await _verify_firewall_rule_action(
            rule_id or "",
            str(rule_payload["name"]),
            str(rule_payload["action"]),
        )
        await _record_rule(ruleset, idx, direction, group_id, rule_id, payload_hash)
        return verify_error
    group = await _get_or_create_firewall_group(group_payload)
    group_id = _unifi_id(group)
    if not group_id:
        raise ValueError("UniFi did not return a firewall group ID")
    rule = await _get_or_create_firewall_rule(rule_payload, group_id)
    rule_id = _unifi_id(rule)
    if not rule_id:
        raise ValueError("UniFi did not return a firewall rule ID")
    verify_error = await _verify_firewall_rule_action(
        rule_id,
        str(rule_payload["name"]),
        str(rule_payload["action"]),
    )
    log.info(
        "Threat feed enforcement (classic rule): group_id=%s rule_id=%s ruleset=%s chunk=%s",
        group_id,
        rule_id,
        ruleset,
        idx,
    )
    await _record_rule(ruleset, idx, direction, group_id, rule_id, payload_hash)
    return verify_error


async def _do_apply_pending_rule(pending_id: int) -> ThreatFeedPendingRule:
    # Atomically claim the row: flip pending -> approved only if it is still
    # pending. rowcount tells us whether this call won the claim, which stops a
    # double-submit (rapid re-click / two browser tabs) from both pushing the
    # same rule to UniFi. The claim is its own short transaction so no DB lock is
    # held across the slow UniFi calls that follow.
    async with async_session_factory() as session:
        claimed = await session.execute(
            update(ThreatFeedPendingRule)
            .where(
                ThreatFeedPendingRule.id == pending_id,
                ThreatFeedPendingRule.status == "pending",
            )
            .values(status="approved", decided_at=datetime.now(UTC))
        )
        await session.commit()
        if not claimed.rowcount:
            if await session.get(ThreatFeedPendingRule, pending_id) is None:
                raise ValueError("Pending rule not found")
            raise ValueError("Pending rule has already been decided")

        pending = await session.get(ThreatFeedPendingRule, pending_id)
        existing = await session.scalar(
            select(ThreatFeedRule).where(
                ThreatFeedRule.ruleset == pending.ruleset,
                ThreatFeedRule.chunk_index == pending.chunk_index,
                ThreatFeedRule.direction == pending.direction,
            )
        )
        payload = json.loads(pending.payload_json)
        claimed_rule = pending

    try:
        apply_error = await _apply_change(
            ruleset=claimed_rule.ruleset,
            idx=claimed_rule.chunk_index,
            direction=claimed_rule.direction,
            action=claimed_rule.action,
            payload=payload,
            existing=existing,
            group_unifi_id=claimed_rule.group_unifi_id,
            rule_unifi_id=claimed_rule.rule_unifi_id,
            payload_hash=claimed_rule.payload_hash,
        )
    except Exception as exc:
        async with async_session_factory() as session:
            failed = await session.get(ThreatFeedPendingRule, pending_id)
            if failed:
                failed.status = "failed"
                failed.error = str(exc)
                await session.commit()
                await session.refresh(failed)
                return failed
        raise

    if apply_error:
        async with async_session_factory() as session:
            failed = await session.get(ThreatFeedPendingRule, pending_id)
            if failed:
                failed.status = "failed"
                failed.error = apply_error
                await session.commit()
                await session.refresh(failed)
                return failed
        raise ValueError("Pending rule not found after failed apply verification")

    async with async_session_factory() as session:
        applied = await session.get(ThreatFeedPendingRule, pending_id)
        if applied is None:
            raise ValueError("Pending rule not found after apply")
        applied.status = "applied"
        applied.applied_at = datetime.now(UTC)
        await session.commit()
        await session.refresh(applied)
        return applied


async def apply_pending_rule(pending_id: int) -> ThreatFeedPendingRule:
    # Shield the apply from cancellation. If the browser request is cut (rapid
    # re-click, navigation, or an nginx read timeout on a large feed) the request
    # handler task is cancelled, but the shielded coroutine still runs to
    # completion and drives the row to a terminal applied/failed status. Without
    # this the row was abandoned mid-apply in "approved" — invisible to the
    # pending list and never applied: the original "approved rule won't
    # disappear" bug.
    return await asyncio.shield(_do_apply_pending_rule(pending_id))


async def recover_orphaned_approvals() -> None:
    # Backstop for a process killed mid-apply (where shield cannot help): rows
    # left in "approved" are invisible to the pending list and never reach
    # "applied". Delete them on startup so the next collector run re-queues any
    # still-needed change as a fresh "pending" row; changes already enforced on
    # UniFi are skipped by payload hash, and _apply_change is idempotent
    # (get-or-create by name) so nothing is duplicated. Deleting rather than
    # resetting to "pending" avoids colliding with the pending unique key if a
    # refresh has meanwhile re-queued the same change.
    async with async_session_factory() as session:
        result = await session.execute(
            delete(ThreatFeedPendingRule).where(ThreatFeedPendingRule.status == "approved")
        )
        await session.commit()
        if result.rowcount:
            log.warning(
                "Cleared %s orphaned threat-feed approval(s) after restart", result.rowcount
            )


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


async def _apply_to_unifi(
    zones: list[str],
    apply_mode: str,
    direction_mode: str,
    rule_action: str,
) -> None:
    if direction_mode not in VALID_DIRECTION_MODES:
        raise ValueError("threat_feed.direction_mode must be inbound or bidirectional")
    use_zone_policies = await _ensure_zone_policy_probed()
    if use_zone_policies:
        await _populate_zone_cache()
        target_zones = _normalise_target_zones(zones, set(_zone_id_cache))
    else:
        if direction_mode == "bidirectional":
            log.warning(
                "Bidirectional threat feed enforcement requires zone policies; "
                "classic firewall rule fallback will remain inbound-only"
            )
        target_zones = [zone for zone in zones if zone in VALID_RULESETS]
    target_directions = [INBOUND_DIRECTION]
    if use_zone_policies and direction_mode == "bidirectional":
        target_directions.append(OUTBOUND_DIRECTION)
    async with async_session_factory() as session:
        rows = (await session.scalars(select(ThreatFeedEntry))).all()
        existing_rules = (await session.scalars(select(ThreatFeedRule))).all()

    all_ips = sorted({row.cidr for row in rows})
    chunks = [all_ips[i : i + CHUNK_SIZE] for i in range(0, len(all_ips), CHUNK_SIZE)]
    existing_by_key = {
        (rule.ruleset, rule.chunk_index, rule.direction): rule
        for rule in existing_rules
    }
    needed_keys = {
        (zone, idx, direction)
        for zone in target_zones
        for idx in range(len(chunks))
        for direction in target_directions
    }

    for key, rule in existing_by_key.items():
        if key not in needed_keys:
            group_payload, rule_payload = _rule_payloads(
                rule.ruleset, rule.chunk_index, [], rule.direction, rule_action
            )
            payload_hash = _hash_payload(
                {"delete": key, "group_id": rule.group_unifi_id, "direction": rule.direction}
            )
            if apply_mode == "auto":
                await _apply_change(
                    ruleset=rule.ruleset,
                    idx=rule.chunk_index,
                    direction=rule.direction,
                    action="delete",
                    payload={"group": group_payload, "rule": rule_payload, "chunk": []},
                    existing=rule,
                    group_unifi_id=rule.group_unifi_id,
                    rule_unifi_id=rule.rule_unifi_id,
                    payload_hash=payload_hash,
                )
            else:
                await _queue_pending_rule(
                    ruleset=rule.ruleset,
                    idx=rule.chunk_index,
                    direction=rule.direction,
                    action="delete",
                    entry_count=0,
                    group_payload=group_payload,
                    rule_payload=rule_payload,
                    chunk=[],
                    existing=rule,
                    payload_hash=payload_hash,
                )

    for zone in target_zones:
        for idx, chunk in enumerate(chunks):
            for direction in target_directions:
                group_payload, rule_payload = _rule_payloads(zone, idx, chunk, direction, rule_action)
                payload = {"group": group_payload, "rule": rule_payload, "chunk": chunk}
                payload_hash = _hash_payload(
                    {"group": group_payload, "rule": rule_payload, "direction": direction}
                )
                existing = existing_by_key.get((zone, idx, direction))
                if existing and existing.payload_hash == payload_hash:
                    continue
                action = "update" if existing else "create"
                if apply_mode == "auto":
                    await _apply_change(
                        ruleset=zone,
                        idx=idx,
                        direction=direction,
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
                        direction=direction,
                        action=action,
                        entry_count=len(chunk),
                        group_payload=group_payload,
                        rule_payload=rule_payload,
                        chunk=chunk,
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
            if rule.group_unifi_id:
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
    direction_mode = await _get_setting("threat_feed.direction_mode", "inbound")
    rule_action = _normalise_rule_action(await _get_setting("threat_feed.rule_action", "drop"))
    zones_json = await _get_setting("threat_feed.zones", '["WAN_IN", "WAN_LOCAL"]')
    zones = json.loads(zones_json)
    if not isinstance(zones, list):
        raise ValueError("threat_feed.zones must be a JSON array")
    await _poll_all_feeds(proxy_url if proxy_enabled and proxy_url else None)
    await _apply_to_unifi(
        [str(zone) for zone in zones],
        "auto" if apply_mode == "auto" else "preview",
        direction_mode,
        rule_action,
    )


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
