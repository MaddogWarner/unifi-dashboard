import pytest
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from app.collectors import threat_feed_collector
from app.collectors.threat_feed_collector import (
    _do_apply_pending_rule,
    _fetch_misp_feed,
    _normalise_rule_action,
    _normalise_target_zones,
    _rule_payloads,
    validate_outbound_url,
)
from app.database import Base
from app.models.threatfeed import ThreatFeedPendingRule, ThreatFeedRule, ThreatFeedSource


def test_legacy_rulesets_map_to_available_zone_names() -> None:
    result = _normalise_target_zones(
        ["WAN_IN", "WAN_LOCAL", "GUEST_IN"],
        {"External", "Gateway", "Hotspot", "Internal"},
    )

    assert result == ["Internal", "Gateway", "Hotspot"]


def test_legacy_rulesets_are_deduplicated_after_mapping() -> None:
    result = _normalise_target_zones(
        ["WAN_IN", "LAN_IN", "Internal"],
        {"External", "Gateway", "Internal"},
    )

    assert result == ["Internal"]


def test_actual_custom_zone_names_are_preserved() -> None:
    result = _normalise_target_zones(
        ["IoT Smart Home", "WAN_IN"],
        {"Gateway", "Internal", "IoT Smart Home"},
    )

    assert result == ["IoT Smart Home", "Internal"]


def test_legacy_ruleset_aliases_support_guest_zone_name() -> None:
    result = _normalise_target_zones(["GUEST_IN"], {"Guest", "Internal"})

    assert result == ["Guest"]


def test_validate_outbound_url_allows_private_only_when_requested() -> None:
    with pytest.raises(ValueError):
        validate_outbound_url("https://192.168.1.20/feed.netset")

    validate_outbound_url("https://192.168.1.20/feed.netset", allow_private=True)

    with pytest.raises(ValueError):
        validate_outbound_url("https://127.0.0.1/feed.netset", allow_private=True)


def test_rule_payloads_honour_configured_action() -> None:
    _group_payload, rule_payload = _rule_payloads("WAN_IN", 0, ["203.0.113.10/32"], action="deny")

    assert rule_payload["action"] == "deny"


def test_invalid_rule_action_falls_back_to_drop(caplog: pytest.LogCaptureFixture) -> None:
    assert _normalise_rule_action("allow") == "drop"
    assert "Invalid threat_feed.rule_action" in caplog.text


@pytest.mark.asyncio
async def test_fetch_misp_feed_reads_envelope_fallback_and_paginates(monkeypatch) -> None:
    posts: list[dict] = []
    first_page = [{"value": f"10.0.{idx // 250}.{idx % 250}"} for idx in range(498)]
    first_page.extend([{"value": "203.0.113.10|443"}, {"value": "not-an-ip"}])
    pages = [
        {"response": {"Attribute": first_page}},
        {"Attribute": [{"value": "198.51.100.0/24"}]},
    ]

    class FakeResponse:
        def __init__(self, payload: dict) -> None:
            self.payload = payload

        def raise_for_status(self) -> None:
            return None

        def json(self) -> dict:
            return self.payload

    class FakeAsyncClient:
        def __init__(self, **kwargs) -> None:
            self.kwargs = kwargs

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb) -> None:
            return None

        async def post(self, url: str, json: dict, headers: dict) -> FakeResponse:
            posts.append({"url": url, "json": json, "headers": headers})
            return FakeResponse(pages[len(posts) - 1])

    monkeypatch.setattr(threat_feed_collector.httpx, "AsyncClient", FakeAsyncClient)
    source = ThreatFeedSource(
        name="MISP",
        url="https://192.168.1.20",
        source_type="misp",
        api_key="secret",
        misp_verify_ssl=False,
    )

    result = await _fetch_misp_feed(source)

    assert "203.0.113.10/32" in result
    assert "198.51.100.0/24" in result
    assert len(posts) == 2
    assert posts[0]["url"] == "https://192.168.1.20/attributes/restSearch"
    assert posts[0]["headers"]["Authorization"] == "secret"
    assert posts[0]["json"]["page"] == 1
    assert posts[1]["json"]["page"] == 2


@pytest.mark.asyncio
async def test_readback_action_mismatch_records_pending_error(monkeypatch) -> None:
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    try:
        async with engine.begin() as connection:
            await connection.run_sync(Base.metadata.create_all)
        session_factory = async_sessionmaker(engine, expire_on_commit=False)
        monkeypatch.setattr(threat_feed_collector, "async_session_factory", session_factory)
        monkeypatch.setattr(threat_feed_collector, "_zone_policy_available", None)

        async def fake_record_rule(
            ruleset: str,
            idx: int,
            direction: str,
            group_id: str | None,
            rule_id: str | None,
            payload_hash: str,
        ) -> None:
            return None

        monkeypatch.setattr(threat_feed_collector, "_record_rule", fake_record_rule)

        group_payload, rule_payload = _rule_payloads(
            "WAN_IN",
            0,
            ["203.0.113.10/32"],
            action="drop",
        )
        async with session_factory() as session:
            pending = ThreatFeedPendingRule(
                ruleset="WAN_IN",
                chunk_index=0,
                direction="inbound",
                action="create",
                group_name=group_payload["name"],
                rule_name=rule_payload["name"],
                entry_count=1,
                payload_hash="payload-hash",
                payload_json=threat_feed_collector._json(
                    {
                        "group": group_payload,
                        "rule": rule_payload,
                        "chunk": ["203.0.113.10/32"],
                    }
                ),
            )
            session.add(pending)
            await session.commit()
            pending_id = pending.id

        calls = {"rules": 0}

        async def fake_zone_policy_api_available() -> bool:
            return False

        async def fake_get_firewall_groups() -> list[dict]:
            return []

        async def fake_create_firewall_group(payload: dict) -> dict:
            return {"_id": "group-1", **payload}

        async def fake_get_firewall_rules() -> list[dict]:
            calls["rules"] += 1
            if calls["rules"] < 3:
                return []
            return [{"_id": "rule-1", "name": rule_payload["name"], "action": "deny"}]

        async def fake_create_firewall_rule(payload: dict) -> dict:
            return {"_id": "rule-1", **payload}

        monkeypatch.setattr(
            threat_feed_collector.unifi_client,
            "zone_policy_api_available",
            fake_zone_policy_api_available,
        )
        monkeypatch.setattr(
            threat_feed_collector.unifi_client,
            "get_firewall_groups",
            fake_get_firewall_groups,
        )
        monkeypatch.setattr(
            threat_feed_collector.unifi_client,
            "create_firewall_group",
            fake_create_firewall_group,
        )
        monkeypatch.setattr(
            threat_feed_collector.unifi_client,
            "get_firewall_rules",
            fake_get_firewall_rules,
        )
        monkeypatch.setattr(
            threat_feed_collector.unifi_client,
            "create_firewall_rule",
            fake_create_firewall_rule,
        )

        result = await _do_apply_pending_rule(pending_id)

        assert result.status == "failed"
        assert result.error is not None
        assert "Console stored action 'deny', expected 'drop'" in result.error
    finally:
        await engine.dispose()


@pytest.mark.asyncio
async def test_classic_update_verifies_existing_rule_without_updating_rule(monkeypatch) -> None:
    group_payload, rule_payload = _rule_payloads(
        "WAN_IN",
        1,
        ["203.0.113.10/32"],
        action="drop",
    )
    calls = {"group_updates": 0, "rule_updates": 0}

    async def fake_ensure_zone_policy_probed() -> bool:
        return False

    async def fake_update_firewall_group(group_id: str, payload: dict) -> dict:
        calls["group_updates"] += 1
        return {"_id": group_id, **payload}

    async def fake_update_firewall_rule(rule_id: str, payload: dict) -> dict:
        calls["rule_updates"] += 1
        raise AssertionError("classic update must not PUT the firewall rule")

    async def fake_get_firewall_rules() -> list[dict]:
        return [{"_id": "rule-2", "name": rule_payload["name"], "action": "drop"}]

    async def fake_record_rule(
        ruleset: str,
        idx: int,
        direction: str,
        group_id: str | None,
        rule_id: str | None,
        payload_hash: str,
    ) -> None:
        return None

    monkeypatch.setattr(
        threat_feed_collector,
        "_ensure_zone_policy_probed",
        fake_ensure_zone_policy_probed,
    )
    monkeypatch.setattr(
        threat_feed_collector.unifi_client,
        "update_firewall_group",
        fake_update_firewall_group,
    )
    monkeypatch.setattr(
        threat_feed_collector.unifi_client,
        "update_firewall_rule",
        fake_update_firewall_rule,
    )
    monkeypatch.setattr(
        threat_feed_collector.unifi_client,
        "get_firewall_rules",
        fake_get_firewall_rules,
    )
    monkeypatch.setattr(threat_feed_collector, "_record_rule", fake_record_rule)

    verify_error = await threat_feed_collector._apply_change(
        ruleset="WAN_IN",
        idx=1,
        direction="inbound",
        action="update",
        payload={
            "group": group_payload,
            "rule": rule_payload,
            "chunk": ["203.0.113.10/32"],
        },
        existing=ThreatFeedRule(
            ruleset="WAN_IN",
            chunk_index=1,
            direction="inbound",
            group_unifi_id="group-2",
            rule_unifi_id="rule-2",
            payload_hash="old-hash",
        ),
        group_unifi_id="group-2",
        rule_unifi_id="rule-2",
        payload_hash="payload-hash",
    )

    assert verify_error is None
    assert calls == {"group_updates": 1, "rule_updates": 0}
