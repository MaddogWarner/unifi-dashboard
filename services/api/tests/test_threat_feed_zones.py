import pytest

from app.collectors import threat_feed_collector
from app.collectors.threat_feed_collector import (
    _fetch_misp_feed,
    _normalise_target_zones,
    validate_outbound_url,
)
from app.models.threatfeed import ThreatFeedSource


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
