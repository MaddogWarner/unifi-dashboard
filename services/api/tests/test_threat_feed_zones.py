from app.collectors.threat_feed_collector import _normalise_target_zones


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
