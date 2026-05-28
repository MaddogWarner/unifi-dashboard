from app.collectors.poller import normalise_ids_config


def test_notify_and_block_maps_to_ips_enabled() -> None:
    result = normalise_ids_config(
        {
            "intrusion_prevention_enabled": "On",
            "detection_mode": "Notify and Block",
            "selected_networks": ["Secured Network", "Smart Home Network"],
        }
    )

    assert result["enabled"] is True
    assert result["mode"] == "ips"


def test_notify_maps_to_ids_enabled() -> None:
    result = normalise_ids_config(
        {
            "threat_management_enabled": True,
            "detection_mode": "Notify",
        }
    )

    assert result["enabled"] is True
    assert result["mode"] == "ids"


def test_disabled_maps_to_inactive() -> None:
    result = normalise_ids_config(
        {
            "intrusion_prevention_enabled": "Off",
            "detection_mode": "Notify and Block",
        }
    )

    assert result["enabled"] is False
    assert result["mode"] is None


def test_selected_networks_are_secondary_enablement_evidence() -> None:
    result = normalise_ids_config({"selected_networks": ["Secured Network"]})

    assert result["enabled"] is True
    assert result["mode"] is None


def test_legacy_enabled_ips_payload_still_works() -> None:
    result = normalise_ids_config(
        {
            "enabled": True,
            "ips_enabled": True,
            "mode": "ips",
            "sensitivity": "medium",
            "categories": ["botnets"],
        }
    )

    assert result["enabled"] is True
    assert result["mode"] == "ips"
    assert result["sensitivity"] == "medium"
    assert result["categories"] == ["botnets"]


def test_camel_case_payload_fields_are_supported() -> None:
    result = normalise_ids_config(
        {
            "intrusionPreventionEnabled": True,
            "detectionMode": "notify-and-block",
        }
    )

    assert result["enabled"] is True
    assert result["mode"] == "ips"
