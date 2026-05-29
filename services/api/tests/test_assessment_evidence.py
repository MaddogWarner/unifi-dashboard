import json
from datetime import UTC, datetime

from app.models.firewall import FirewallPortForward, FirewallRule
from app.models.scan import ScanResult
from app.services.assessment import check_dmz_zone


def _scan() -> ScanResult:
    now = datetime.now(UTC)
    return ScanResult(
        id=7,
        target_ip="192.168.1.20",
        scan_type="connect",
        ports_requested="22,443",
        status="done",
        result_json=json.dumps(
            {
                "host": "192.168.1.20",
                "ports": [
                    {
                        "port": 443,
                        "protocol": "tcp",
                        "state": "open",
                        "service": "https",
                        "reason": "syn-ack",
                    }
                ],
            }
        ),
        created_at=now,
        completed_at=now,
    )


def test_dmz_check_lists_open_port_evidence() -> None:
    result = check_dmz_zone([], _scan(), [], [], [])

    assert result.status == "warn"
    assert "192.168.1.20:443/tcp" in result.detail
    assert result.evidence is not None
    assert result.evidence[-1].type == "open_port"
    assert result.evidence[-1].service == "https"


def test_dmz_check_correlates_port_forward() -> None:
    now = datetime.now(UTC)
    forward = FirewallPortForward(
        unifi_id="pf-1",
        name="HTTPS to app",
        enabled=True,
        protocol="tcp",
        dst_port="443",
        fwd_port="443",
        fwd_ip="192.168.1.20",
        raw_json="{}",
        synced_at=now,
    )

    result = check_dmz_zone([], _scan(), [], [], [forward])

    assert result.evidence is not None
    assert result.evidence[0].type == "wan_port_forward"
    assert result.evidence[0].matched_name == "HTTPS to app"
    assert "Likely WAN-exposed services" in result.detail


def test_dmz_check_correlates_wan_rule() -> None:
    now = datetime.now(UTC)
    rule = FirewallRule(
        unifi_id="rule-1",
        name="Allow WAN HTTPS",
        action="ALLOW",
        ruleset="WAN_IN",
        rule_index=100,
        enabled=True,
        src_address=None,
        dst_address="192.168.1.20",
        protocol="tcp",
        dst_port="443",
        raw_json="{}",
        synced_at=now,
    )

    result = check_dmz_zone([], _scan(), [], [rule], [])

    assert result.evidence is not None
    assert result.evidence[0].type == "wan_firewall_rule"
    assert result.evidence[0].matched_name == "Allow WAN HTTPS"
