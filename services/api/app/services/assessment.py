import json
import re
from dataclasses import dataclass
from typing import Literal

from app.models.firewall import FirewallPolicy, FirewallRule
from app.models.network import IdsConfig, Network
from app.models.scan import ScanResult


@dataclass
class CheckResult:
    check_id: str
    label: str
    status: Literal["pass", "warn", "fail"]
    detail: str
    recommendation: str


def _result(
    check_id: str,
    label: str,
    status: Literal["pass", "warn", "fail"],
    detail: str,
    recommendation: str,
) -> CheckResult:
    return CheckResult(check_id, label, status, detail, recommendation)


async def run_checks(
    policies: list[FirewallPolicy],
    rules: list[FirewallRule],
    networks: list[Network],
    ids_config: IdsConfig | None,
    last_scan: ScanResult | None,
) -> list[CheckResult]:
    checks = [
        check_ids_enabled(ids_config),
        check_ips_mode(ids_config),
        check_wan_to_internal_blocked(policies),
        check_guest_isolated(policies),
        check_zone_pairs_covered(policies, networks),
        check_no_permit_any_any(policies),
        check_management_vlan(networks),
        check_dmz_zone(networks, last_scan),
        check_block_policies_logged(policies),
        check_policy_names(policies),
    ]
    return checks


def check_ids_enabled(ids_config: IdsConfig | None) -> CheckResult:
    passed = bool(ids_config and ids_config.enabled)
    return _result(
        "check_ids_enabled",
        "IDS/IPS enabled",
        "pass" if passed else "fail",
        "IDS/IPS is enabled." if passed else "IDS/IPS is not enabled.",
        "Enable IDS/IPS on the UniFi console for threat visibility.",
    )


def check_ips_mode(ids_config: IdsConfig | None) -> CheckResult:
    mode = (ids_config.mode if ids_config else None) or "disabled"
    status: Literal["pass", "warn", "fail"] = "pass" if mode == "ips" else "warn"
    return _result(
        "check_ips_mode",
        "IPS prevention mode",
        status,
        f"Current mode is {mode}.",
        "Use IPS mode where appliance capacity and operational risk allow.",
    )


def check_wan_to_internal_blocked(policies: list[FirewallPolicy]) -> CheckResult:
    risky = [
        policy.name
        for policy in policies
        if (policy.src_zone or "").lower() in {"external", "wan"}
        and (policy.dst_zone or "").lower() in {"internal", "lan"}
        and policy.action.upper() == "ALLOW"
    ]
    return _result(
        "check_wan_to_internal_blocked",
        "WAN to internal blocked",
        "fail" if risky else "pass",
        f"Risky allow policies: {', '.join(risky)}" if risky else "No WAN to internal allow policies found.",
        "Remove or tightly scope WAN to internal allow policies.",
    )


def check_guest_isolated(policies: list[FirewallPolicy]) -> CheckResult:
    risky = [
        policy.name
        for policy in policies
        if (policy.src_zone or "").lower() in {"hotspot", "guest"}
        and (policy.dst_zone or "").lower() in {"internal", "lan"}
        and policy.action.upper() == "ALLOW"
    ]
    return _result(
        "check_guest_isolated",
        "Guest isolation",
        "fail" if risky else "pass",
        f"Guest/internal allow policies: {', '.join(risky)}" if risky else "Guest networks appear isolated from internal zones.",
        "Block Guest/Hotspot to Internal/LAN unless a documented exception exists.",
    )


def check_zone_pairs_covered(
    policies: list[FirewallPolicy], networks: list[Network]
) -> CheckResult:
    zones = {network.zone for network in networks if network.zone}
    covered = {(policy.src_zone, policy.dst_zone) for policy in policies}
    missing = [
        f"{src}->{dst}"
        for src in sorted(zones)
        for dst in sorted(zones)
        if src != dst and (src, dst) not in covered
    ]
    return _result(
        "check_zone_pairs_covered",
        "Zone pair coverage",
        "warn" if missing else "pass",
        f"Missing policy pairs: {', '.join(missing[:10])}" if missing else "All discovered zone pairs have policies.",
        "Add explicit policies for each zone pair to avoid relying on implicit defaults.",
    )


def check_no_permit_any_any(policies: list[FirewallPolicy]) -> CheckResult:
    risky = [
        policy.name
        for policy in policies
        if policy.action.upper() == "ALLOW"
        and policy.protocol is None
        and policy.src_zone is None
        and policy.dst_zone is None
    ]
    return _result(
        "check_no_permit_any_any",
        "No permit any-any",
        "fail" if risky else "pass",
        f"Permit any-any policies: {', '.join(risky)}" if risky else "No permit any-any zone policies found.",
        "Replace permit any-any rules with explicit source, destination, protocol, and port scopes.",
    )


def check_management_vlan(networks: list[Network]) -> CheckResult:
    found = any(
        (network.purpose or "").lower() == "management"
        or (network.zone or "").lower() == "gateway"
        for network in networks
    )
    return _result(
        "check_management_vlan",
        "Management network",
        "pass" if found else "warn",
        "Management network found." if found else "No management or gateway zone network found.",
        "Use a dedicated management VLAN or gateway zone for infrastructure administration.",
    )


def check_dmz_zone(networks: list[Network], last_scan: ScanResult | None) -> CheckResult:
    has_open_ports = False
    if last_scan and last_scan.result_json:
        try:
            payload = json.loads(last_scan.result_json)
            has_open_ports = any(port.get("state") == "open" for port in payload.get("ports", []))
        except json.JSONDecodeError:
            has_open_ports = False
    has_dmz = any((network.zone or "").lower() == "dmz" for network in networks)
    status: Literal["pass", "warn", "fail"] = "warn" if has_open_ports and not has_dmz else "pass"
    return _result(
        "check_dmz_zone",
        "DMZ for exposed services",
        status,
        "Open ports were found without a DMZ zone." if status == "warn" else "No DMZ gap detected from latest scan.",
        "Place exposed internal services in a segmented DMZ zone.",
    )


def check_block_policies_logged(policies: list[FirewallPolicy]) -> CheckResult:
    missing = []
    for policy in policies:
        if policy.action.upper() != "BLOCK":
            continue
        try:
            raw = json.loads(policy.raw_json)
        except json.JSONDecodeError:
            raw = {}
        if not (raw.get("logging") or raw.get("log") or raw.get("log_enabled")):
            missing.append(policy.name)
    return _result(
        "check_block_policies_logged",
        "Block policy logging",
        "warn" if missing else "pass",
        f"Block policies without logging: {', '.join(missing)}" if missing else "Block policies appear to have logging enabled.",
        "Enable logging for deny controls that support audit and detection use cases.",
    )


def check_policy_names(policies: list[FirewallPolicy]) -> CheckResult:
    generic = [policy.name for policy in policies if re.match(r"^Policy \d+$", policy.name)]
    return _result(
        "check_policy_names",
        "Policy naming",
        "warn" if generic else "pass",
        f"Generic policy names: {', '.join(generic)}" if generic else "Policy names are descriptive.",
        "Rename generic policies with source, destination, purpose, and ticket/change context.",
    )
