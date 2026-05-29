import json
import re
from dataclasses import dataclass
from datetime import datetime
from typing import Literal

from app.models.firewall import FirewallPolicy, FirewallPortForward, FirewallRule
from app.models.network import IdsConfig, Network
from app.models.scan import ScanResult


@dataclass
class AssessmentEvidence:
    type: str
    target_ip: str | None = None
    port: int | None = None
    protocol: str | None = None
    service: str | None = None
    reason: str | None = None
    source: str | None = None
    matched_name: str | None = None
    scan_id: int | None = None
    observed_at: datetime | None = None


@dataclass
class CheckResult:
    check_id: str
    label: str
    status: Literal["pass", "warn", "fail"]
    detail: str
    recommendation: str
    evidence: list[AssessmentEvidence] | None = None


def _result(
    check_id: str,
    label: str,
    status: Literal["pass", "warn", "fail"],
    detail: str,
    recommendation: str,
    evidence: list[AssessmentEvidence] | None = None,
) -> CheckResult:
    return CheckResult(check_id, label, status, detail, recommendation, evidence)


async def run_checks(
    policies: list[FirewallPolicy],
    rules: list[FirewallRule],
    port_forwards: list[FirewallPortForward],
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
        check_dmz_zone(networks, last_scan, policies, rules, port_forwards),
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


def _open_ports_from_scan(last_scan: ScanResult | None) -> list[AssessmentEvidence]:
    if not last_scan or last_scan.status != "done" or not last_scan.result_json:
        return []
    if last_scan and last_scan.result_json:
        try:
            payload = json.loads(last_scan.result_json)
        except json.JSONDecodeError:
            return []
    else:
        return []
    target_ip = payload.get("host") or last_scan.target_ip
    evidence = []
    for port in payload.get("ports", []):
        if port.get("state") != "open":
            continue
        try:
            port_number = int(port.get("port")) if port.get("port") else None
        except (TypeError, ValueError):
            port_number = None
        evidence.append(
            AssessmentEvidence(
                type="open_port",
                target_ip=target_ip,
                port=port_number,
                protocol=port.get("protocol"),
                service=port.get("service") or None,
                reason=port.get("reason") or None,
                source="latest_scan",
                matched_name=f"Scan #{last_scan.id}",
                scan_id=last_scan.id,
                observed_at=last_scan.completed_at or last_scan.created_at,
            )
        )
    return evidence


def _port_matches(value: str | None, port: int | None) -> bool:
    if port is None or not value:
        return False
    for part in str(value).split(","):
        token = part.strip()
        if not token:
            continue
        if "-" in token:
            start, _, end = token.partition("-")
            if start.isdigit() and end.isdigit() and int(start) <= port <= int(end):
                return True
        elif token.isdigit() and int(token) == port:
            return True
    return False


def _protocol_matches(rule_protocol: str | None, protocol: str | None) -> bool:
    if not rule_protocol or not protocol:
        return True
    return rule_protocol.lower() in {"all", protocol.lower()}


def _address_matches(value: str | None, target_ip: str | None) -> bool:
    if not value or value.lower() in {"any", "0.0.0.0/0"}:
        return True
    return target_ip is not None and target_ip in value


def _correlate_wan_exposure(
    open_ports: list[AssessmentEvidence],
    policies: list[FirewallPolicy],
    rules: list[FirewallRule],
    port_forwards: list[FirewallPortForward],
) -> list[AssessmentEvidence]:
    evidence: list[AssessmentEvidence] = []
    for open_port in open_ports:
        for forward in port_forwards:
            if not forward.enabled or forward.fwd_ip != open_port.target_ip:
                continue
            if not _protocol_matches(forward.protocol, open_port.protocol):
                continue
            if not (
                _port_matches(forward.fwd_port, open_port.port)
                or _port_matches(forward.dst_port, open_port.port)
            ):
                continue
            evidence.append(
                AssessmentEvidence(
                    type="wan_port_forward",
                    target_ip=open_port.target_ip,
                    port=open_port.port,
                    protocol=open_port.protocol,
                    service=open_port.service,
                    reason=open_port.reason,
                    source="unifi_port_forward",
                    matched_name=forward.name,
                    scan_id=open_port.scan_id,
                    observed_at=forward.synced_at,
                )
            )
        for rule in rules:
            if rule.action.upper() not in {"ALLOW", "ACCEPT"}:
                continue
            if not (rule.ruleset or "").upper().startswith("WAN"):
                continue
            if not _address_matches(rule.dst_address, open_port.target_ip):
                continue
            if rule.dst_port and not _port_matches(rule.dst_port, open_port.port):
                continue
            if not _protocol_matches(rule.protocol, open_port.protocol):
                continue
            evidence.append(
                AssessmentEvidence(
                    type="wan_firewall_rule",
                    target_ip=open_port.target_ip,
                    port=open_port.port,
                    protocol=open_port.protocol,
                    service=open_port.service,
                    reason=open_port.reason,
                    source="unifi_firewall_rule",
                    matched_name=rule.name,
                    scan_id=open_port.scan_id,
                    observed_at=rule.synced_at,
                )
            )
        for policy in policies:
            if policy.action.upper() not in {"ALLOW", "ACCEPT"}:
                continue
            if (policy.src_zone or "").lower() not in {"external", "wan"}:
                continue
            if (policy.dst_zone or "").lower() not in {"internal", "lan"}:
                continue
            evidence.append(
                AssessmentEvidence(
                    type="wan_zone_policy",
                    target_ip=open_port.target_ip,
                    port=open_port.port,
                    protocol=open_port.protocol,
                    service=open_port.service,
                    reason=open_port.reason,
                    source="unifi_zone_policy",
                    matched_name=policy.name,
                    scan_id=open_port.scan_id,
                    observed_at=policy.synced_at,
                )
            )
    return evidence


def check_dmz_zone(
    networks: list[Network],
    last_scan: ScanResult | None,
    policies: list[FirewallPolicy],
    rules: list[FirewallRule],
    port_forwards: list[FirewallPortForward],
) -> CheckResult:
    open_ports = _open_ports_from_scan(last_scan)
    wan_evidence = _correlate_wan_exposure(open_ports, policies, rules, port_forwards)
    evidence = [*wan_evidence, *open_ports]
    has_dmz = any((network.zone or "").lower() == "dmz" for network in networks)
    has_open_ports = bool(open_ports)
    status: Literal["pass", "warn", "fail"] = "warn" if has_open_ports and not has_dmz else "pass"
    if status == "warn":
        summary = ", ".join(
            f"{item.target_ip}:{item.port}/{item.protocol or 'tcp'}"
            + (f" ({item.service})" if item.service else "")
            for item in open_ports[:5]
        )
        if wan_evidence:
            detail = f"Likely WAN-exposed services found without a DMZ zone: {summary}."
        else:
            detail = f"Open internal services found without a DMZ zone: {summary}."
    else:
        detail = "No DMZ gap detected from latest scan."
    return _result(
        "check_dmz_zone",
        "DMZ for exposed services",
        status,
        detail,
        "Place exposed internal services in a segmented DMZ zone.",
        evidence[:20],
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
