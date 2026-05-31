import os
from secrets import compare_digest
from typing import Any
from urllib.parse import urlencode

import httpx
from mcp.server.auth.provider import AccessToken, TokenVerifier
from mcp.server.auth.settings import AuthSettings
from mcp.server.fastmcp import FastMCP
from pydantic import AnyHttpUrl

API = os.getenv("API_BASE_URL", "http://api:8000")
MCP_AUTH_TOKEN = os.getenv("MCP_AUTH_TOKEN", "").strip()
MCP_AUTH_DISABLED = os.getenv("MCP_AUTH_DISABLED", "false").lower() == "true"
MCP_RESOURCE_SERVER_URL = os.getenv("MCP_RESOURCE_SERVER_URL", "http://localhost:8001")


class StaticTokenVerifier(TokenVerifier):
    def __init__(self, expected_token: str):
        self.expected_token = expected_token

    async def verify_token(self, token: str) -> AccessToken | None:
        if not compare_digest(token, self.expected_token):
            return None
        return AccessToken(
            token=token,
            client_id="unifi-dashboard-mcp",
            scopes=["mcp:tools"],
        )


def _create_mcp() -> FastMCP:
    if MCP_AUTH_DISABLED:
        return FastMCP("UniFi Security Dashboard", host="0.0.0.0", port=8001)

    if not MCP_AUTH_TOKEN or MCP_AUTH_TOKEN == "change-this-long-random-token":
        raise RuntimeError(
            "MCP_AUTH_TOKEN must be set to a long random value, "
            "or set MCP_AUTH_DISABLED=true for local development only."
        )

    return FastMCP(
        "UniFi Security Dashboard",
        host="0.0.0.0",
        port=8001,
        token_verifier=StaticTokenVerifier(MCP_AUTH_TOKEN),
        auth=AuthSettings(
            issuer_url=AnyHttpUrl(MCP_RESOURCE_SERVER_URL),
            resource_server_url=AnyHttpUrl(MCP_RESOURCE_SERVER_URL),
            required_scopes=["mcp:tools"],
        ),
    )


mcp = _create_mcp()


def _get(path: str) -> Any:
    response = httpx.get(f"{API}/api/v1{path}", timeout=15)
    response.raise_for_status()
    return response.json()


@mcp.tool()
def get_firewall_policies() -> list:
    """List all zone-based firewall policies with hit counts."""
    return _get("/firewall/policies")


@mcp.tool()
def get_firewall_logs(src_ip: str = "", rule_name: str = "", limit: int = 50) -> list:
    """Query recent firewall events filtered by source IP, rule name, or limit."""
    params = "?" + urlencode(
        {
            key: value
            for key, value in {
                "limit": limit,
                "src_ip": src_ip,
                "rule_name": rule_name,
            }.items()
            if value not in ("", None)
        }
    )
    return _get(f"/firewall/logs{params}")


@mcp.tool()
def get_threats(limit: int = 50) -> list:
    """List recent IDS/IPS threat events."""
    return _get(f"/threats/events?limit={limit}")


@mcp.tool()
def get_ids_status() -> dict:
    """Get IDS/IPS enabled state and configuration gaps."""
    return _get("/threats/ids-status")


@mcp.tool()
def get_vlans() -> list:
    """List VLANs and networks with zone assignments."""
    return _get("/networks/")


@mcp.tool()
def get_assessment() -> dict:
    """Run and return the full scored security assessment."""
    return _get("/assessment/")


@mcp.tool()
def get_policy_conflicts() -> list:
    """List detected policy conflicts."""
    return _get("/assessment/conflicts")


@mcp.tool()
def get_drift_report() -> dict:
    """Show the latest policy drift event and change set."""
    return _get("/drift/latest-change")


@mcp.tool()
def run_port_scan(target_ip: str, ports: str = "22,80,443,8080", scan_type: str = "connect") -> dict:
    """Trigger a port scan against an RFC1918 target and return a scan_id."""
    response = httpx.post(
        f"{API}/api/v1/scan/",
        json={"target": target_ip, "ports": ports, "scan_type": scan_type},
        timeout=15,
    )
    response.raise_for_status()
    return response.json()


@mcp.tool()
def get_scan_results(scan_id: int) -> dict:
    """Retrieve results of a previous scan by scan_id."""
    return _get(f"/scan/{scan_id}")


@mcp.tool()
def get_cve_alerts(severity: str = "", limit: int = 20) -> dict:
    """List unacknowledged HIGH/CRITICAL CVE alerts for connected UniFi devices."""
    params = {"limit": limit, "acknowledged": "false"}
    if severity:
        params["severity"] = severity
    return _get(f"/cve/alerts?{urlencode(params)}")


@mcp.tool()
def get_cve_devices() -> list:
    """List UniFi device inventory with firmware versions and matched CVE counts."""
    return _get("/cve/devices")


@mcp.tool()
def get_threatfeed_status() -> dict:
    """Get threat feed status, apply mode, blocked IP count, and pending approvals."""
    return _get("/threatfeed/status")


@mcp.tool()
def get_threatfeed_entries(limit: int = 50, cidr_search: str = "") -> dict:
    """Query the blocked IP/CIDR list from active threat feeds."""
    params = {"limit": limit}
    if cidr_search:
        params["cidr"] = cidr_search
    return _get(f"/threatfeed/entries?{urlencode(params)}")


@mcp.tool()
def get_threatfeed_pending_rules() -> list:
    """List threat feed rule changes waiting for manual approval."""
    return _get("/threatfeed/pending-rules")


if __name__ == "__main__":
    mcp.run(transport="streamable-http")
