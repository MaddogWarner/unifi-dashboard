import os
from typing import Any
from urllib.parse import urlencode

import httpx
from mcp.server.fastmcp import FastMCP

API = os.getenv("API_BASE_URL", "http://api:8000")
mcp = FastMCP("UniFi Security Dashboard")


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


if __name__ == "__main__":
    mcp.run(transport="streamable-http", host="0.0.0.0", port=8001)
