import asyncio
import ipaddress
import xml.etree.ElementTree as ET
from typing import Literal

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

app = FastAPI(title="UniFi Dashboard Scanner")

_RFC1918 = [
    ipaddress.IPv4Network("10.0.0.0/8"),
    ipaddress.IPv4Network("172.16.0.0/12"),
    ipaddress.IPv4Network("192.168.0.0/16"),
]


def _is_private(ip: str) -> bool:
    try:
        address = ipaddress.IPv4Address(ip)
        return any(address in network for network in _RFC1918)
    except ValueError:
        return False


class ScanRequest(BaseModel):
    target: str
    ports: str = Field(default="1-1024", max_length=256)
    scan_type: Literal["connect", "syn", "udp"] = "connect"


@app.get("/health")
async def health() -> dict:
    return {"status": "ok"}


@app.post("/scan")
async def scan(request: ScanRequest) -> dict:
    if not _is_private(request.target):
        raise HTTPException(400, "Only RFC1918 addresses may be scanned")

    flags = {"connect": "-sT", "syn": "-sS", "udp": "-sU"}[request.scan_type]
    proc = await asyncio.create_subprocess_exec(
        "nmap",
        "-oX",
        "-",
        flags,
        request.target,
        "-p",
        request.ports,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=120)
    if proc.returncode != 0:
        raise HTTPException(500, stderr.decode(errors="replace"))
    return {"host": request.target, "ports": _parse_nmap_xml(stdout.decode(errors="replace"))}


def _parse_nmap_xml(xml_str: str) -> list[dict]:
    root = ET.fromstring(xml_str)
    results = []
    for port in root.findall(".//port"):
        state_el = port.find("state")
        service_el = port.find("service")
        results.append(
            {
                "port": int(port.get("portid", 0)),
                "protocol": port.get("protocol", "tcp"),
                "state": state_el.get("state", "") if state_el is not None else "",
                "service": service_el.get("name", "") if service_el is not None else "",
                "reason": state_el.get("reason", "") if state_el is not None else "",
            }
        )
    return results
