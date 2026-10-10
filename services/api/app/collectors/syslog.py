import asyncio
import logging
import re
from datetime import UTC, datetime

from sqlalchemy import select

from app.config import settings
from app.database import async_session_factory
from app.models.firewall import FirewallLog, FirewallPolicy

log = logging.getLogger(__name__)

_RULE_RE = re.compile(r"\[([A-Za-z0-9_\-]+?)-(A|D|R)\]")
MAX_DATAGRAM_BYTES = 4096


def _parse_fields(line: str) -> dict[str, str | None] | None:
    # One pass over whitespace-delimited fields; duplicate keys consistently use
    # the last value. UniFi can attach IN= directly to the closing rule marker.
    fields: dict[str, str] = {}
    for token in line.split():
        key, separator, value = token.partition("=")
        key = key.rpartition("]")[2]
        if separator and key in {"IN", "SRC", "DST", "PROTO", "SPT", "DPT"}:
            fields[key] = value
    if not all(fields.get(key) for key in ("SRC", "DST", "PROTO")):
        return None
    result: dict[str, str | None] = {
        "iface": fields.get("IN"),
        "src": fields["SRC"],
        "dst": fields["DST"],
        "proto": fields["PROTO"],
    }
    for key, name in (("SPT", "spt"), ("DPT", "dpt")):
        value = fields.get(key, "")
        # Strip leading zeroes and bound the digit count before integer conversion.
        digits = value.lstrip("0") or "0"
        result[name] = digits if value.isdecimal() and len(digits) <= 5 and int(digits) <= 65535 else None
    return result


class SyslogProtocol(asyncio.DatagramProtocol):
    def __init__(self) -> None:
        self.received_count = 0
        self.unparsed_count = 0
        self.parsed_count = 0

    def datagram_received(self, data: bytes, addr: tuple) -> None:
        self.received_count += 1
        if len(data) > MAX_DATAGRAM_BYTES:
            self._log_unparsed("oversize", f"{len(data)} bytes")
            return
        line = data.decode("utf-8", errors="replace").strip()
        if self.received_count == 1:
            log.info("Received first syslog datagram from %s:%s", addr[0], addr[1])
        asyncio.create_task(self._process(line))

    async def _process(self, line: str) -> None:
        rule_match = _RULE_RE.search(line)
        if not rule_match:
            self._log_unparsed("rule marker", line)
            return
        fields = _parse_fields(line)
        if fields is None:
            self._log_unparsed("IP/port fields", line)
            return
        src_port, dst_port = fields["spt"], fields["dpt"]
        rule_name, action = rule_match.group(1), rule_match.group(2)
        async with async_session_factory() as session:
            async with session.begin():
                policy_id = await session.scalar(select(FirewallPolicy.id).where(FirewallPolicy.name == rule_name))
                session.add(
                    FirewallLog(
                        timestamp=datetime.now(UTC),
                        rule_name=rule_name,
                        action=action,
                        src_ip=fields["src"],
                        dst_ip=fields["dst"],
                        src_port=int(src_port) if src_port else None,
                        dst_port=int(dst_port) if dst_port else None,
                        protocol=fields["proto"],
                        interface=fields["iface"],
                        direction=None,
                        matched_policy_id=policy_id,
                        raw_line=line,
                    )
                )
        self.parsed_count += 1
        if self.parsed_count == 1:
            log.info("Parsed first firewall syslog event for rule '%s'", rule_name)

    def _log_unparsed(self, reason: str, line: str) -> None:
        self.unparsed_count += 1
        if self.unparsed_count <= 5:
            log.warning(
                "Ignoring non-firewall syslog datagram #%s (missing %s): %s",
                self.unparsed_count,
                reason,
                line,
            )
        elif self.unparsed_count % 1000 == 0:
            log.warning(
                "Ignored %s non-firewall syslog datagrams so far (missing %s); latest: %s",
                self.unparsed_count,
                reason,
                line,
            )


async def start_syslog_server() -> None:
    loop = asyncio.get_running_loop()
    transport, _ = await loop.create_datagram_endpoint(
        SyslogProtocol,
        local_addr=("0.0.0.0", settings.syslog_port),
    )
    log.info("Syslog receiver listening on UDP 0.0.0.0:%s", settings.syslog_port)
    try:
        await asyncio.get_running_loop().create_future()
    finally:
        transport.close()
