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
_FIELD_RE = re.compile(
    r"(?:.*IN=(?P<iface>[^\s]*))?.*SRC=(?P<src>[^\s]+).*DST=(?P<dst>[^\s]+).*"
    r"PROTO=(?P<proto>[^\s]+)(?:.*SPT=(?P<spt>\d+))?(?:.*DPT=(?P<dpt>\d+))?",
    re.DOTALL,
)


class SyslogProtocol(asyncio.DatagramProtocol):
    def __init__(self) -> None:
        self.received_count = 0
        self.unparsed_count = 0
        self.parsed_count = 0

    def datagram_received(self, data: bytes, addr: tuple) -> None:
        self.received_count += 1
        line = data.decode("utf-8", errors="replace").strip()
        if self.received_count == 1:
            log.info("Received first syslog datagram from %s:%s", addr[0], addr[1])
        asyncio.create_task(self._process(line))

    async def _process(self, line: str) -> None:
        rule_match = _RULE_RE.search(line)
        if not rule_match:
            self._log_unparsed("rule marker", line)
            return
        field_match = _FIELD_RE.search(line)
        if not field_match:
            self._log_unparsed("IP/port fields", line)
            return
        rule_name, action = rule_match.group(1), rule_match.group(2)
        async with async_session_factory() as session:
            async with session.begin():
                policy_id = await session.scalar(
                    select(FirewallPolicy.id).where(FirewallPolicy.name == rule_name)
                )
                session.add(
                    FirewallLog(
                        timestamp=datetime.now(UTC),
                        rule_name=rule_name,
                        action=action,
                        src_ip=field_match.group("src"),
                        dst_ip=field_match.group("dst"),
                        src_port=int(field_match.group("spt")) if field_match.group("spt") else None,
                        dst_port=int(field_match.group("dpt")) if field_match.group("dpt") else None,
                        protocol=field_match.group("proto"),
                        interface=field_match.group("iface"),
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
        if self.unparsed_count == 1:
            log.warning(
                "Ignoring non-firewall syslog traffic (missing %s); "
                "this is normal if the router forwards all syslog categories. Sample: %s",
                reason,
                line[:300],
            )
        elif self.unparsed_count % 10000 == 0:
            log.debug(
                "Ignored %s unparsed syslog datagram(s) so far (missing %s)",
                self.unparsed_count,
                reason,
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
