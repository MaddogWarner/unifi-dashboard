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
    def datagram_received(self, data: bytes, addr: tuple) -> None:
        line = data.decode("utf-8", errors="replace").strip()
        asyncio.create_task(self._process(line))

    async def _process(self, line: str) -> None:
        rule_match = _RULE_RE.search(line)
        if not rule_match:
            return
        field_match = _FIELD_RE.search(line)
        if not field_match:
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


async def start_syslog_server() -> None:
    loop = asyncio.get_running_loop()
    transport, _ = await loop.create_datagram_endpoint(
        SyslogProtocol,
        local_addr=("0.0.0.0", settings.syslog_port),
    )
    log.info("Syslog receiver listening on UDP :%s", settings.syslog_port)
    try:
        await asyncio.get_running_loop().create_future()
    finally:
        transport.close()
