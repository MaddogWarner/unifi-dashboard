import logging
import re
import time
from unittest.mock import AsyncMock, patch

import pytest

from app.collectors.syslog import _RULE_RE, MAX_DATAGRAM_BYTES, SyslogProtocol, _parse_fields

# Only run the old implementation on short, benign compatibility fixtures.
_OLD_FIELD_RE = re.compile(
    r"(?:.*IN=(?P<iface>[^\s]*))?.*SRC=(?P<src>[^\s]+).*DST=(?P<dst>[^\s]+).*"
    r"PROTO=(?P<proto>[^\s]+)(?:.*SPT=(?P<spt>\d+))?(?:.*DPT=(?P<dpt>\d+))?",
    re.DOTALL,
)
FIXTURES = [
    "allow dns raw",
    "block guest raw",
    "block guest ssh raw",
    "reject iot raw",
    "test",
    "kernel: [WAN_LOCAL-default-D]IN=eth4 OUT= SRC=1.2.3.4 DST=192.168.1.1 LEN=60 PROTO=TCP SPT=54321 DPT=22",
    "<4>Oct 10 12:00:00 gateway kernel: [RULE-A] IN=br0 OUT=eth4 "
    "MAC=00:11:22:33:44:55 SRC=192.168.1.10 DST=198.51.100.10 LEN=60 "
    "TOS=0x00 TTL=64 PROTO=TCP SPT=54321 DPT=443 SYN",
    "<4>Oct 10 12:00:00 gateway kernel: [RULE-A] IN= OUT=br0 "
    "MAC=00:11:22:33:44:55 SRC=198.51.100.10 DST=192.168.1.10 PROTO=ICMP TYPE=8 CODE=0",
    "[RULE-R] SRC=192.0.2.1 DST=192.0.2.2 PROTO=UDP SPT=53 DPT=123",
]


@pytest.mark.parametrize("line", FIXTURES)
def test_fixture_equivalence(line: str) -> None:
    old = _OLD_FIELD_RE.search(line)
    assert _parse_fields(line) == (old.groupdict() if old else None)


@pytest.mark.parametrize("fragment", ["SRC=a DST=b ", "IN= ", "=", "x", "[", "[a-"])
def test_hostile_inputs_are_bounded(fragment: str) -> None:
    line = (fragment * MAX_DATAGRAM_BYTES)[:MAX_DATAGRAM_BYTES]
    start = time.perf_counter()
    assert _RULE_RE.search(line) is None
    assert _parse_fields(line) is None
    assert time.perf_counter() - start < 0.1


@pytest.mark.parametrize("value", ["99999", "12a", "-1", "", "9" * 4096])
@pytest.mark.parametrize("key", ["SPT", "DPT"])
def test_invalid_ports_are_absent(key: str, value: str) -> None:
    fields = _parse_fields(f"SRC=a DST=b PROTO=TCP {key}={value}")
    assert fields is not None
    assert fields["spt"] is None and fields["dpt"] is None


@pytest.mark.parametrize(
    "value, expected",
    [
        ("0", "0"),
        ("65535", "65535"),
        ("00053", "53"),
        ("0" * 4000 + "53", "53"),
    ],
)
def test_valid_ports(value: str, expected: str) -> None:
    fields = _parse_fields(f"SRC=a DST=b PROTO=TCP SPT={value} DPT={value}")
    assert fields is not None
    assert fields["spt"] == fields["dpt"] == expected


def test_duplicate_keys_last_wins() -> None:
    assert _parse_fields("IN=a SRC=a DST=b PROTO=TCP SPT=1 DPT=2 IN= SRC=c DST=d PROTO=UDP SPT=12a DPT=53") == {
        "iface": "",
        "src": "c",
        "dst": "d",
        "proto": "UDP",
        "spt": None,
        "dpt": "53",
    }


@pytest.mark.parametrize("line", ["SRC=a DST=b", "SRC= DST=b PROTO=TCP", "SRC=a DST= PROTO=TCP", "SRC=a DST=b PROTO="])
def test_required_fields(line: str) -> None:
    assert _parse_fields(line) is None


def test_oversize_dropped_before_decoding(caplog: pytest.LogCaptureFixture) -> None:
    class Undecodable(bytes):
        def decode(self, *args: object, **kwargs: object) -> str:
            pytest.fail("oversize datagrams must not be decoded")

    protocol = SyslogProtocol()
    with patch("app.collectors.syslog.asyncio.create_task") as create_task:
        with caplog.at_level(logging.WARNING):
            protocol.datagram_received(Undecodable(b"secret-payload".ljust(4097, b"x")), ("127.0.0.1", 123))
    assert protocol.received_count == protocol.unparsed_count == 1
    assert protocol.parsed_count == 0
    create_task.assert_not_called()
    assert "oversize" in caplog.text and "4097 bytes" in caplog.text
    assert "secret-payload" not in caplog.text


@pytest.mark.asyncio
async def test_cap_is_in_bytes_and_boundary_is_accepted() -> None:
    protocol = SyslogProtocol()
    with patch.object(protocol, "_process", new_callable=AsyncMock) as process:
        with patch("app.collectors.syslog.asyncio.create_task") as create_task:
            protocol.datagram_received(b"x" * 4096, ("127.0.0.1", 123))
            await create_task.call_args.args[0]
        process.assert_awaited_once_with("x" * 4096)
    protocol.datagram_received(("é" * 2049).encode(), ("127.0.0.1", 123))
    assert protocol.unparsed_count == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("fragment", ["SRC=a DST=b ", "IN= ", "=", "x", "[", "[a-"])
async def test_hostile_process_path(fragment: str) -> None:
    prefix = "[RULE-A] "
    line = prefix + (fragment * MAX_DATAGRAM_BYTES)[: MAX_DATAGRAM_BYTES - len(prefix)]
    protocol = SyslogProtocol()
    start = time.perf_counter()
    with patch("app.collectors.syslog.async_session_factory") as factory:
        await protocol._process(line)
    assert time.perf_counter() - start < 0.1
    factory.assert_not_called()
    assert protocol.unparsed_count == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("line", FIXTURES[5:])
async def test_process_preserves_stored_fields(line: str) -> None:
    from unittest.mock import MagicMock

    session = MagicMock()
    session.scalar = AsyncMock(return_value=None)
    session.begin.return_value.__aenter__ = AsyncMock()
    session.begin.return_value.__aexit__ = AsyncMock(return_value=False)
    factory = MagicMock()
    factory.return_value.__aenter__ = AsyncMock(return_value=session)
    factory.return_value.__aexit__ = AsyncMock(return_value=False)
    protocol = SyslogProtocol()
    with patch("app.collectors.syslog.async_session_factory", factory):
        await protocol._process(line)
    event = session.add.call_args.args[0]
    old = _OLD_FIELD_RE.search(line)
    assert old is not None
    assert event.interface == old.group("iface")
    assert event.protocol == old.group("proto")
    assert event.src_ip == old.group("src")
    assert event.dst_ip == old.group("dst")
    assert event.src_port == (int(old.group("spt")) if old.group("spt") else None)
    assert event.dst_port == (int(old.group("dpt")) if old.group("dpt") else None)
    assert event.raw_line == line
    assert protocol.parsed_count == 1
