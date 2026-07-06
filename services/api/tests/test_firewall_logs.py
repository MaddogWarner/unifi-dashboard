import asyncio
from datetime import UTC, datetime, timedelta

from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from app.database import Base
from app.models.firewall import FirewallLog
from app.routers.firewall import list_logs

BASE_TIME = datetime(2026, 7, 6, 2, 0, tzinfo=UTC)


def _rows() -> list[FirewallLog]:
    return [
        FirewallLog(
            timestamp=BASE_TIME - timedelta(minutes=30),
            rule_name="Allow DNS",
            action="accept",
            src_ip="192.168.10.10",
            dst_ip="192.168.1.53",
            src_port=53120,
            dst_port=53,
            protocol="UDP",
            interface="br10",
            direction="IN",
            matched_policy_id=None,
            raw_line="allow dns raw",
        ),
        FirewallLog(
            timestamp=BASE_TIME - timedelta(minutes=20),
            rule_name="Block Guest",
            action="drop",
            src_ip="192.168.20.15",
            dst_ip="192.168.1.10",
            src_port=49152,
            dst_port=443,
            protocol="TCP",
            interface="br20",
            direction="IN",
            matched_policy_id=None,
            raw_line="block guest raw",
        ),
        FirewallLog(
            timestamp=BASE_TIME - timedelta(minutes=10),
            rule_name="Block Guest",
            action="drop",
            src_ip="192.168.20.15",
            dst_ip="192.168.1.11",
            src_port=49153,
            dst_port=22,
            protocol="TCP",
            interface="br20",
            direction="IN",
            matched_policy_id=None,
            raw_line="block guest ssh raw",
        ),
        FirewallLog(
            timestamp=BASE_TIME,
            rule_name="Reject IoT",
            action="reject",
            src_ip="192.168.30.25",
            dst_ip="192.168.1.10",
            src_port=50000,
            dst_port=445,
            protocol="TCP",
            interface="br30",
            direction="IN",
            matched_policy_id=None,
            raw_line="reject iot raw",
        ),
    ]


async def _query_logs(**params: object) -> list[FirewallLog]:
    route_params = {"limit": 100, **params}
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    try:
        async with engine.begin() as connection:
            await connection.run_sync(Base.metadata.create_all)
        session_factory = async_sessionmaker(engine, expire_on_commit=False)
        async with session_factory() as session:
            session.add_all(_rows())
            await session.commit()
            return await list_logs(db=session, **route_params)
    finally:
        await engine.dispose()


def _logs(**params: object) -> list[FirewallLog]:
    return asyncio.run(_query_logs(**params))


def test_list_logs_returns_all_rows_newest_first() -> None:
    logs = _logs()

    assert [log.rule_name for log in logs] == [
        "Reject IoT",
        "Block Guest",
        "Block Guest",
        "Allow DNS",
    ]


def test_list_logs_action_filter_is_case_insensitive() -> None:
    logs = _logs(action="DROP")

    assert [log.dst_ip for log in logs] == ["192.168.1.11", "192.168.1.10"]
    assert {log.action for log in logs} == {"drop"}


def test_list_logs_combines_src_ip_and_action_filters() -> None:
    logs = _logs(src_ip="192.168.20.15", action="drop")

    assert len(logs) == 2
    assert {log.rule_name for log in logs} == {"Block Guest"}


def test_list_logs_filters_by_dst_ip() -> None:
    logs = _logs(dst_ip="192.168.1.10")

    assert [log.rule_name for log in logs] == ["Reject IoT", "Block Guest"]


def test_list_logs_applies_skip_and_limit_paging() -> None:
    logs = _logs(skip=1, limit=2)

    assert [log.rule_name for log in logs] == ["Block Guest", "Block Guest"]
    assert [log.dst_ip for log in logs] == ["192.168.1.11", "192.168.1.10"]
