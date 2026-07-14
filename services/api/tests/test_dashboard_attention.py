import asyncio
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime, timedelta

from pytest import MonkeyPatch
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.database import Base
from app.models.assessment import AssessmentRun
from app.models.cve import CVEAlert
from app.models.firewall import FirewallLog
from app.models.threat import ThreatEvent
from app.routers.dashboard import attention

BASE_TIME = datetime.now(UTC)


def _set_connectivity(monkeypatch: MonkeyPatch, reachable: bool) -> None:
    async def fake_connectivity() -> bool:
        return reachable

    monkeypatch.setattr("app.routers.dashboard.check_connectivity", fake_connectivity)


async def _with_session(
    callback: Callable[[AsyncSession], Awaitable[None]],
) -> None:
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    try:
        async with engine.begin() as connection:
            await connection.run_sync(Base.metadata.create_all)
        session_factory = async_sessionmaker(engine, expire_on_commit=False)
        async with session_factory() as session:
            await callback(session)
    finally:
        await engine.dispose()


def _firewall_log(timestamp: datetime) -> FirewallLog:
    return FirewallLog(
        timestamp=timestamp,
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
    )


def _threat_event(timestamp: datetime) -> ThreatEvent:
    return ThreatEvent(
        timestamp=timestamp,
        signature_id="1:1000001",
        signature_name="Test signature",
        category="test",
        severity="medium",
        src_ip="192.168.20.15",
        dst_ip="192.168.1.10",
        action="allowed",
        raw_json="{}",
    )


def test_empty_db_reachable_returns_status_and_syslog_item(monkeypatch: MonkeyPatch) -> None:
    _set_connectivity(monkeypatch, True)

    async def scenario(session: AsyncSession) -> None:
        result = await attention(db=session)

        assert result.status.unifi_reachable is True
        assert result.status.last_policy_sync is None
        assert result.status.last_syslog_event is None
        assert result.status.threat_events_24h == 0
        assert result.status.assessment_score is not None
        assert any(item.title == "No firewall syslog events received" for item in result.items)
        assert not any(item.category == "connectivity" for item in result.items)
        assert not any(item.category == "conflict" for item in result.items)
        assert not any(item.category == "cve" for item in result.items)

    asyncio.run(_with_session(scenario))


def test_unifi_unreachable_item_sorts_first(monkeypatch: MonkeyPatch) -> None:
    _set_connectivity(monkeypatch, False)

    async def scenario(session: AsyncSession) -> None:
        result = await attention(db=session)

        assert result.items[0].category == "connectivity"
        assert result.items[0].severity == "critical"
        assert result.items[0].title == "UniFi console unreachable"

    asyncio.run(_with_session(scenario))


def test_unacknowledged_high_cves_roll_up_until_acknowledged(
    monkeypatch: MonkeyPatch,
) -> None:
    _set_connectivity(monkeypatch, True)

    async def scenario(session: AsyncSession) -> None:
        active = CVEAlert(
            cve_id="CVE-2026-0001",
            title="Critical advisory",
            description="Test advisory",
            severity="HIGH",
            source="nvd",
            created_at=BASE_TIME,
        )
        acknowledged = CVEAlert(
            cve_id="CVE-2026-0002",
            title="Acknowledged advisory",
            description="Test advisory",
            severity="HIGH",
            source="nvd",
            acknowledged_at=BASE_TIME,
            created_at=BASE_TIME,
        )
        session.add_all([active, acknowledged])
        await session.commit()

        result = await attention(db=session)
        cve_items = [item for item in result.items if item.category == "cve"]
        assert len(cve_items) == 1
        assert cve_items[0].severity == "critical"
        assert cve_items[0].title == "1 unacknowledged CVE alert"

        active.acknowledged_at = BASE_TIME
        await session.commit()

        result = await attention(db=session)
        assert not any(item.category == "cve" for item in result.items)

    asyncio.run(_with_session(scenario))


def test_stale_syslog_warns_until_fresh_event_arrives(monkeypatch: MonkeyPatch) -> None:
    _set_connectivity(monkeypatch, True)

    async def scenario(session: AsyncSession) -> None:
        stale_at = datetime.now(UTC) - timedelta(hours=48)
        session.add(_firewall_log(stale_at))
        await session.commit()

        result = await attention(db=session)
        syslog_items = [item for item in result.items if item.category == "syslog"]
        assert len(syslog_items) == 1
        assert syslog_items[0].severity == "warning"
        assert syslog_items[0].title == "Firewall syslog has gone quiet"
        assert syslog_items[0].timestamp == stale_at
        assert result.status.last_syslog_event == stale_at

        session.add(_firewall_log(datetime.now(UTC)))
        await session.commit()

        result = await attention(db=session)
        assert not any(item.category == "syslog" for item in result.items)
        assert result.status.last_syslog_event is not None

    asyncio.run(_with_session(scenario))


def test_attention_items_are_sorted_by_severity(monkeypatch: MonkeyPatch) -> None:
    _set_connectivity(monkeypatch, False)

    async def scenario(session: AsyncSession) -> None:
        session.add_all(
            [
                CVEAlert(
                    cve_id="CVE-2026-0003",
                    title="Moderate advisory",
                    description="Test advisory",
                    severity="MEDIUM",
                    source="nvd",
                    created_at=BASE_TIME,
                ),
                _firewall_log(datetime.now(UTC) - timedelta(hours=48)),
                _threat_event(datetime.now(UTC)),
            ]
        )
        await session.commit()

        result = await attention(db=session)
        rank = {"critical": 0, "warning": 1, "info": 2}
        severities = [rank[item.severity] for item in result.items]
        assert severities == sorted(severities)

    asyncio.run(_with_session(scenario))


def test_assessment_regression_uses_episodes_and_clears_on_recovery(
    monkeypatch: MonkeyPatch,
) -> None:
    _set_connectivity(monkeypatch, True)

    async def scenario(session: AsyncSession) -> None:
        now = datetime.now(UTC)
        session.add_all(
            [
                AssessmentRun(
                    created_at=now - timedelta(days=3),
                    score=90,
                    pass_count=9,
                    warn_count=1,
                    fail_count=0,
                    status_hash="before",
                    checks_json="[]",
                ),
                AssessmentRun(
                    created_at=now - timedelta(days=2),
                    score=80,
                    pass_count=8,
                    warn_count=1,
                    fail_count=1,
                    status_hash="drop",
                    checks_json="[]",
                ),
                AssessmentRun(
                    created_at=now - timedelta(days=1),
                    score=80,
                    pass_count=8,
                    warn_count=1,
                    fail_count=1,
                    status_hash="drop",
                    checks_json="[]",
                ),
            ]
        )
        await session.commit()

        result = await attention(db=session)
        regression = [item for item in result.items if item.title == "Assessment score dropped"]
        assert len(regression) == 1
        assert "90 → 80" in regression[0].detail

        session.add(
            AssessmentRun(
                created_at=now,
                score=95,
                pass_count=10,
                warn_count=0,
                fail_count=0,
                status_hash="recovered",
                checks_json="[]",
            )
        )
        await session.commit()
        result = await attention(db=session)
        assert not any(item.title == "Assessment score dropped" for item in result.items)

    asyncio.run(_with_session(scenario))


def test_assessment_regression_ages_out_after_seven_days(monkeypatch: MonkeyPatch) -> None:
    _set_connectivity(monkeypatch, True)

    async def scenario(session: AsyncSession) -> None:
        now = datetime.now(UTC)
        session.add_all(
            [
                AssessmentRun(
                    created_at=now - timedelta(days=9),
                    score=90,
                    pass_count=9,
                    warn_count=1,
                    fail_count=0,
                    status_hash="before",
                    checks_json="[]",
                ),
                AssessmentRun(
                    created_at=now - timedelta(days=8),
                    score=80,
                    pass_count=8,
                    warn_count=1,
                    fail_count=1,
                    status_hash="drop",
                    checks_json="[]",
                ),
                AssessmentRun(
                    created_at=now - timedelta(days=1),
                    score=80,
                    pass_count=8,
                    warn_count=1,
                    fail_count=1,
                    status_hash="drop",
                    checks_json="[]",
                ),
            ]
        )
        await session.commit()

        result = await attention(db=session)
        assert not any(item.title == "Assessment score dropped" for item in result.items)

    asyncio.run(_with_session(scenario))
