import asyncio
from datetime import UTC, datetime, timedelta

from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from app.database import Base
from app.models.firewall import FirewallLog
from app.models.threatfeed import ThreatFeedEntry, ThreatFeedSource
from app.services.feed_hits import build_feed_hits


def _log(now: datetime, ip: str, port: int, *, outbound: bool = False) -> FirewallLog:
    return FirewallLog(
        timestamp=now,
        rule_name="Block-ThreatFeed-WAN-Outbound-0" if outbound else "Block-ThreatFeed-WAN-0",
        action="drop",
        src_ip="192.168.1.10" if outbound else ip,
        dst_ip=ip if outbound else "192.168.1.10",
        dst_port=port,
        raw_line="test",
    )


def test_feed_hits_attribution_scope_precedence_and_port_tie_break() -> None:
    async def scenario() -> None:
        engine = create_async_engine("sqlite+aiosqlite:///:memory:")
        try:
            async with engine.begin() as connection:
                await connection.run_sync(Base.metadata.create_all)
            factory = async_sessionmaker(engine, expire_on_commit=False)
            now = datetime.now(UTC)
            async with factory() as db:
                broad = ThreatFeedSource(name="Broad", url="https://broad.example")
                exact = ThreatFeedSource(name="Exact", url="https://exact.example")
                db.add_all([broad, exact])
                await db.flush()
                db.add_all(
                    [
                        ThreatFeedEntry(cidr="10.0.0.0/8", feed_source_id=broad.id),
                        ThreatFeedEntry(cidr="10.1.2.3/32", feed_source_id=exact.id),
                        _log(now, "10.1.2.3", 443),
                        _log(now, "10.1.2.3", 80),
                        _log(now, "10.2.3.4", 53),
                        _log(now, "203.0.113.9", 22, outbound=True),
                        FirewallLog(
                            timestamp=now,
                            rule_name="Unrelated",
                            action="drop",
                            src_ip="10.9.9.9",
                            raw_line="test",
                        ),
                        _log(now - timedelta(days=8), "10.8.8.8", 25),
                    ]
                )
                await db.commit()
                result = await build_feed_hits(db, 7)
                assert result.total_hits == 4
                assert result.unique_sources == 3
                sources = {row.ip: row for row in result.top_sources}
                assert sources["10.1.2.3"].feed == "Exact"
                assert sources["10.1.2.3"].top_dst_port == 80
                assert sources["203.0.113.9"].feed == "(no longer listed)"
                assert sum(feed.hits for feed in result.feeds) == result.total_hits
        finally:
            await engine.dispose()

    asyncio.run(scenario())
