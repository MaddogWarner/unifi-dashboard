import ipaddress
from datetime import UTC, datetime, timedelta

from sqlalchemy import case, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.firewall import FirewallLog
from app.models.threatfeed import ThreatFeedEntry, ThreatFeedSource
from app.schemas.threatfeed import (
    ThreatFeedHitsDailyOut,
    ThreatFeedHitsFeedOut,
    ThreatFeedHitsOut,
    ThreatFeedHitsSourceOut,
)

REMOVED_FEED = "(no longer listed)"


async def build_feed_hits(db: AsyncSession, days: int) -> ThreatFeedHitsOut:
    now = datetime.now(UTC)
    cutoff = now - timedelta(days=days)
    remote_ip = case(
        (FirewallLog.rule_name.contains("-Outbound-"), FirewallLog.dst_ip),
        else_=FirewallLog.src_ip,
    ).label("remote_ip")
    base_filters = (
        FirewallLog.rule_name.like("Block-ThreatFeed-%"),
        FirewallLog.timestamp >= cutoff,
        remote_ip.is_not(None),
    )

    aggregate_rows = (
        await db.execute(
            select(
                remote_ip,
                func.count(FirewallLog.id).label("hits"),
                func.max(FirewallLog.timestamp).label("last_seen"),
            )
            .where(*base_filters)
            .group_by(remote_ip)
            .order_by(func.count(FirewallLog.id).desc(), remote_ip.asc())
        )
    ).all()

    daily_rows = (
        await db.execute(
            select(
                func.date(FirewallLog.timestamp).label("day"),
                func.count(FirewallLog.id).label("hits"),
            )
            .where(*base_filters)
            .group_by(func.date(FirewallLog.timestamp))
            .order_by(func.date(FirewallLog.timestamp))
        )
    ).all()

    port_counts = (
        await db.execute(
            select(
                remote_ip,
                FirewallLog.dst_port,
                func.count(FirewallLog.id).label("hits"),
            )
            .where(*base_filters, FirewallLog.dst_port.is_not(None))
            .group_by(remote_ip, FirewallLog.dst_port)
            .order_by(remote_ip.asc(), func.count(FirewallLog.id).desc(), FirewallLog.dst_port.asc())
        )
    ).all()
    top_ports: dict[str, int] = {}
    for ip, port, _hits in port_counts:
        top_ports.setdefault(ip, port)

    entry_rows = (
        await db.execute(
            select(ThreatFeedEntry.cidr, ThreatFeedSource.name).join(
                ThreatFeedSource, ThreatFeedEntry.feed_source_id == ThreatFeedSource.id
            )
        )
    ).all()
    networks: list[tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, str]] = []
    for cidr, feed_name in entry_rows:
        try:
            networks.append((ipaddress.ip_network(cidr, strict=False), feed_name))
        except ValueError:
            continue

    source_rows: list[ThreatFeedHitsSourceOut] = []
    feed_totals: dict[str, tuple[int, int]] = {}
    for ip, hits, last_seen in aggregate_rows:
        feed = REMOVED_FEED
        try:
            address = ipaddress.ip_address(ip)
            matches = [
                (network.prefixlen, feed_name)
                for network, feed_name in networks
                if network.version == address.version and address in network
            ]
            if matches:
                longest_prefix = max(prefix for prefix, _name in matches)
                feed = min(name for prefix, name in matches if prefix == longest_prefix)
        except ValueError:
            pass
        current_hits, current_sources = feed_totals.get(feed, (0, 0))
        feed_totals[feed] = (current_hits + hits, current_sources + 1)
        source_rows.append(
            ThreatFeedHitsSourceOut(
                ip=ip,
                hits=hits,
                feed=feed,
                last_seen=last_seen,
                top_dst_port=top_ports.get(ip),
            )
        )

    return ThreatFeedHitsOut(
        window_days=days,
        generated_at=now,
        total_hits=sum(row.hits for row in source_rows),
        unique_sources=len(source_rows),
        feeds=[
            ThreatFeedHitsFeedOut(feed=feed, hits=hits, unique_sources=unique_sources)
            for feed, (hits, unique_sources) in sorted(feed_totals.items())
        ],
        top_sources=source_rows[:10],
        daily=[ThreatFeedHitsDailyOut(date=str(day), hits=hits) for day, hits in daily_rows],
    )
