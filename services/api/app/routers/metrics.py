import secrets
import time
from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Depends, Header, HTTPException, Response
from prometheus_client import CONTENT_TYPE_LATEST, CollectorRegistry, Gauge, generate_latest
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.database import get_db
from app.models.cve import CVEAlert
from app.models.firewall import FirewallLog, FirewallPolicy
from app.models.threat import ThreatEvent
from app.models.threatfeed import ThreatFeedEntry, ThreatFeedPendingRule
from app.routers.assessment import assessment as build_assessment
from app.services.unifi_client import check_connectivity

router = APIRouter()
CACHE_SECONDS = 60
_cache: tuple[float, bytes] | None = None


async def build_metrics(db: AsyncSession) -> bytes:
    registry = CollectorRegistry()
    reachable = Gauge(
        "unifi_dashboard_unifi_reachable", "Whether the UniFi console is reachable", registry=registry
    )
    assessment_score = Gauge(
        "unifi_dashboard_assessment_score", "Current security assessment score", registry=registry
    )
    assessment_checks = Gauge(
        "unifi_dashboard_assessment_checks",
        "Security assessment checks by status",
        ["status"],
        registry=registry,
    )
    policies = Gauge(
        "unifi_dashboard_firewall_policies", "Firewall policies by action", ["action"], registry=registry
    )
    firewall_events = Gauge(
        "unifi_dashboard_firewall_log_events_24h",
        "Firewall log events in the last 24 hours by action",
        ["action"],
        registry=registry,
    )
    threat_events = Gauge(
        "unifi_dashboard_threat_events_24h", "Threat events in the last 24 hours", registry=registry
    )
    cve_alerts = Gauge(
        "unifi_dashboard_cve_alerts_unacknowledged",
        "Unacknowledged CVE alerts by severity",
        ["severity"],
        registry=registry,
    )
    feed_entries = Gauge(
        "unifi_dashboard_threatfeed_entries", "Threat feed blocklist entries", registry=registry
    )
    pending_rules = Gauge(
        "unifi_dashboard_threatfeed_pending_rules", "Pending threat feed approvals", registry=registry
    )
    last_syslog = Gauge(
        "unifi_dashboard_last_syslog_event_timestamp_seconds",
        "Unix timestamp of the last firewall syslog event",
        registry=registry,
    )
    last_sync = Gauge(
        "unifi_dashboard_last_policy_sync_timestamp_seconds",
        "Unix timestamp of the last firewall policy sync",
        registry=registry,
    )

    reachable.set(1 if await check_connectivity() else 0)
    report = await build_assessment(db)
    assessment_score.set(report.score)
    for status, value in (
        ("pass", report.pass_count),
        ("warn", report.warn_count),
        ("fail", report.fail_count),
    ):
        assessment_checks.labels(status=status).set(value)

    for action, count in (
        await db.execute(select(FirewallPolicy.action, func.count()).group_by(FirewallPolicy.action))
    ).all():
        policies.labels(action=action).set(count)
    cutoff = datetime.now(UTC) - timedelta(hours=24)
    for action, count in (
        await db.execute(
            select(FirewallLog.action, func.count())
            .where(FirewallLog.timestamp >= cutoff)
            .group_by(FirewallLog.action)
        )
    ).all():
        firewall_events.labels(action=action).set(count)
    threat_events.set(
        await db.scalar(
            select(func.count()).select_from(ThreatEvent).where(ThreatEvent.timestamp >= cutoff)
        )
        or 0
    )
    for severity, count in (
        await db.execute(
            select(CVEAlert.severity, func.count())
            .where(CVEAlert.acknowledged_at.is_(None))
            .group_by(CVEAlert.severity)
        )
    ).all():
        cve_alerts.labels(severity=severity.lower()).set(count)
    feed_entries.set(await db.scalar(select(func.count()).select_from(ThreatFeedEntry)) or 0)
    pending_rules.set(
        await db.scalar(
            select(func.count())
            .select_from(ThreatFeedPendingRule)
            .where(ThreatFeedPendingRule.status == "pending")
        )
        or 0
    )
    last_syslog_value = await db.scalar(select(func.max(FirewallLog.timestamp)))
    if last_syslog_value:
        last_syslog.set(last_syslog_value.replace(tzinfo=last_syslog_value.tzinfo or UTC).timestamp())
    last_sync_value = await db.scalar(select(func.max(FirewallPolicy.synced_at)))
    if last_sync_value:
        last_sync.set(last_sync_value.replace(tzinfo=last_sync_value.tzinfo or UTC).timestamp())
    return generate_latest(registry)


@router.get("")
async def metrics(
    authorization: str | None = Header(default=None),
    db: AsyncSession = Depends(get_db),
) -> Response:
    global _cache
    if not settings.metrics_token:
        raise HTTPException(404, "Not found")
    scheme, _, supplied = (authorization or "").partition(" ")
    if scheme.lower() != "bearer" or not secrets.compare_digest(supplied, settings.metrics_token):
        raise HTTPException(401, "Invalid metrics token")
    now = time.monotonic()
    if _cache is None or now - _cache[0] >= CACHE_SECONDS:
        _cache = (now, await build_metrics(db))
    return Response(content=_cache[1], media_type=CONTENT_TYPE_LATEST)
