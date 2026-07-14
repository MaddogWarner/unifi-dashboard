import logging
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime, timedelta

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.assessment import AssessmentRun
from app.models.cve import CVEAlert
from app.models.firewall import FirewallLog, FirewallPolicy
from app.models.threat import ThreatEvent
from app.schemas.dashboard import AttentionItemOut, DashboardAttentionOut, DashboardStatusOut
from app.services.assessment import build_report
from app.services.policy_engine import detect_conflicts
from app.services.unifi_client import check_connectivity

log = logging.getLogger(__name__)


def _normalise_utc(value: datetime | None) -> datetime | None:
    if value is None or value.tzinfo is not None:
        return value
    return value.replace(tzinfo=UTC)


async def build_attention(
    db: AsyncSession,
    connectivity_check: Callable[[], Awaitable[bool]] = check_connectivity,
) -> DashboardAttentionOut:
    now = datetime.now(UTC)
    cutoff_24h = now - timedelta(hours=24)
    items: list[AttentionItemOut] = []

    unifi_reachable = await connectivity_check()
    policies = list((await db.scalars(select(FirewallPolicy))).all())
    last_policy_sync = _normalise_utc(max((policy.synced_at for policy in policies), default=None))

    if not unifi_reachable:
        items.append(
            AttentionItemOut(
                severity="critical",
                category="connectivity",
                title="UniFi console unreachable",
                detail="The dashboard cannot reach the UniFi API. Data shown may be stale.",
                link="/settings",
            )
        )

    assessment_score: int | None
    try:
        report = await build_report(db)
        assessment_score = report.score
        for check in report.checks:
            if check.status == "pass":
                continue
            items.append(
                AttentionItemOut(
                    severity="critical" if check.status == "fail" else "warning",
                    category="assessment",
                    title=check.label,
                    detail=check.detail,
                    link="/assessment",
                )
            )
    except Exception as exc:
        log.exception("Security assessment unavailable for dashboard attention feed")
        assessment_score = None
        detail = getattr(exc, "detail", "Security assessment is temporarily unavailable")
        items.append(
            AttentionItemOut(
                severity="info",
                category="assessment",
                title="Security assessment unavailable",
                detail=str(detail),
                link="/assessment",
            )
        )

    recent_runs = list(
        (
            await db.scalars(
                select(AssessmentRun)
                .where(AssessmentRun.created_at >= now - timedelta(days=14))
                .order_by(AssessmentRun.created_at)
            )
        ).all()
    )
    episodes: list[AssessmentRun] = []
    for run in recent_runs:
        if not episodes or run.status_hash != episodes[-1].status_hash:
            episodes.append(run)
    if len(episodes) >= 2:
        previous, current = episodes[-2:]
        started_at = _normalise_utc(current.created_at)
        if started_at and current.score < previous.score and started_at >= now - timedelta(days=7):
            items.append(
                AttentionItemOut(
                    severity="warning",
                    category="assessment",
                    title="Assessment score dropped",
                    detail=(
                        f"Score dropped {previous.score} → {current.score} on "
                        f"{started_at.strftime('%d/%m/%Y %H:%M')}."
                    ),
                    link="/assessment",
                    timestamp=started_at,
                )
            )

    conflicts = detect_conflicts(policies)
    if conflicts:
        count = len(conflicts)
        detail = conflicts[0].description
        if count > 1:
            detail = f"{detail} …and {count - 1} more"
        items.append(
            AttentionItemOut(
                severity="warning",
                category="conflict",
                title=f"{count} policy conflict{'s' if count != 1 else ''} detected",
                detail=detail,
                link="/assessment",
            )
        )

    unacknowledged_cves = (
        await db.scalar(select(func.count()).select_from(CVEAlert).where(CVEAlert.acknowledged_at.is_(None))) or 0
    )
    high_unacknowledged_cves = (
        await db.scalar(
            select(func.count())
            .select_from(CVEAlert)
            .where(
                CVEAlert.acknowledged_at.is_(None),
                CVEAlert.severity.in_(("CRITICAL", "HIGH")),
            )
        )
        or 0
    )
    if unacknowledged_cves > 0:
        items.append(
            AttentionItemOut(
                severity="critical" if high_unacknowledged_cves else "warning",
                category="cve",
                title=(f"{unacknowledged_cves} unacknowledged CVE alert{'s' if unacknowledged_cves != 1 else ''}"),
                detail="Review and acknowledge advisories for your UniFi devices.",
                link="/cve",
            )
        )

    last_syslog_event = _normalise_utc(await db.scalar(select(func.max(FirewallLog.timestamp))))
    if last_syslog_event is None:
        items.append(
            AttentionItemOut(
                severity="info",
                category="syslog",
                title="No firewall syslog events received",
                detail="Confirm remote logging is enabled on the UniFi console and UDP 514 is reachable.",
                link="/firewall?tab=logs",
            )
        )
    elif last_syslog_event < cutoff_24h:
        items.append(
            AttentionItemOut(
                severity="warning",
                category="syslog",
                title="Firewall syslog has gone quiet",
                detail="No events received in the last 24 hours.",
                link="/firewall?tab=logs",
                timestamp=last_syslog_event,
            )
        )

    threat_events_24h = (
        await db.scalar(select(func.count()).select_from(ThreatEvent).where(ThreatEvent.timestamp >= cutoff_24h)) or 0
    )
    if threat_events_24h > 0:
        items.append(
            AttentionItemOut(
                severity="info",
                category="threat",
                title=(
                    f"{threat_events_24h} IDS/IPS event{'s' if threat_events_24h != 1 else ''} in the last 24 hours"
                ),
                detail="Review the threat log for detail.",
                link="/threats",
            )
        )

    rank = {"critical": 0, "warning": 1, "info": 2}
    items = sorted(items, key=lambda item: rank[item.severity])

    return DashboardAttentionOut(
        generated_at=now,
        status=DashboardStatusOut(
            unifi_reachable=unifi_reachable,
            assessment_score=assessment_score,
            last_policy_sync=last_policy_sync,
            last_syslog_event=last_syslog_event,
            threat_events_24h=threat_events_24h,
        ),
        items=items,
    )
