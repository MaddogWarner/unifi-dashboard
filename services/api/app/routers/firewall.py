from datetime import datetime

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models.firewall import FirewallLog, FirewallPolicy, FirewallRule
from app.models.network import Network
from app.schemas.firewall import (
    FirewallLogOut,
    FirewallLogSummary,
    FirewallPolicyOut,
    FirewallRuleOut,
    FirewallZoneOut,
    TopPort,
    TopRule,
    TopSource,
)

router = APIRouter()


@router.get("/policies", response_model=list[FirewallPolicyOut])
async def list_policies(db: AsyncSession = Depends(get_db)) -> list[FirewallPolicyOut]:
    result = await db.execute(
        select(FirewallPolicy, func.count(FirewallLog.id).label("hit_count"))
        .outerjoin(FirewallLog, FirewallLog.matched_policy_id == FirewallPolicy.id)
        .group_by(FirewallPolicy.id)
        .order_by(FirewallPolicy.src_zone, FirewallPolicy.dst_zone, FirewallPolicy.name)
    )
    return [FirewallPolicyOut.model_validate({**policy.__dict__, "hit_count": count}) for policy, count in result.all()]


@router.get("/rules", response_model=list[FirewallRuleOut])
async def list_rules(db: AsyncSession = Depends(get_db)) -> list[FirewallRuleOut]:
    result = await db.scalars(select(FirewallRule).order_by(FirewallRule.ruleset, FirewallRule.rule_index))
    return list(result.all())


BLOCKING_ACTIONS = ("drop", "reject")
SUMMARY_LIMIT = 5


def _log_conditions(
    src_ip: str | None,
    dst_ip: str | None,
    rule_name: str | None,
    action: str | None,
    from_ts: datetime | None,
    to_ts: datetime | None,
) -> list:
    conditions = []
    if src_ip:
        conditions.append(FirewallLog.src_ip == src_ip)
    if dst_ip:
        conditions.append(FirewallLog.dst_ip == dst_ip)
    if rule_name:
        conditions.append(FirewallLog.rule_name == rule_name)
    if action:
        conditions.append(func.lower(FirewallLog.action) == action.lower())
    if from_ts:
        conditions.append(FirewallLog.timestamp >= from_ts)
    if to_ts:
        conditions.append(FirewallLog.timestamp <= to_ts)
    return conditions


@router.get("/logs", response_model=list[FirewallLogOut])
async def list_logs(
    skip: int = 0,
    limit: int = Query(default=100, le=1000),
    src_ip: str | None = None,
    dst_ip: str | None = None,
    rule_name: str | None = None,
    action: str | None = None,
    from_ts: datetime | None = None,
    to_ts: datetime | None = None,
    db: AsyncSession = Depends(get_db),
) -> list[FirewallLogOut]:
    stmt = select(FirewallLog).where(*_log_conditions(src_ip, dst_ip, rule_name, action, from_ts, to_ts))
    result = await db.scalars(stmt.order_by(FirewallLog.timestamp.desc()).offset(skip).limit(limit))
    return list(result.all())


@router.get("/logs/summary", response_model=FirewallLogSummary)
async def logs_summary(
    src_ip: str | None = None,
    dst_ip: str | None = None,
    rule_name: str | None = None,
    action: str | None = None,
    from_ts: datetime | None = None,
    to_ts: datetime | None = None,
    db: AsyncSession = Depends(get_db),
) -> FirewallLogSummary:
    conditions = _log_conditions(src_ip, dst_ip, rule_name, action, from_ts, to_ts)
    blocked_only = func.lower(FirewallLog.action).in_(BLOCKING_ACTIONS)
    count = func.count(FirewallLog.id)

    total = await db.scalar(select(count).where(*conditions))
    blocked = await db.scalar(select(count).where(*conditions, blocked_only))
    sources = await db.execute(
        select(FirewallLog.src_ip, count)
        .where(*conditions, blocked_only, FirewallLog.src_ip.is_not(None))
        .group_by(FirewallLog.src_ip)
        .order_by(count.desc(), FirewallLog.src_ip)
        .limit(SUMMARY_LIMIT)
    )
    ports = await db.execute(
        select(FirewallLog.dst_port, FirewallLog.protocol, count)
        .where(*conditions, blocked_only, FirewallLog.dst_port.is_not(None))
        .group_by(FirewallLog.dst_port, FirewallLog.protocol)
        .order_by(count.desc(), FirewallLog.dst_port, FirewallLog.protocol)
        .limit(SUMMARY_LIMIT)
    )
    rules = await db.execute(
        select(FirewallLog.rule_name, count)
        .where(*conditions, blocked_only, FirewallLog.rule_name.is_not(None))
        .group_by(FirewallLog.rule_name)
        .order_by(count.desc(), FirewallLog.rule_name)
        .limit(SUMMARY_LIMIT)
    )
    return FirewallLogSummary(
        total=total or 0,
        blocked=blocked or 0,
        top_sources=[TopSource(ip=ip, count=n) for ip, n in sources.all()],
        top_ports=[TopPort(port=port, protocol=protocol, count=n) for port, protocol, n in ports.all()],
        top_rules=[TopRule(rule_name=name, count=n) for name, n in rules.all()],
    )


@router.get("/zones", response_model=list[FirewallZoneOut])
async def list_zones(db: AsyncSession = Depends(get_db)) -> list[FirewallZoneOut]:
    networks = list((await db.scalars(select(Network))).all())
    policies = list((await db.scalars(select(FirewallPolicy))).all())
    names = {network.zone for network in networks if network.zone}
    names.update(policy.src_zone for policy in policies if policy.src_zone)
    names.update(policy.dst_zone for policy in policies if policy.dst_zone)
    return [
        FirewallZoneOut(
            name=name,
            networks=[network.name for network in networks if network.zone == name],
            policy_count=sum(1 for policy in policies if name in {policy.src_zone, policy.dst_zone}),
        )
        for name in sorted(names)
    ]
