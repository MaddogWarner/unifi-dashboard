from datetime import datetime

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models.firewall import FirewallLog, FirewallPolicy, FirewallRule
from app.models.network import Network
from app.schemas.firewall import FirewallLogOut, FirewallPolicyOut, FirewallRuleOut, FirewallZoneOut

router = APIRouter()


@router.get("/policies", response_model=list[FirewallPolicyOut])
async def list_policies(db: AsyncSession = Depends(get_db)) -> list[FirewallPolicyOut]:
    result = await db.execute(
        select(FirewallPolicy, func.count(FirewallLog.id).label("hit_count"))
        .outerjoin(FirewallLog, FirewallLog.matched_policy_id == FirewallPolicy.id)
        .group_by(FirewallPolicy.id)
        .order_by(FirewallPolicy.src_zone, FirewallPolicy.dst_zone, FirewallPolicy.name)
    )
    return [
        FirewallPolicyOut.model_validate({**policy.__dict__, "hit_count": count})
        for policy, count in result.all()
    ]


@router.get("/rules", response_model=list[FirewallRuleOut])
async def list_rules(db: AsyncSession = Depends(get_db)) -> list[FirewallRuleOut]:
    result = await db.scalars(select(FirewallRule).order_by(FirewallRule.ruleset, FirewallRule.rule_index))
    return list(result.all())


@router.get("/logs", response_model=list[FirewallLogOut])
async def list_logs(
    skip: int = 0,
    limit: int = Query(default=100, le=1000),
    src_ip: str | None = None,
    rule_name: str | None = None,
    from_ts: datetime | None = None,
    to_ts: datetime | None = None,
    db: AsyncSession = Depends(get_db),
) -> list[FirewallLogOut]:
    stmt = select(FirewallLog)
    if src_ip:
        stmt = stmt.where(FirewallLog.src_ip == src_ip)
    if rule_name:
        stmt = stmt.where(FirewallLog.rule_name == rule_name)
    if from_ts:
        stmt = stmt.where(FirewallLog.timestamp >= from_ts)
    if to_ts:
        stmt = stmt.where(FirewallLog.timestamp <= to_ts)
    result = await db.scalars(stmt.order_by(FirewallLog.timestamp.desc()).offset(skip).limit(limit))
    return list(result.all())


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
