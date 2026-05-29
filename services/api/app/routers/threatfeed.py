import asyncio
import logging

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.collectors.threat_feed_collector import (
    apply_pending_rule,
    reject_pending_rule,
    run_threat_feed_collector_once,
    validate_outbound_url,
)
from app.database import get_db
from app.models.settings import AppSetting
from app.models.threatfeed import (
    ThreatFeedEntry,
    ThreatFeedPendingRule,
    ThreatFeedRule,
    ThreatFeedSource,
)
from app.schemas.threatfeed import (
    ThreatFeedCreate,
    ThreatFeedEntryList,
    ThreatFeedPendingRuleOut,
    ThreatFeedSourceOut,
    ThreatFeedStatusOut,
    ThreatFeedUpdate,
    ThreatFeedZoneRuleOut,
)

router = APIRouter()
log = logging.getLogger(__name__)


@router.get("/feeds", response_model=list[ThreatFeedSourceOut])
async def list_feeds(db: AsyncSession = Depends(get_db)) -> list[ThreatFeedSource]:
    return list((await db.scalars(select(ThreatFeedSource).order_by(ThreatFeedSource.id))).all())


@router.post("/feeds", response_model=ThreatFeedSourceOut, status_code=201)
async def add_feed(
    body: ThreatFeedCreate, db: AsyncSession = Depends(get_db)
) -> ThreatFeedSource:
    try:
        validate_outbound_url(body.url)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    feed = ThreatFeedSource(name=body.name, url=body.url)
    db.add(feed)
    try:
        await db.commit()
    except IntegrityError as exc:
        await db.rollback()
        raise HTTPException(409, "Threat feed URL already exists") from exc
    await db.refresh(feed)
    return feed


@router.put("/feeds/{feed_id}", response_model=ThreatFeedSourceOut)
async def update_feed(
    feed_id: int, body: ThreatFeedUpdate, db: AsyncSession = Depends(get_db)
) -> ThreatFeedSource:
    feed = await db.get(ThreatFeedSource, feed_id)
    if not feed:
        raise HTTPException(404, "Threat feed not found")
    data = body.model_dump(exclude_unset=True)
    if "url" in data and data["url"]:
        try:
            validate_outbound_url(data["url"])
        except ValueError as exc:
            raise HTTPException(400, str(exc)) from exc
    for field, value in data.items():
        setattr(feed, field, value)
    try:
        await db.commit()
    except IntegrityError as exc:
        await db.rollback()
        raise HTTPException(409, "Threat feed URL already exists") from exc
    await db.refresh(feed)
    return feed


@router.delete("/feeds/{feed_id}", status_code=204)
async def delete_feed(feed_id: int, db: AsyncSession = Depends(get_db)) -> None:
    feed = await db.get(ThreatFeedSource, feed_id)
    if not feed:
        raise HTTPException(404, "Threat feed not found")
    await db.delete(feed)
    await db.commit()


@router.get("/status", response_model=ThreatFeedStatusOut)
async def get_status(db: AsyncSession = Depends(get_db)) -> ThreatFeedStatusOut:
    enabled_setting = await db.get(AppSetting, "threat_feed.enabled")
    mode_setting = await db.get(AppSetting, "threat_feed.apply_mode")
    direction_setting = await db.get(AppSetting, "threat_feed.direction_mode")
    enabled = enabled_setting.value.lower() == "true" if enabled_setting else False
    total = (await db.scalar(select(func.count(ThreatFeedEntry.id)))) or 0
    last = await db.scalar(select(func.max(ThreatFeedSource.last_polled_at)))
    pending_count = (
        await db.scalar(
            select(func.count(ThreatFeedPendingRule.id)).where(
                ThreatFeedPendingRule.status == "pending"
            )
        )
    ) or 0
    rules = (await db.scalars(select(ThreatFeedRule))).all()
    zone_summary: dict[tuple[str, str], dict[str, int]] = {}
    for rule in rules:
        key = (rule.ruleset, rule.direction)
        zone_summary.setdefault(key, {"group_count": 0, "rule_count": 0})
        zone_summary[key]["group_count"] += 1
        if rule.rule_unifi_id:
            zone_summary[key]["rule_count"] += 1
    return ThreatFeedStatusOut(
        enabled=enabled,
        apply_mode=mode_setting.value if mode_setting else "preview",
        direction_mode=direction_setting.value if direction_setting else "inbound",
        last_updated=last,
        total_entries=total,
        pending_count=pending_count,
        zone_rules=[
            ThreatFeedZoneRuleOut(ruleset=ruleset, direction=direction, **counts)
            for (ruleset, direction), counts in sorted(zone_summary.items())
        ],
    )


@router.get("/entries", response_model=ThreatFeedEntryList)
async def list_entries(
    feed_source_id: int | None = None,
    cidr: str | None = None,
    skip: int = 0,
    limit: int = Query(default=100, le=1000),
    db: AsyncSession = Depends(get_db),
) -> ThreatFeedEntryList:
    stmt = (
        select(ThreatFeedEntry, ThreatFeedSource.name.label("feed_name"))
        .join(ThreatFeedSource, ThreatFeedEntry.feed_source_id == ThreatFeedSource.id)
        .order_by(ThreatFeedEntry.cidr)
    )
    if feed_source_id:
        stmt = stmt.where(ThreatFeedEntry.feed_source_id == feed_source_id)
    if cidr:
        stmt = stmt.where(ThreatFeedEntry.cidr.ilike(f"%{cidr}%"))
    total = (await db.execute(select(func.count()).select_from(stmt.subquery()))).scalar() or 0
    rows = (await db.execute(stmt.offset(skip).limit(limit))).all()
    return ThreatFeedEntryList(
        total=total,
        items=[
            {"id": entry.id, "cidr": entry.cidr, "feed_source_name": name, "added_at": entry.added_at}
            for entry, name in rows
        ],
    )


@router.get("/pending-rules", response_model=list[ThreatFeedPendingRuleOut])
async def list_pending_rules(
    status: str = "pending", db: AsyncSession = Depends(get_db)
) -> list[ThreatFeedPendingRule]:
    return list(
        (
            await db.scalars(
                select(ThreatFeedPendingRule)
                .where(ThreatFeedPendingRule.status == status)
                .order_by(ThreatFeedPendingRule.created_at.desc())
            )
        ).all()
    )


@router.post("/pending-rules/{pending_id}/approve", response_model=ThreatFeedPendingRuleOut)
async def approve_pending_rule(pending_id: int) -> ThreatFeedPendingRule:
    try:
        return await apply_pending_rule(pending_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except Exception as exc:
        log.exception("Unexpected error approving pending rule %s", pending_id)
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.post("/pending-rules/{pending_id}/reject", response_model=ThreatFeedPendingRuleOut)
async def reject_rule(pending_id: int) -> ThreatFeedPendingRule:
    try:
        return await reject_pending_rule(pending_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except Exception as exc:
        log.exception("Unexpected error rejecting pending rule %s", pending_id)
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.post("/refresh")
async def refresh_feeds() -> dict[str, str | bool]:
    asyncio.create_task(run_threat_feed_collector_once())
    return {"ok": True, "message": "Threat feed refresh triggered"}
