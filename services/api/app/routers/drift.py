import json

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models.firewall import PolicySnapshot
from app.schemas.firewall import DriftDiffOut, DriftLatestOut, PolicySnapshotOut

router = APIRouter()


@router.get("/snapshots", response_model=list[PolicySnapshotOut])
async def snapshots(db: AsyncSession = Depends(get_db)) -> list[PolicySnapshotOut]:
    result = await db.scalars(select(PolicySnapshot).order_by(PolicySnapshot.created_at.desc()))
    return list(result.all())


def _policy_key(policy: dict) -> str:
    return str(policy.get("_id") or policy.get("id") or policy.get("name") or "")


def _diff(first: PolicySnapshot, second: PolicySnapshot) -> DriftDiffOut:
    a_items = {_policy_key(item): item for item in json.loads(first.snapshot_json or "[]")}
    b_items = {_policy_key(item): item for item in json.loads(second.snapshot_json or "[]")}
    added = [b_items[key] for key in sorted(b_items.keys() - a_items.keys())]
    removed = [a_items[key] for key in sorted(a_items.keys() - b_items.keys())]
    changed = [
        {"before": a_items[key], "after": b_items[key]}
        for key in sorted(a_items.keys() & b_items.keys())
        if a_items[key] != b_items[key]
    ]
    return DriftDiffOut(
        from_snapshot=first.id,
        to_snapshot=second.id,
        added=added,
        removed=removed,
        changed=changed,
    )


@router.get("/diff/{a}/{b}", response_model=DriftDiffOut)
async def diff(a: int, b: int, db: AsyncSession = Depends(get_db)) -> DriftDiffOut:
    first = await db.get(PolicySnapshot, a)
    second = await db.get(PolicySnapshot, b)
    if first is None or second is None:
        raise HTTPException(404, "Snapshot not found")
    return _diff(first, second)


@router.get("/latest-change", response_model=DriftLatestOut)
async def latest_change(db: AsyncSession = Depends(get_db)) -> DriftLatestOut:
    result = await db.scalars(
        select(PolicySnapshot)
        .where(PolicySnapshot.snapshot_type == "zone_policies")
        .order_by(PolicySnapshot.created_at.desc())
        .limit(2)
    )
    items = list(result.all())
    latest = items[0] if items else None
    previous = items[1] if len(items) > 1 else None
    return DriftLatestOut(
        latest_snapshot=latest,
        previous_snapshot=previous,
        diff=_diff(previous, latest) if previous and latest else None,
    )
