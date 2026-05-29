from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models.network import Network
from app.schemas.network import NetworkOut
from app.services import unifi_client

router = APIRouter()


@router.get("/", response_model=list[NetworkOut])
async def list_networks(db: AsyncSession = Depends(get_db)) -> list[NetworkOut]:
    result = await db.scalars(select(Network).order_by(Network.vlan_id, Network.name))
    return list(result.all())


@router.get("/zones")
async def list_zones(db: AsyncSession = Depends(get_db)) -> list[dict]:
    zones = await unifi_client.get_zones_list()
    result = [
        {"id": z.get("_id") or z.get("id"), "name": z["name"]}
        for z in zones
        if z.get("name")
    ]
    if not result:
        # Fall back to distinct zone names stored against networks in the DB
        rows = await db.scalars(
            select(Network.zone).where(Network.zone.isnot(None)).distinct()
        )
        result = [{"id": None, "name": name} for name in sorted(rows.all()) if name]
    return result
