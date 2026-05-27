from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models.network import Network
from app.schemas.network import NetworkOut

router = APIRouter()


@router.get("/", response_model=list[NetworkOut])
async def list_networks(db: AsyncSession = Depends(get_db)) -> list[NetworkOut]:
    result = await db.scalars(select(Network).order_by(Network.vlan_id, Network.name))
    return list(result.all())
