from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.schemas.dashboard import DashboardAttentionOut
from app.services.attention import build_attention
from app.services.unifi_client import check_connectivity

router = APIRouter()


@router.get("/attention", response_model=DashboardAttentionOut)
async def attention(db: AsyncSession = Depends(get_db)) -> DashboardAttentionOut:
    return await build_attention(db, check_connectivity)
