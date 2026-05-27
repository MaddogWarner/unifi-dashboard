from fastapi import APIRouter
from sqlalchemy import text

from app.database import async_session_factory
from app.schemas.health import HealthOut
from app.services.unifi_client import check_connectivity

router = APIRouter()


@router.get("", response_model=HealthOut)
async def health() -> HealthOut:
    db_ok = False
    async with async_session_factory() as session:
        try:
            await session.execute(text("SELECT 1"))
            db_ok = True
        except Exception:
            db_ok = False
    return HealthOut(
        status="ok" if db_ok else "degraded",
        unifi_reachable=await check_connectivity(),
        db_ok=db_ok,
    )
