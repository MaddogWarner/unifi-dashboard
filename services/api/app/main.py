import asyncio
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.collectors.poller import run_poll_loop
from app.collectors.syslog import start_syslog_server
from app.database import Base, engine
from app.models import firewall, network, scan, threat  # noqa: F401
from app.routers import assessment, drift, firewall as fw_router, health, networks, scan as scan_router, threats

logging.basicConfig(level=logging.INFO)


@asynccontextmanager
async def lifespan(app: FastAPI):
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    tasks = [
        asyncio.create_task(run_poll_loop()),
        asyncio.create_task(start_syslog_server()),
    ]
    yield
    for task in tasks:
        task.cancel()


app = FastAPI(title="UniFi Security Dashboard", lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(health.router, prefix="/api/v1/health", tags=["health"])
app.include_router(fw_router.router, prefix="/api/v1/firewall", tags=["firewall"])
app.include_router(threats.router, prefix="/api/v1/threats", tags=["threats"])
app.include_router(networks.router, prefix="/api/v1/networks", tags=["networks"])
app.include_router(assessment.router, prefix="/api/v1/assessment", tags=["assessment"])
app.include_router(drift.router, prefix="/api/v1/drift", tags=["drift"])
app.include_router(scan_router.router, prefix="/api/v1/scan", tags=["scan"])
