import asyncio
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import select

from app.collectors.cve_collector import run_cve_collector
from app.collectors.poller import run_poll_loop
from app.collectors.syslog import start_syslog_server
from app.collectors.threat_feed_collector import run_threat_feed_collector
from app.config import settings as app_config
from app.database import Base, async_session_factory, engine
from app.models import cve, firewall, network, scan, settings as settings_model, threat, threatfeed  # noqa: F401
from app.models.settings import AppSetting
from app.models.threatfeed import ThreatFeedSource
from app.routers import (
    assessment,
    cve as cve_router,
    drift,
    firewall as fw_router,
    health,
    networks,
    scan as scan_router,
    settings as settings_router,
    threatfeed as threatfeed_router,
    threats,
)

logging.basicConfig(level=logging.INFO)

SETTING_DEFAULTS = {
    "unifi.host": app_config.unifi_host,
    "unifi.api_key": app_config.unifi_api_key,
    "unifi.site": app_config.unifi_site,
    "unifi.verify_ssl": str(app_config.unifi_verify_ssl).lower(),
    "cve_monitoring.enabled": "false",
    "cve_monitoring.poll_interval_hours": "24",
    "threat_feed.enabled": "false",
    "threat_feed.poll_interval_hours": "24",
    "threat_feed.zones": '["WAN_IN", "WAN_LOCAL"]',
    "threat_feed.apply_mode": "preview",
    "http_proxy.enabled": "false",
    "http_proxy.url": "",
}
DEFAULT_FEEDS = [
    {
        "name": "FireHOL Level 1",
        "url": "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset",
    },
    {"name": "Spamhaus DROP", "url": "https://www.spamhaus.org/drop/drop_v4.json"},
]


async def seed_defaults() -> None:
    async with async_session_factory() as session:
        for key, value in SETTING_DEFAULTS.items():
            if not await session.get(AppSetting, key):
                session.add(AppSetting(key=key, value=value))
        existing_urls = set((await session.scalars(select(ThreatFeedSource.url))).all())
        for feed in DEFAULT_FEEDS:
            if feed["url"] not in existing_urls:
                session.add(ThreatFeedSource(**feed, enabled=False))
        await session.commit()


@asynccontextmanager
async def lifespan(app: FastAPI):
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    await seed_defaults()

    tasks = [
        asyncio.create_task(run_poll_loop()),
        asyncio.create_task(start_syslog_server()),
        asyncio.create_task(run_cve_collector()),
        asyncio.create_task(run_threat_feed_collector()),
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
app.include_router(settings_router.router, prefix="/api/v1/settings", tags=["settings"])
app.include_router(cve_router.router, prefix="/api/v1/cve", tags=["cve"])
app.include_router(threatfeed_router.router, prefix="/api/v1/threatfeed", tags=["threatfeed"])
