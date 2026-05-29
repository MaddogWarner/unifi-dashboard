import asyncio
import logging
from contextlib import asynccontextmanager

from alembic import command
from alembic.config import Config
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import inspect, select, text

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
log = logging.getLogger(__name__)

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
ALEMBIC_VERSION_TABLE = "alembic_version"
INITIAL_SCHEMA_TABLES = {
    "firewall_policies",
    "firewall_rules",
    "networks",
    "ids_config",
    "threat_events",
    "policy_snapshots",
    "scan_results",
    "firewall_logs",
}
PHASE_2_TABLES = {
    "app_settings",
    "device_inventory",
    "cve_alerts",
    "cve_device_links",
    "threat_feed_sources",
    "threat_feed_entries",
    "threat_feed_rules",
    "threat_feed_pending_rules",
}
PHASE_3_TABLES = {
    "firewall_port_forwards",
}
NOOP_FAST_FORWARD_REVISIONS = {
    "003_ids_config_raw_json": "004_firewall_port_forwards",
}


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


async def existing_schema_state() -> tuple[set[str], set[str]]:
    log.info("Inspecting database schema before migrations")
    async with engine.begin() as conn:
        def inspect_schema(sync_conn) -> tuple[set[str], set[str]]:
            inspector = inspect(sync_conn)
            table_names = set(inspector.get_table_names())
            ids_config_columns = (
                {column["name"] for column in inspector.get_columns("ids_config")}
                if "ids_config" in table_names
                else set()
            )
            return table_names, ids_config_columns

        return await conn.run_sync(inspect_schema)


async def stamp_existing_database_if_needed(alembic_config: Config) -> None:
    table_names, ids_config_columns = await existing_schema_state()
    log.info("Database schema inspection found %s tables", len(table_names))
    has_app_tables = bool((INITIAL_SCHEMA_TABLES | PHASE_2_TABLES | PHASE_3_TABLES) & table_names)
    if ALEMBIC_VERSION_TABLE in table_names or not has_app_tables:
        if ALEMBIC_VERSION_TABLE in table_names:
            log.info("Alembic version table already exists; no baseline stamp required")
        else:
            log.info("No existing application tables found; running Alembic from base")
        return

    baseline_revision = (
        "004_firewall_port_forwards"
        if PHASE_3_TABLES & table_names
        else "003_ids_config_raw_json"
        if "raw_json" in ids_config_columns
        else "002_cve_threatfeed_settings"
        if PHASE_2_TABLES & table_names
        else "001_initial_schema"
    )
    log.warning(
        "Existing application tables found without Alembic version metadata; "
        "stamping database at revision %s before upgrade",
        baseline_revision,
    )
    await asyncio.to_thread(command.stamp, alembic_config, baseline_revision)
    log.info("Database stamped at Alembic revision %s", baseline_revision)


async def current_alembic_revisions() -> set[str]:
    async with engine.begin() as conn:
        result = await conn.execute(text(f"SELECT version_num FROM {ALEMBIC_VERSION_TABLE}"))
        return {str(row.version_num) for row in result}


async def fast_forward_noop_revisions(alembic_config: Config) -> None:
    table_names, _ = await existing_schema_state()
    if ALEMBIC_VERSION_TABLE not in table_names:
        return

    revisions = await current_alembic_revisions()
    fast_forward_targets = {
        target for source, target in NOOP_FAST_FORWARD_REVISIONS.items() if source in revisions
    }
    if not fast_forward_targets:
        return

    if len(fast_forward_targets) > 1:
        targets = sorted(fast_forward_targets)
        raise RuntimeError(f"Ambiguous Alembic fast-forward targets: {targets}")

    target_revision = fast_forward_targets.pop()
    log.warning(
        "Fast-forwarding Alembic version from %s to %s before upgrade; "
        "the skipped revision is additive and applied by SQLAlchemy metadata checks",
        sorted(revisions),
        target_revision,
    )
    await asyncio.to_thread(command.stamp, alembic_config, target_revision)
    log.info("Alembic version fast-forwarded to %s", target_revision)


async def run_migrations() -> None:
    alembic_config = Config("alembic.ini")
    try:
        log.info("Preparing database migrations")
        await stamp_existing_database_if_needed(alembic_config)
        await fast_forward_noop_revisions(alembic_config)
        log.info("Running Alembic upgrade to head")
        await asyncio.to_thread(command.upgrade, alembic_config, "head")
        log.info("Database migrations applied")
    except Exception:
        log.exception("Database migration failed during API startup")
        raise


@asynccontextmanager
async def lifespan(app: FastAPI):
    await run_migrations()
    async with engine.begin() as conn:
        log.info("Ensuring SQLAlchemy metadata exists")
        await conn.run_sync(Base.metadata.create_all)
    log.info("SQLAlchemy metadata check complete")
    await seed_defaults()
    log.info("Default settings seeded")

    tasks = [
        asyncio.create_task(run_poll_loop()),
        asyncio.create_task(start_syslog_server()),
        asyncio.create_task(run_cve_collector()),
        asyncio.create_task(run_threat_feed_collector()),
    ]
    log.info("Application startup complete; background collectors started")
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
