import asyncio
import logging
from contextlib import asynccontextmanager

from alembic import command
from alembic.config import Config
from alembic.script import ScriptDirectory
from fastapi import Depends, FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from sqlalchemy import func, inspect, select, text

from app.audit import audit_event
from app.auth import auth_backend, current_active_user, current_superuser, fastapi_users
from app.collectors.cve_collector import run_cve_collector
from app.collectors.poller import run_poll_loop
from app.collectors.syslog import start_syslog_server
from app.collectors.threat_feed_collector import (
    recover_orphaned_approvals,
    run_threat_feed_collector,
)
from app.config import settings as app_config
from app.database import Base, async_session_factory, engine
from app.models import (  # noqa: F401
    cve,
    firewall,
    network,
    scan,
    settings as settings_model,
    threat,
    threatfeed,
    user,
)
from app.models.settings import AppSetting
from app.models.threatfeed import ThreatFeedSource
from app.models.user import User
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
from app.routers.auth_setup import router as setup_router
from app.schemas.user import UserCreate, UserRead, UserUpdate

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
    "threat_feed.direction_mode": "inbound",
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
    async with engine.begin() as conn:
        await conn.execute(
            text("""
                CREATE TABLE IF NOT EXISTS alembic_version (
                    version_num VARCHAR(32) NOT NULL,
                    CONSTRAINT alembic_version_pkc PRIMARY KEY (version_num)
                )
            """)
        )
        await conn.execute(
            text("INSERT INTO alembic_version (version_num) VALUES (:rev)"),
            {"rev": baseline_revision},
        )
    log.info("Database stamped at Alembic revision %s", baseline_revision)


async def current_alembic_revisions() -> set[str]:
    async with engine.begin() as conn:
        result = await conn.execute(text(f"SELECT version_num FROM {ALEMBIC_VERSION_TABLE}"))
        return {str(row.version_num) for row in result}


def current_script_heads(alembic_config: Config) -> set[str]:
    return set(ScriptDirectory.from_config(alembic_config).get_heads())


async def fast_forward_noop_revisions(alembic_config: Config) -> str | None:
    table_names, _ = await existing_schema_state()
    if ALEMBIC_VERSION_TABLE not in table_names:
        return None

    revisions = await current_alembic_revisions()
    fast_forward_targets = {
        target for source, target in NOOP_FAST_FORWARD_REVISIONS.items() if source in revisions
    }
    if not fast_forward_targets:
        return None

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
    source_revision = next(src for src in revisions if src in NOOP_FAST_FORWARD_REVISIONS)
    async with engine.begin() as conn:
        await conn.execute(
            text("UPDATE alembic_version SET version_num = :new WHERE version_num = :old"),
            {"new": target_revision, "old": source_revision},
        )
    log.info("Alembic version fast-forwarded to %s", target_revision)
    return target_revision


def _run_upgrade(connection, alembic_config: Config) -> None:
    alembic_config.attributes["connection"] = connection
    command.upgrade(alembic_config, "head")


async def run_migrations() -> None:
    alembic_config = Config("alembic.ini")
    try:
        log.info("Preparing database migrations")
        await stamp_existing_database_if_needed(alembic_config)
        fast_forwarded_revision = await fast_forward_noop_revisions(alembic_config)
        if fast_forwarded_revision in current_script_heads(alembic_config):
            log.info(
                "Database is already at Alembic head %s after fast-forward; skipping upgrade",
                fast_forwarded_revision,
            )
            return
        log.info("Running Alembic upgrade to head")
        async with engine.connect() as conn:
            await conn.run_sync(_run_upgrade, alembic_config)
        log.info("Database migrations applied")
    except Exception:
        log.exception("Database migration failed during API startup")
        raise


async def enforce_runtime_schema_guards() -> None:
    async with engine.begin() as conn:
        # Guard 1: ensure group_unifi_id is nullable in threat_feed_rules.
        def threat_feed_group_nullable(sync_conn) -> bool:
            inspector = inspect(sync_conn)
            table_names = set(inspector.get_table_names())
            if "threat_feed_rules" not in table_names:
                return True
            columns = {
                column["name"]: column
                for column in inspector.get_columns("threat_feed_rules")
            }
            group_column = columns.get("group_unifi_id")
            return bool(group_column is None or group_column.get("nullable"))

        if not await conn.run_sync(threat_feed_group_nullable):
            if conn.dialect.name != "postgresql":
                log.warning(
                    "threat_feed_rules.group_unifi_id is not nullable, but automatic "
                    "schema guard is only supported on PostgreSQL"
                )
            else:
                log.warning(
                    "Correcting threat_feed_rules.group_unifi_id nullable constraint after migrations"
                )
                await conn.execute(
                    text("ALTER TABLE threat_feed_rules ALTER COLUMN group_unifi_id DROP NOT NULL")
                )

        # Guard 2: ensure the direction column exists in threat_feed_rules and
        # threat_feed_pending_rules.  Migration 008 uses op.add_column which can
        # silently not apply through the asyncpg run_sync adapter (same issue as
        # migration 005 / group_unifi_id).  This guard adds the column with a
        # temporary DEFAULT so existing rows get a value; the DEFAULT is removed
        # immediately after to match the intended schema.
        def missing_direction_tables(sync_conn) -> list[str]:
            inspector = inspect(sync_conn)
            table_names = set(inspector.get_table_names())
            missing = []
            for table in ("threat_feed_rules", "threat_feed_pending_rules"):
                if table not in table_names:
                    continue
                col_names = {col["name"] for col in inspector.get_columns(table)}
                if "direction" not in col_names:
                    missing.append(table)
            return missing

        for table in await conn.run_sync(missing_direction_tables):
            log.warning(
                "Adding missing direction column to %s (migration 008 fallback guard)", table
            )
            if table == "threat_feed_rules":
                await conn.execute(text(
                    "ALTER TABLE threat_feed_rules "
                    "ADD COLUMN IF NOT EXISTS direction VARCHAR(16) NOT NULL DEFAULT 'inbound'"
                ))
                await conn.execute(text(
                    "ALTER TABLE threat_feed_rules ALTER COLUMN direction DROP DEFAULT"
                ))
            elif table == "threat_feed_pending_rules":
                await conn.execute(text(
                    "ALTER TABLE threat_feed_pending_rules "
                    "ADD COLUMN IF NOT EXISTS direction VARCHAR(16) NOT NULL DEFAULT 'inbound'"
                ))
                await conn.execute(text(
                    "ALTER TABLE threat_feed_pending_rules ALTER COLUMN direction DROP DEFAULT"
                ))

        # Guard 2b: ensure uq_threat_feed_rules_key (ruleset, chunk_index, direction) exists.
        # Without this constraint the ON CONFLICT clause in the threat feed UPSERT will fail.
        def has_rules_constraint(sync_conn) -> bool:
            return bool(
                sync_conn.execute(
                    text("SELECT 1 FROM pg_constraint WHERE conname = 'uq_threat_feed_rules_key'")
                ).scalar()
            )

        if not await conn.run_sync(has_rules_constraint):
            log.warning("Creating uq_threat_feed_rules_key constraint (migration 008 fallback guard)")
            await conn.execute(text("""
                DO $$
                DECLARE cname text;
                BEGIN
                    SELECT c.conname INTO cname
                    FROM pg_constraint c
                    JOIN pg_class t ON t.oid = c.conrelid
                    JOIN pg_namespace n ON n.oid = t.relnamespace
                    WHERE t.relname = 'threat_feed_rules' AND n.nspname = current_schema()
                      AND c.contype = 'u'
                      AND (
                        SELECT array_agg(a.attname::text ORDER BY k.ordinality)
                        FROM unnest(c.conkey) WITH ORDINALITY AS k(attnum, ordinality)
                        JOIN pg_attribute a ON a.attrelid = c.conrelid AND a.attnum = k.attnum
                      ) = ARRAY['ruleset', 'chunk_index'];
                    IF cname IS NOT NULL THEN
                        EXECUTE format('ALTER TABLE threat_feed_rules DROP CONSTRAINT %I', cname);
                    END IF;
                END $$;
            """))
            await conn.execute(text(
                "ALTER TABLE threat_feed_rules "
                "ADD CONSTRAINT uq_threat_feed_rules_key UNIQUE (ruleset, chunk_index, direction)"
            ))

        # Guard 2c: ensure uq_threat_feed_pending_rules_key exists.
        def has_pending_constraint(sync_conn) -> bool:
            return bool(
                sync_conn.execute(
                    text(
                        "SELECT 1 FROM pg_constraint "
                        "WHERE conname = 'uq_threat_feed_pending_rules_key'"
                    )
                ).scalar()
            )

        if not await conn.run_sync(has_pending_constraint):
            log.warning(
                "Creating uq_threat_feed_pending_rules_key constraint (migration 008 fallback guard)"
            )
            await conn.execute(text("""
                DO $$
                DECLARE cname text;
                BEGIN
                    SELECT c.conname INTO cname
                    FROM pg_constraint c
                    JOIN pg_class t ON t.oid = c.conrelid
                    JOIN pg_namespace n ON n.oid = t.relnamespace
                    WHERE t.relname = 'threat_feed_pending_rules' AND n.nspname = current_schema()
                      AND c.contype = 'u'
                      AND (
                        SELECT array_agg(a.attname::text ORDER BY k.ordinality)
                        FROM unnest(c.conkey) WITH ORDINALITY AS k(attnum, ordinality)
                        JOIN pg_attribute a ON a.attrelid = c.conrelid AND a.attnum = k.attnum
                      ) = ARRAY['ruleset', 'chunk_index', 'action', 'payload_hash', 'status'];
                    IF cname IS NOT NULL THEN
                        EXECUTE format(
                            'ALTER TABLE threat_feed_pending_rules DROP CONSTRAINT %I', cname
                        );
                    END IF;
                END $$;
            """))
            await conn.execute(text(
                "ALTER TABLE threat_feed_pending_rules "
                "ADD CONSTRAINT uq_threat_feed_pending_rules_key "
                "UNIQUE (ruleset, chunk_index, direction, action, payload_hash, status)"
            ))


@asynccontextmanager
async def lifespan(app: FastAPI):
    await run_migrations()
    await enforce_runtime_schema_guards()
    async with engine.begin() as conn:
        log.info("Ensuring SQLAlchemy metadata exists")
        await conn.run_sync(Base.metadata.create_all)
    log.info("SQLAlchemy metadata check complete")
    await seed_defaults()
    log.info("Default settings seeded")
    await recover_orphaned_approvals()

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


@app.middleware("http")
async def guard_open_registration(request: Request, call_next):
    if request.method == "POST" and request.url.path == "/api/v1/auth/register":
        async with async_session_factory() as session:
            count = await session.scalar(select(func.count()).select_from(User))
            if (count or 0) > 0:
                try:
                    audit_event(
                        "auth.registration_blocked",
                        client_host=request.client.host if request.client else None,
                    )
                except Exception:
                    pass
                return JSONResponse(
                    status_code=403,
                    content={
                        "detail": (
                            "Registration is closed. Use the admin user management API."
                        )
                    },
                )
    return await call_next(request)


@app.middleware("http")
async def audit_login_attempts(request: Request, call_next):
    response = await call_next(request)
    if request.method == "POST" and request.url.path == "/api/v1/auth/login":
        try:
            audit_event(
                "auth.login_success" if response.status_code < 400 else "auth.login_failure",
                client_host=request.client.host if request.client else None,
                status_code=response.status_code,
            )
        except Exception:
            pass
    return response


app.add_middleware(
    CORSMiddleware,
    allow_origins=app_config.cors_allowed_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type"],
)

app.include_router(health.router, prefix="/api/v1/health", tags=["health"])
app.include_router(
    fastapi_users.get_auth_router(auth_backend),
    prefix="/api/v1/auth",
    tags=["auth"],
)
app.include_router(
    fastapi_users.get_register_router(UserRead, UserCreate),
    prefix="/api/v1/auth",
    tags=["auth"],
)
app.include_router(
    fastapi_users.get_users_router(UserRead, UserUpdate),
    prefix="/api/v1/users",
    tags=["users"],
    dependencies=[Depends(current_superuser)],
)
app.include_router(setup_router, prefix="/api/v1/auth", tags=["auth"])

protected = [Depends(current_active_user)]
app.include_router(
    fw_router.router, prefix="/api/v1/firewall", tags=["firewall"], dependencies=protected
)
app.include_router(threats.router, prefix="/api/v1/threats", tags=["threats"], dependencies=protected)
app.include_router(
    networks.router, prefix="/api/v1/networks", tags=["networks"], dependencies=protected
)
app.include_router(
    assessment.router, prefix="/api/v1/assessment", tags=["assessment"], dependencies=protected
)
app.include_router(drift.router, prefix="/api/v1/drift", tags=["drift"], dependencies=protected)
app.include_router(scan_router.router, prefix="/api/v1/scan", tags=["scan"], dependencies=protected)
app.include_router(
    settings_router.router, prefix="/api/v1/settings", tags=["settings"], dependencies=protected
)
app.include_router(cve_router.router, prefix="/api/v1/cve", tags=["cve"], dependencies=protected)
app.include_router(
    threatfeed_router.router,
    prefix="/api/v1/threatfeed",
    tags=["threatfeed"],
    dependencies=protected,
)
