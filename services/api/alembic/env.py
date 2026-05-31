from logging.config import fileConfig

from alembic import context
from sqlalchemy import pool, text
from sqlalchemy.ext.asyncio import async_engine_from_config

from app.config import settings
from app.database import Base
from app.models import cve, firewall, network, scan, settings as settings_model, threat, threatfeed  # noqa: F401

config = context.config
config.set_main_option("sqlalchemy.url", settings.database_url)

# Skip fileConfig when driven by the app (connection injected) — the app
# manages its own logging and fileConfig would disable all app.* loggers.
if config.config_file_name is not None and not config.attributes.get("connection"):
    fileConfig(config.config_file_name)

target_metadata = Base.metadata


def run_migrations_offline() -> None:
    context.configure(
        url=settings.database_url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )
    with context.begin_transaction():
        context.run_migrations()


def do_run_migrations(connection) -> None:
    context.configure(connection=connection, target_metadata=target_metadata)
    with context.begin_transaction():
        # SET LOCAL keeps these scoped to the migration transaction. Running them
        # before begin_transaction() would autobegin a SQLAlchemy 2.0 transaction
        # that collides with Alembic's own, forcing a rollback.
        connection.execute(text("SET LOCAL lock_timeout = '10s'"))
        connection.execute(text("SET LOCAL statement_timeout = '60s'"))
        context.run_migrations()


async def run_async_migrations() -> None:
    connectable = async_engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    async with connectable.connect() as connection:
        await connection.run_sync(do_run_migrations)
    await connectable.dispose()


def run_migrations_online() -> None:
    # When the FastAPI app drives the upgrade it injects a live connection so the
    # migration runs on the application's own event loop (via run_sync). Nesting
    # asyncio.run() inside a worker thread deadlocks on some hosts (e.g. the Pi).
    connectable = config.attributes.get("connection")
    if connectable is not None:
        do_run_migrations(connectable)
        return

    import asyncio

    asyncio.run(run_async_migrations())


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
