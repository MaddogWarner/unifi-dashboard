import asyncio
import importlib.util
from pathlib import Path

from alembic.config import Config
from alembic.script import ScriptDirectory
from sqlalchemy import Text
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from app.database import Base
from app.models.cve import CVEAlert

API_ROOT = Path(__file__).parents[1]


def _load_migration():
    path = API_ROOT / "alembic/versions/015_widen_cve_affected_cpe.py"
    spec = importlib.util.spec_from_file_location("widen_cve_affected_cpe", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_affected_cpe_is_unbounded_text() -> None:
    # SQLite ignores VARCHAR lengths, so the column type is the real guard against the
    # StringDataRightTruncationError seen on PostgreSQL with long CPE lists.
    assert isinstance(CVEAlert.__table__.c.affected_cpe.type, Text)


def test_long_cpe_list_round_trips() -> None:
    cpes = ",".join(f"cpe:2.3:h:ui:model-{i}:-:*:*:*:*:*:*:*" for i in range(200))
    assert len(cpes) > 5000

    async def scenario() -> str | None:
        engine = create_async_engine("sqlite+aiosqlite:///:memory:")
        try:
            async with engine.begin() as connection:
                await connection.run_sync(Base.metadata.create_all)
            async with async_sessionmaker(engine, expire_on_commit=False)() as session:
                session.add(CVEAlert(cve_id="CVE-2023-35085", severity="CRITICAL", affected_cpe=cpes))
                await session.commit()
                row = await session.get(CVEAlert, 1)
                return row.affected_cpe if row else None
        finally:
            await engine.dispose()

    assert asyncio.run(scenario()) == cpes


def test_migration_widens_the_column(monkeypatch) -> None:
    migration = _load_migration()
    statements: list[str] = []
    monkeypatch.setattr(migration.op, "execute", statements.append)

    migration.upgrade()

    assert statements == ["ALTER TABLE cve_alerts ALTER COLUMN affected_cpe TYPE TEXT"]


def test_migration_chain_has_a_single_head() -> None:
    config = Config(str(API_ROOT / "alembic.ini"))
    config.set_main_option("script_location", str(API_ROOT / "alembic"))
    script = ScriptDirectory.from_config(config)

    assert script.get_heads() == ["015_widen_cve_affected_cpe"]
    assert script.get_revision("015_widen_cve_affected_cpe").down_revision == "014_add_assessment_runs"
