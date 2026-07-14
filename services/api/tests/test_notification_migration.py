import importlib.util
from pathlib import Path

from alembic.migration import MigrationContext
from alembic.operations import Operations
from sqlalchemy import create_engine, inspect


def test_notification_state_migration_is_idempotent() -> None:
    path = Path(__file__).parents[1] / "alembic/versions/013_add_notification_state.py"
    spec = importlib.util.spec_from_file_location("notification_migration", path)
    assert spec and spec.loader
    migration = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(migration)
    engine = create_engine("sqlite:///:memory:")
    try:
        with engine.begin() as connection:
            context = MigrationContext.configure(connection)
            with Operations.context(context):
                migration.upgrade()
                migration.upgrade()
            assert "notification_state" in inspect(connection).get_table_names()
    finally:
        engine.dispose()
