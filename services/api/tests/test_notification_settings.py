import asyncio

import pytest
from fastapi import HTTPException
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from app.database import Base
from app.models.settings import AppSetting
from app.models.user import User
from app.routers.settings import SECRET_MASK, _validate_settings, get_settings, update_settings
from app.schemas.settings import SettingsUpdate


def test_ntfy_token_masking_and_sentinel_preservation_pattern() -> None:
    async def scenario() -> None:
        engine = create_async_engine("sqlite+aiosqlite:///:memory:")
        try:
            async with engine.begin() as connection:
                await connection.run_sync(Base.metadata.create_all)
            factory = async_sessionmaker(engine, expire_on_commit=False)
            user = User(
                email="admin@example.test",
                hashed_password="test",
                is_active=True,
                is_superuser=True,
                is_verified=True,
            )
            async with factory() as db:
                db.add(AppSetting(key="notifications.ntfy_token", value="original"))
                await db.commit()
                assert (await get_settings(db))["notifications.ntfy_token"] == SECRET_MASK
                preserved = await update_settings(
                    SettingsUpdate(settings={"notifications.ntfy_token": SECRET_MASK}), db, user
                )
                assert preserved["notifications.ntfy_token"] == SECRET_MASK
                row = await db.get(AppSetting, "notifications.ntfy_token")
                assert row is not None and row.value == "original"
                replaced = await update_settings(
                    SettingsUpdate(settings={"notifications.ntfy_token": "replacement"}), db, user
                )
                assert replaced["notifications.ntfy_token"] == SECRET_MASK
                await db.refresh(row)
                assert row.value == "replacement"
        finally:
            await engine.dispose()

    asyncio.run(scenario())


def test_notification_url_rejects_cloud_metadata_address() -> None:
    with pytest.raises(HTTPException, match="local"):
        _validate_settings({"notifications.webhook_url": "http://169.254.169.254/x"})
