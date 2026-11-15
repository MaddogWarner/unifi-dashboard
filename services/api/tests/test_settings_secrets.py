import asyncio

import pytest
from fastapi import HTTPException
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from app.database import Base
from app.models.settings import AppSetting
from app.models.user import User
from app.routers.settings import SECRET_MASK, SECRET_SETTINGS, get_settings, update_settings
from app.schemas.settings import SettingsUpdate

REAL_VALUES = {
    "unifi.api_key": "real-api-key",
    "notifications.ntfy_token": "real-token",
    "notifications.webhook_url": "https://hooks.example.test/secret-path",
    "http_proxy.url": "http://user:pass@proxy.example.test:3128",
}


def _user() -> User:
    return User(
        email="admin@example.test",
        hashed_password="test",
        is_active=True,
        is_superuser=True,
        is_verified=True,
    )


def _run(scenario) -> None:
    async def wrapper() -> None:
        engine = create_async_engine("sqlite+aiosqlite:///:memory:")
        try:
            async with engine.begin() as connection:
                await connection.run_sync(Base.metadata.create_all)
            factory = async_sessionmaker(engine, expire_on_commit=False)
            async with factory() as db:
                await scenario(db)
        finally:
            await engine.dispose()

    asyncio.run(wrapper())


def test_secret_set_covers_all_credential_bearing_keys() -> None:
    assert SECRET_SETTINGS == set(REAL_VALUES)


def test_get_masks_set_secrets_and_leaves_empty_ones_blank() -> None:
    async def scenario(db) -> None:
        for key, value in REAL_VALUES.items():
            db.add(AppSetting(key=key, value=value))
        db.add(AppSetting(key="notifications.ntfy_url", value=""))
        await db.commit()
        result = await get_settings(db)
        assert all(result[key] == SECRET_MASK for key in REAL_VALUES)

        for key in REAL_VALUES:
            row = await db.get(AppSetting, key)
            row.value = ""
        await db.commit()
        result = await get_settings(db)
        assert all(result[key] == "" for key in REAL_VALUES)

    _run(scenario)


def test_put_with_mask_preserves_every_secret_including_url_keys() -> None:
    async def scenario(db) -> None:
        for key, value in REAL_VALUES.items():
            db.add(AppSetting(key=key, value=value))
        await db.commit()
        await update_settings(SettingsUpdate(settings={key: SECRET_MASK for key in REAL_VALUES}), db, _user())
        for key, value in REAL_VALUES.items():
            row = await db.get(AppSetting, key)
            await db.refresh(row)
            assert row.value == value

    _run(scenario)


def test_put_with_new_value_replaces_and_invalid_url_still_rejected() -> None:
    async def scenario(db) -> None:
        db.add(AppSetting(key="unifi.api_key", value="old"))
        await db.commit()
        result = await update_settings(SettingsUpdate(settings={"unifi.api_key": "new"}), db, _user())
        assert result["unifi.api_key"] == SECRET_MASK
        row = await db.get(AppSetting, "unifi.api_key")
        await db.refresh(row)
        assert row.value == "new"

        with pytest.raises(HTTPException, match="notifications.webhook_url"):
            await update_settings(
                SettingsUpdate(settings={"notifications.webhook_url": "not-a-url"}), db, _user()
            )

    _run(scenario)
