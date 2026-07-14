import asyncio

import pytest
from fastapi import HTTPException

from app.routers import metrics as metrics_router


def test_metrics_gate_and_cache(monkeypatch) -> None:
    async def scenario() -> None:
        metrics_router._cache = None
        monkeypatch.setattr(metrics_router.settings, "metrics_token", "test-token")
        calls = 0

        async def builder(db):
            nonlocal calls
            calls += 1
            return b"unifi_dashboard_unifi_reachable 1\n"

        monkeypatch.setattr(metrics_router, "build_metrics", builder)
        with pytest.raises(HTTPException) as wrong:
            await metrics_router.metrics("Bearer wrong", object())
        assert wrong.value.status_code == 401
        first = await metrics_router.metrics("Bearer test-token", object())
        second = await metrics_router.metrics("Bearer test-token", object())
        assert first.status_code == second.status_code == 200
        assert b"unifi_dashboard_unifi_reachable" in first.body
        assert calls == 1

    asyncio.run(scenario())


def test_metrics_returns_404_when_disabled(monkeypatch) -> None:
    async def scenario() -> None:
        monkeypatch.setattr(metrics_router.settings, "metrics_token", "")
        with pytest.raises(HTTPException) as disabled:
            await metrics_router.metrics(None, object())
        assert disabled.value.status_code == 404

    asyncio.run(scenario())
