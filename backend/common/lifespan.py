from __future__ import annotations

from contextlib import asynccontextmanager
from typing import AsyncIterator

from fastapi import FastAPI

from backend.common.config import Settings
from backend.common.db import Database
from backend.common.logging import get_logger

logger = get_logger(__name__)


def build_lifespan(settings: Settings):
    @asynccontextmanager
    async def _lifespan(app: FastAPI) -> AsyncIterator[None]:
        db = Database.from_settings(settings)

        app.state.settings = settings
        app.state.db = db

        logger.info("Application startup (env=%s)", settings.environment)
        yield
        logger.info("Application shutdown")

        await db.dispose()

    return _lifespan
