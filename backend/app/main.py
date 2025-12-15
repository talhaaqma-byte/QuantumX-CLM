from __future__ import annotations

from fastapi import FastAPI

from backend.app.api.router import api_router
from backend.common.config import get_settings
from backend.common.lifespan import build_lifespan
from backend.common.logging import configure_logging


def create_app() -> FastAPI:
    settings = get_settings()
    configure_logging(settings)

    app = FastAPI(
        title=settings.app_name,
        version=settings.app_version,
        lifespan=build_lifespan(settings),
    )

    app.include_router(api_router)
    return app


app = create_app()
