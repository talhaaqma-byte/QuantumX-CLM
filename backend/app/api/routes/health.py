from __future__ import annotations

from fastapi import APIRouter, Request

from backend.common.schemas.health import HealthResponse

router = APIRouter(tags=["health"])


@router.get("/health", response_model=HealthResponse)
async def health(request: Request) -> HealthResponse:
    settings = request.app.state.settings

    core_db: str | None
    secure_db: str | None

    db = getattr(request.app.state, "db", None)
    if settings.healthcheck_db and db is not None:
        core_db = await db.ping_core()
        secure_db = await db.ping_secure()
    else:
        core_db = "configured" if settings.core_db_dsn is not None else None
        secure_db = "configured" if settings.secure_db_dsn is not None else None

    return HealthResponse(
        status="ok",
        service=settings.app_name,
        environment=settings.environment,
        core_db=core_db,
        secure_db=secure_db,
    )
