from __future__ import annotations

from fastapi import APIRouter

from backend.app.api.routes.health import router as health_router
from backend.auth.router import router as auth_router
from backend.certificates.router import router as certificates_router
from backend.integrations.router import router as integrations_router
from backend.policies.router import router as policies_router
from backend.workflows.router import router as workflows_router

api_router = APIRouter()

api_router.include_router(health_router)
api_router.include_router(auth_router)
api_router.include_router(certificates_router)
api_router.include_router(integrations_router)
api_router.include_router(policies_router)
api_router.include_router(workflows_router)
