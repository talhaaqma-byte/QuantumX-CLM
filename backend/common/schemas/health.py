from __future__ import annotations

from pydantic import BaseModel, Field


class HealthResponse(BaseModel):
    status: str = Field(description="Health status", examples=["ok"])
    service: str
    environment: str
    core_db: str | None = Field(default=None, description="core db status")
    secure_db: str | None = Field(default=None, description="secure db status")
