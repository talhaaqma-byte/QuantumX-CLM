from __future__ import annotations

from functools import lru_cache

from pydantic import Field, SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="CLM_",
        env_file=".env",
        extra="ignore",
    )

    app_name: str = "QuantumX-CLM API"
    app_version: str = "0.1.0"
    environment: str = Field(default="development")

    log_level: str = Field(default="INFO")

    core_db_dsn: SecretStr | None = Field(default=None)
    secure_db_dsn: SecretStr | None = Field(default=None)

    @field_validator("core_db_dsn", "secure_db_dsn", mode="before")
    @classmethod
    def _empty_str_to_none(cls, value):
        if value in {None, ""}:
            return None
        return value

    db_pool_size: int = Field(default=5)
    db_max_overflow: int = Field(default=10)
    db_pool_timeout_s: int = Field(default=30)

    db_ssl_required: bool = Field(default=False)
    db_ssl_ca_file: str | None = Field(default=None)
    db_ssl_cert_file: str | None = Field(default=None)
    db_ssl_key_file: str | None = Field(default=None)

    healthcheck_db: bool = Field(
        default=False,
        description="If true, /health will attempt to connect to both databases.",
    )

    jwt_secret_key: SecretStr = Field(
        default=SecretStr("dev-secret-key-change-in-production"),
        description="Secret key for JWT token signing. Must be kept secure in production.",
    )
    jwt_algorithm: str = Field(
        default="HS256",
        description="Algorithm used for JWT signing (HS256, HS384, HS512, RS256, etc.)",
    )
    jwt_access_token_expire_minutes: int = Field(
        default=60,
        description="Access token expiration time in minutes",
    )
    jwt_refresh_token_expire_days: int = Field(
        default=7,
        description="Refresh token expiration time in days",
    )


@lru_cache
def get_settings() -> Settings:
    return Settings()
