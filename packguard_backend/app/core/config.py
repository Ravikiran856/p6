"""Application settings loaded from environment variables."""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Optional

from pydantic_settings import BaseSettings, SettingsConfigDict

_BACKEND_ROOT = Path(__file__).resolve().parents[2]


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    app_name: str = "PackGuard API"
    api_v1_prefix: str = "/api/v1"
    debug: bool = False

    # Firebase
    firebase_credentials_path: Optional[str] = None
    firebase_project_id: Optional[str] = None

    # ML artifact
    model_path: str = str(_BACKEND_ROOT / "ml" / "artifacts" / "risk_random_forest.pkl")
    model_version: str = "rf_v1.0"

    # PyPI
    pypi_base_url: str = "https://pypi.org/pypi"
    pypi_timeout_seconds: float = 30.0
    pypi_max_retries: int = 2

    # OSV.dev CVE lookup
    osv_base_url: str = "https://api.osv.dev/v1"
    osv_timeout_seconds: float = 8.0

    # Scan limits
    dependency_graph_max_depth: int = 3
    max_requirements_packages: int = 50

    # Redis (optional — used by slowapi / Celery in production)
    redis_url: Optional[str] = None

    # Rate limiting
    rate_limit_enabled: bool = True
    rate_limit_default: str = "60/minute"
    rate_limit_scan: str = "10/minute"

    # Dev fallback when Firebase credentials are absent
    allow_dev_auth_bypass: bool = False


@lru_cache
def get_settings() -> Settings:
    return Settings()
