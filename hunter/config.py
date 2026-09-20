"""Runtime configuration for the Hunter.

Every knob is env-overridable so the same image can run federal-only,
a single state, or the whole country.
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

HUNTER_DIR = Path(__file__).resolve().parent
STATES_DIR = HUNTER_DIR / "states"
REGISTRY_PATH = HUNTER_DIR / "data" / "foundations_registry.json"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore", case_sensitive=False)

    database_url: str = Field(
        default="postgresql+psycopg://granted:granted@localhost:5432/granted",
        alias="DATABASE_URL",
    )

    # Comma separated list of state codes, or ALL. Accepts "WI", "wi, mn", "ALL".
    states_filter: str = Field(default="ALL", alias="STATES_FILTER")

    # Federal
    grants_gov_api: str = Field(default="https://api.grants.gov/v1/api", alias="GRANTS_GOV_API")
    grants_gov_rows: int = Field(default=100, alias="GRANTS_GOV_ROWS")
    grants_gov_max_pages: int = Field(default=20, alias="GRANTS_GOV_MAX_PAGES")
    grants_gov_statuses: str = Field(
        default="forecasted|posted", alias="GRANTS_GOV_STATUSES"
    )

    # Simpler Grants (HHS) - requires an API key.
    simpler_grants_api: str = Field(
        default="https://api.simpler.grants.gov/v1", alias="SIMPLER_GRANTS_API"
    )
    simpler_grants_api_key: str | None = Field(default=None, alias="SIMPLER_GRANTS_API_KEY")
    simpler_grants_page_size: int = Field(default=100, alias="SIMPLER_GRANTS_PAGE_SIZE")
    simpler_grants_max_pages: int = Field(default=5, alias="SIMPLER_GRANTS_MAX_PAGES")

    # SAM.gov - requires an API key.
    sam_gov_api: str = Field(
        default="https://api.sam.gov/opportunities/v2", alias="SAM_GOV_API"
    )
    sam_gov_api_key: str | None = Field(default=None, alias="SAM_GOV_API_KEY")
    sam_gov_max_pages: int = Field(default=5, alias="SAM_GOV_MAX_PAGES")

    # Foundations
    foundations_timeout_s: float = Field(default=15.0, alias="FOUNDATIONS_TIMEOUT_S")
    foundations_max_concurrency: int = Field(default=8, alias="FOUNDATIONS_MAX_CONCURRENCY")
    foundations_use_playwright: bool = Field(default=True, alias="FOUNDATIONS_USE_PLAYWRIGHT")

    # State/local scraping
    states_timeout_s: float = Field(default=25.0, alias="STATES_TIMEOUT_S")
    states_max_concurrency: int = Field(default=6, alias="STATES_MAX_CONCURRENCY")

    # Scheduler
    scheduler_interval_hours: int = Field(default=6, alias="SCHEDULER_INTERVAL_HOURS")
    scheduler_run_on_start: bool = Field(default=False, alias="SCHEDULER_RUN_ON_START")
    http_timeout_s: float = Field(default=20.0, alias="HTTP_TIMEOUT_S")
    user_agent: str = Field(
        default=(
            "GrantedAgent/0.1 (+https://grantedagent.example/bot; grant-intelligence)"
        ),
        alias="USER_AGENT",
    )

    @field_validator("states_filter")
    @classmethod
    def _strip(cls, v: str) -> str:
        return v.strip()

    @property
    def state_codes(self) -> list[str]:
        """Parsed STATES_FILTER. Returns ["ALL"] sentinel when nationwide."""
        tokens = [t.strip().upper() for t in self.states_filter.split(",") if t.strip()]
        if not tokens or "ALL" in tokens:
            return ["ALL"]
        return tokens

    @property
    def is_nationwide(self) -> bool:
        return self.state_codes == ["ALL"]


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()


def reload_settings() -> Settings:
    get_settings.cache_clear()
    return get_settings()


# Backwards-friendly module-level handle used by sources.
settings = get_settings()

__all__ = ["Settings", "get_settings", "reload_settings", "settings", "STATES_DIR", "REGISTRY_PATH"]