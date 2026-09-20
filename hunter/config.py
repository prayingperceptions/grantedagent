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

    # --- Inner Court -------------------------------------------------------
    inner_court_path: str = Field(default="", alias="INNER_COURT_PATH")
    inner_court_key: str = Field(default="", alias="INNER_COURT_KEY")

    # --- Scorer ------------------------------------------------------------
    scorer_model: str = Field(
        default="sentence-transformers/all-MiniLM-L6-v2", alias="SCORER_MODEL"
    )
    scorer_sim_floor: float = Field(default=0.20, alias="SCORER_SIM_FLOOR")
    scorer_sim_ceil: float = Field(default=0.72, alias="SCORER_SIM_CEIL")
    scorer_min_description_chars: int = Field(
        default=80, alias="SCORER_MIN_DESCRIPTION_CHARS"
    )

    # --- API / SaaS --------------------------------------------------------
    cors_origins: str = Field(default="http://localhost:3000", alias="CORS_ORIGINS")
    current_nonprofit_id: str = Field(default="", alias="CURRENT_NONPROFIT_ID")

    api_base_url: str = Field(default="http://localhost:8000", alias="API_BASE_URL")
    frontend_base_url: str = Field(
        default="http://localhost:3000", alias="FRONTEND_BASE_URL"
    )

    # Cookies are only marked Secure when served over TLS. Defaulting this to
    # true would silently drop the session cookie on a local HTTP deployment,
    # producing a confusing "login does nothing" bug.
    session_cookie_secure: bool = Field(default=False, alias="SESSION_COOKIE_SECURE")
    session_cookie_domain: str = Field(default="", alias="SESSION_COOKIE_DOMAIN")

    # Verification and reset links are emailed with this base.
    public_base_url: str = Field(default="http://localhost:8000", alias="PUBLIC_BASE_URL")

    # When unset, outbound email is written to the log instead of sent. This
    # keeps local development and tests from sending real mail.
    smtp_host: str = Field(default="", alias="SMTP_HOST")
    smtp_port: int = Field(default=587, alias="SMTP_PORT")
    smtp_user: str = Field(default="", alias="SMTP_USER")
    smtp_password: str = Field(default="", alias="SMTP_PASSWORD")
    smtp_from: str = Field(default="Granted Agent <no-reply@grantedagent.com>", alias="SMTP_FROM")
    smtp_use_tls: bool = Field(default=True, alias="SMTP_USE_TLS")

    # --- Stripe ------------------------------------------------------------
    stripe_secret_key: str = Field(default="", alias="STRIPE_SECRET_KEY")
    stripe_webhook_secret: str = Field(default="", alias="STRIPE_WEBHOOK_SECRET")
    stripe_publishable_key: str = Field(default="", alias="STRIPE_PUBLISHABLE_KEY")
    # Comma separated price_id:plan pairs, e.g. price_abc:turnkey,price_def:growth.
    stripe_prices: str = Field(default="", alias="STRIPE_PRICES")

    # --- Rate limiting -----------------------------------------------------
    rate_limit_enabled: bool = Field(default=True, alias="RATE_LIMIT_ENABLED")

    # --- Security ----------------------------------------------------------
    # Extra hostnames accepted by the host-header check, besides those derived
    # from the configured base URLs.
    allowed_hosts: str = Field(default="", alias="ALLOWED_HOSTS")
    environment: str = Field(default="development", alias="ENVIRONMENT")

    @field_validator("states_filter")
    @classmethod
    def _strip(cls, v: str) -> str:
        return v.strip()

    @property
    def cors_origin_list(self) -> list[str]:
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]

    @property
    def stripe_price_ids(self) -> dict[str, str]:
        """Map plan key -> Stripe price id, from STRIPE_PRICES."""
        out: dict[str, str] = {}
        for pair in self.stripe_prices.split(","):
            pair = pair.strip()
            if not pair or ":" not in pair:
                continue
            price_id, plan_key = pair.split(":", 1)
            price_id, plan_key = price_id.strip(), plan_key.strip().lower()
            if price_id and plan_key:
                out[plan_key] = price_id
        return out

    @property
    def stripe_price_ids_inverted(self) -> dict[str, str]:
        """Map Stripe price id -> plan key, for webhook reconciliation."""
        return {v: k for k, v in self.stripe_price_ids.items()}

    @property
    def allowed_host_list(self) -> list[str]:
        """Hostnames permitted in the Host header.

        Derived from the configured public URLs plus any explicit extras, so a
        deployment cannot forget to include itself.
        """
        from urllib.parse import urlparse

        hosts = set()
        for url in (self.public_base_url, self.frontend_base_url, self.api_base_url):
            host = urlparse(url).hostname
            if host:
                hosts.add(host)
        for extra in self.allowed_hosts.split(","):
            extra = extra.strip()
            if extra:
                hosts.add(extra)
        hosts.update({"localhost", "127.0.0.1", "testserver"})
        return sorted(hosts)

    @property
    def email_configured(self) -> bool:
        return bool(self.smtp_host)

    @property
    def billing_configured(self) -> bool:
        return bool(self.stripe_secret_key and self.stripe_webhook_secret)

    @property
    def cookie_secure(self) -> bool:
        return self.session_cookie_secure or self.public_base_url.startswith("https://")

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