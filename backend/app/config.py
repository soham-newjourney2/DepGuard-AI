from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic_settings import BaseSettings, SettingsConfigDict

ROOT = Path(__file__).resolve().parents[2]


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=ROOT / ".env", extra="ignore")

    scanner: Literal["osv-api", "osv-cli", "fixture"] = "osv-api"
    ai_provider: Literal["auto", "anthropic", "template", "off"] = "auto"
    anthropic_api_key: str = ""
    ai_model: str = "claude-haiku-5-5"
    verify_mode: Literal["auto", "docker", "demo-local", "off", "mock"] = "auto"
    max_upload_mb: int = 15
    max_files: int = 5000
    max_unzipped_mb: int = 80
    max_ratio: int = 100
    job_ttl_min: int = 60
    scan_timeout_s: int = 60
    verify_timeout_s: int = 300
    rate_limit: str = "30/min"
    data_dir: Path = ROOT / "data"
    frontend_dir: Path = ROOT / "frontend"
    samples_dir: Path = ROOT / "samples"
    cleanup_interval_s: float = 60
    osv_api_url: str = "https://api.osv.dev"
    registry_url: str = "https://registry.npmjs.org"
    github_codeload_url: str = "https://codeload.github.com"
    local_only: bool = False
    cache_ttl_h: float = 24
    recorded_dir: Path = ROOT / "samples" / "_recorded" / "osv"
    web_timeout_s: float = 10
    web_max_page_kb: int = 2048
    web_max_asset_kb: int = 3072
    web_max_assets: int = 25
    web_max_total_mb: int = 15
    web_allow_private: bool = False

    @property
    def ai_effective(self) -> str:
        if self.local_only:
            return "off"
        if self.ai_provider == "auto":
            return "anthropic" if self.anthropic_api_key else "template"
        return self.ai_provider


@lru_cache
def get_settings() -> Settings:
    return Settings()
