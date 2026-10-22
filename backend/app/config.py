from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic_settings import BaseSettings, SettingsConfigDict

ROOT = Path(__file__).resolve().parents[2]
RECORDED = ROOT / "backend" / "tests" / "fixtures" / "recorded"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=ROOT / ".env", extra="ignore")

    scanner: Literal["osv-api", "osv-cli", "fixture"] = "osv-api"
    verify_mode: Literal["auto", "demo-local", "off", "mock"] = "auto"
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
    exploit_signals: Literal["auto", "off"] = "auto"
    kev_url: str = ("https://www.cisa.gov/sites/default/files/feeds/"
                    "known_exploited_vulnerabilities.json")
    epss_url: str = "https://api.first.org/data/v1/epss"
    cache_ttl_h: float = 24
    recorded_dir: Path = RECORDED / "osv"


@lru_cache
def get_settings() -> Settings:
    return Settings()
