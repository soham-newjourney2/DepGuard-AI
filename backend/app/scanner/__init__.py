from app.config import Settings
from app.scanner.base import Package, ScanError, ScanResult
from app.scanner.cache import DiskCache
from app.scanner.fixture import RecordedScanner
from app.scanner.osv_api import OsvApiScanner
from app.scanner.osv_cli import OsvCliScanner

__all__ = ["Package", "ScanError", "ScanResult", "make_scanner"]


def make_scanner(s: Settings):
    if s.scanner == "fixture":
        return RecordedScanner(s.recorded_dir)
    if s.scanner == "osv-cli" and OsvCliScanner.available():
        return OsvCliScanner(timeout_s=s.scan_timeout_s)
    cache = DiskCache(s.data_dir / "cache" / "osv", s.cache_ttl_h * 3600)
    return OsvApiScanner(s.osv_api_url, cache, timeout_s=min(15, s.scan_timeout_s))

