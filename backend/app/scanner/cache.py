import hashlib
import json
import os
import time
from pathlib import Path
from typing import Any


class DiskCache:
    def __init__(self, root: Path, ttl_s: float, clock=time.time):
        self.root = root
        self.ttl = ttl_s
        self.clock = clock

    def _path(self, key: str) -> Path:
        digest = hashlib.sha256(key.encode()).hexdigest()
        return self.root / digest[:2] / f"{digest}.json"

    def entry(self, key: str, allow_stale: bool = False) -> dict | None:
        try:
            data = json.loads(self._path(key).read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return None
        if data.get("key") != key:
            return None
        if not allow_stale and self.clock() - data.get("ts", 0) > self.ttl:
            return None
        return data

    def get(self, key: str, allow_stale: bool = False) -> Any:
        data = self.entry(key, allow_stale)
        return None if data is None else data.get("value")

    def put(self, key: str, value: Any) -> None:
        path = self._path(key)
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(f".{os.getpid()}.tmp")
        tmp.write_text(json.dumps({"key": key, "ts": self.clock(), "value": value}),
                       encoding="utf-8")
        os.replace(tmp, path)
