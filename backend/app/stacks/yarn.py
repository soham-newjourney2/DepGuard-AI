"""yarn.lock readers: Yarn 1 (classic text format) and Yarn 2+ "Berry" (YAML)."""

from pathlib import Path

from app.stacks.base import Builder, bad_lock, read_json, read_text, read_yaml

ECOSYSTEM = "npm"
KINDS = {"dependencies": "prod", "optionalDependencies": "optional",
         "devDependencies": "dev", "peerDependencies": "peer"}
LOCKED_KINDS = {"dependencies": "prod", "optionalDependencies": "optional"}


def spec_name(spec: str) -> str:
    """'@scope/name@^1.0.0' → '@scope/name'; 'name@npm:^1' → 'name'."""
    at = spec.find("@", 1)
    return spec[:at] if at > 0 else spec


def unquote(s: str) -> str:
    s = s.strip()
    return s[1:-1] if len(s) >= 2 and s[0] == s[-1] == '"' else s


def parse_classic(text: str) -> dict[str, dict]:
    """Entries keyed by their header specs; each has version, resolved, integrity and deps."""
    entries: dict[str, dict] = {}
    current, section = None, None
    for raw in text.splitlines():
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        indent = len(raw) - len(raw.lstrip(" "))
        line = raw.strip()
        if indent == 0:
            if not line.endswith(":"):
                raise ValueError(f"unexpected line {line[:40]!r}")
            current = {"deps": {}, "header": raw}
            for spec in line[:-1].split(","):
                entries[unquote(spec)] = current
            section = None
        elif current is None:
            raise ValueError("field before the first entry")
        elif indent == 2:
            key, _, value = line.partition(" ")
            if line.endswith(":") and not value:
                section = line[:-1]
                continue
            section = None
            current[key] = unquote(value)
        elif indent >= 4 and section in LOCKED_KINDS:
            name, _, rng = line.partition(" ")
            current["deps"].setdefault(section, {})[unquote(name)] = unquote(rng)
    return entries


def resolve(entries: dict[str, dict], name: str, rng: str) -> dict | None:
    for spec in (f"{name}@{rng}", f"{name}@npm:{rng}"):
        if spec in entries:
            return entries[spec]
    return None


def berry_entries(doc: dict) -> dict[str, dict]:
    entries: dict[str, dict] = {}
    for header, body in doc.items():
        if header == "__metadata" or not isinstance(body, dict):
            continue
        current = {"version": str(body.get("version", "")),
                   "resolution": str(body.get("resolution", "")),
                   "checksum": body.get("checksum"), "linkType": body.get("linkType"),
                   "deps": {k: {n: str(v) for n, v in (body.get(k) or {}).items()}
                            for k in LOCKED_KINDS}, "header": header}
        for spec in str(header).split(","):
            entries[spec.strip()] = current
    return entries


def load_yarn(root: Path) -> Builder:
    path = root / "yarn.lock"
    text = read_text(path)
    manifest = read_json(root / "package.json") if (root / "package.json").is_file() else {}
    b = Builder(ECOSYSTEM, manifest.get("name") or root.name)
    berry = "__metadata:" in text
    try:
        entries = berry_entries(read_yaml(path, text)) if berry else parse_classic(text)
    except ValueError as exc:
        raise bad_lock(path, str(exc)[:80]) from None
    unique = {id(e): (spec, e) for spec, e in reversed(entries.items())}
    keys: dict[int, str] = {}
    for eid, (spec, e) in unique.items():
        local = berry and ("@workspace:" in e.get("resolution", "") or
                           e.get("linkType") == "soft")
        if local and e.get("resolution", "").endswith("@workspace:."):
            keys[eid] = ""
            continue
        keys[eid] = b.add(spec_name(spec), e.get("version") or "0.0.0", local=local)
    has_manifest_deps = any(manifest.get(s) for s in KINDS)
    for eid, (_, e) in unique.items():
        src = keys[eid]
        if src == "" and has_manifest_deps:
            continue  # Berry folds devDependencies into the root entry; package.json knows which
        for section, deps in e["deps"].items():
            for dep, rng in deps.items():
                target = resolve(entries, dep, rng)
                if target is not None:
                    b.edges.append((src, keys[id(target)], LOCKED_KINDS[section]))
    for section, kind in KINDS.items():
        for dep, rng in (manifest.get(section) or {}).items():
            target = resolve(entries, dep, str(rng))
            if target is not None and keys[id(target)]:
                b.edges.append(("", keys[id(target)], kind))
            elif target is None:
                b.edges.append(("", dep, kind))
    if not any(src == "" for src, _, _ in b.edges):
        b.roots_without_parents()
    return b
