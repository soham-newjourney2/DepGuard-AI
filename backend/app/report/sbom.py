import uuid
from urllib.parse import quote

from app import __version__
from app.evidence import fix_versions
from app.jobs import iso, utcnow

SCOPES = {"prod": "required", "optional": "optional", "peer": "optional", "dev": "excluded"}
SEVERITIES = {"critical", "high", "medium", "low", "unknown"}


PURL_TYPES = {"npm": "npm", "PyPI": "pypi", "Go": "golang", "crates.io": "cargo",
              "Packagist": "composer", "RubyGems": "gem", "NuGet": "nuget", "Maven": "maven"}


def path_purl(kind: str, parts: list[str], version: str) -> str:
    return f"pkg:{kind}/{'/'.join(quote(x) for x in parts)}@{quote(version)}"


def purl(name: str, version: str, ecosystem: str = "npm") -> str:
    kind = PURL_TYPES.get(ecosystem, "generic")
    if kind == "npm" and name.startswith("@"):
        return path_purl(kind, name.split("/", 1), version)
    if kind == "pypi":
        return path_purl(kind, [name.lower().replace("_", "-")], version)
    if kind == "golang":
        return path_purl(kind, name.split("/"), f"v{version}")
    if kind in ("composer", "maven"):
        return path_purl(kind, name.replace(":", "/").split("/"), version)
    return path_purl(kind, [name], version)


def method(sev: dict) -> str:
    vector = sev.get("vector") or ""
    if sev.get("source") == "CVSS_V4":
        return "CVSSv4"
    if sev.get("source") == "CVSS_V3":
        return "CVSSv31" if vector.startswith("CVSS:3.1") else "CVSSv3"
    return "other"


def vulnerability(f: dict) -> dict:
    adv, sev = f["advisory"], f["advisory"]["severity"]
    ref = purl(f["package"]["name"], f["package"]["version"],
               f["package"].get("ecosystem", "npm"))
    rating = {"source": {"name": "OSV"}, "severity": sev["label"]
              if sev["label"] in SEVERITIES else "unknown", "method": method(sev)}
    if sev.get("score") is not None:
        rating["score"] = sev["score"]
    if sev.get("vector"):
        rating["vector"] = sev["vector"]
    fixes = fix_versions(f)
    return {
        "bom-ref": f"vuln:{adv['id']}:{ref}",
        "id": adv["id"],
        "source": {"name": "OSV", "url": f"https://osv.dev/vulnerability/{quote(adv['id'])}"},
        "references": [{"id": a, "source": {"name": "NVD" if a.startswith("CVE-") else "OSV"}}
                       for a in adv["aliases"]],
        "ratings": [rating],
        "description": adv["summary"],
        "recommendation": (f"Upgrade {f['package']['name']} to {', '.join(fixes)} or later."
                           if fixes else "No fixed version is published."),
        "published": adv.get("published"),
        "updated": adv.get("modified"),
        "affects": [{"ref": ref, "versions": [{"version": f["package"]["version"],
                                                "status": "affected"}]}],
        "properties": [{"name": "depguard:priority", "value": str(f["priority"]["score"])},
                       {"name": "depguard:band", "value": f["priority"]["band"]},
                       {"name": "depguard:reachability", "value": f["reachability"]["label"]},
                       *exploit_properties(f.get("exploit"))],
    }


def exploit_properties(x: dict | None) -> list[dict]:
    if not x:
        return []
    kev = ("true" if x["status"] == "listed" else "false" if x["checked"]["kev"] and x["cves"]
           else "unknown")
    out = [{"name": "depguard:exploit_status", "value": x["status"]},
           {"name": "depguard:kev", "value": kev}]
    if x["epss"]:
        out += [{"name": "depguard:epss", "value": str(x["epss"]["epss"])},
                {"name": "depguard:epss_percentile", "value": str(x["epss"]["percentile"])}]
    return out


def build(job: dict, graph: dict, findings: list[dict]) -> dict:
    nodes = {n["id"]: n for n in graph["nodes"]}
    root = nodes.get("") or {"name": "project", "version": "0.0.0"}
    ref_of = {}
    components = []
    for key, n in nodes.items():
        if key == "" or n["local"]:
            continue
        ref = purl(n["name"], n["version"], n.get("ecosystem", "npm"))
        ref_of[key] = ref
        if any(c["bom-ref"] == ref for c in components):
            continue
        components.append({
            "type": "library", "bom-ref": ref, "name": n["name"], "version": n["version"],
            "purl": ref, "scope": SCOPES.get(n["scope"], "required"),
            "properties": [{"name": "depguard:scope", "value": n["scope"]},
                           {"name": "depguard:direct", "value": str(n["direct"]).lower()}],
        })
    ref_of[""] = "root"
    deps: dict[str, set[str]] = {}
    for e in graph["edges"]:
        src, dst = ref_of.get(e["from"]), ref_of.get(e["to"])
        if src and dst and src != dst:
            deps.setdefault(src, set()).add(dst)
    seed = uuid.uuid5(uuid.NAMESPACE_URL, f"depguard:{job['id']}:{job['updated_at']}")
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{seed}",
        "version": 1,
        "metadata": {
            "timestamp": iso(utcnow()),
            "tools": {"components": [{"type": "application", "name": "DepGuard AI",
                                      "version": __version__}]},
            "component": {"type": "application", "bom-ref": "root",
                          "name": root.get("name") or "project",
                          "version": root.get("version") or "0.0.0"},
        },
        "components": sorted(components, key=lambda c: c["bom-ref"]),
        "dependencies": [{"ref": ref, "dependsOn": sorted(deps.get(ref, set()))}
                         for ref in ["root", *sorted(c["bom-ref"] for c in components)]],
        "vulnerabilities": [vulnerability(f) for f in findings],
    }
