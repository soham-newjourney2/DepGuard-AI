"""Maintainer tool: python tasks.py rehearse [--warm]: times the demo with the network cut."""

import json
import sys
import time
from pathlib import Path

from fastapi.testclient import TestClient

from app.config import ROOT, Settings
from app.main import create_app
from app.verify import modes

DEAD = "http://127.0.0.1:9"
QS = "GHSA-hrpp-h998-j3pp"
FINAL = {"verified", "verify_failed", "unable_to_verify"}
BUDGET = {"scan": 40, "evidence": 45, "fix": 45, "verify": 65, "report": 40}


def settings(data: Path, offline: bool) -> Settings:
    extra = {"scanner": "osv-api", "osv_api_url": DEAD, "registry_url": DEAD} if offline \
        else {"scanner": "fixture"}
    return Settings(_env_file=None, data_dir=data, ai_provider="template",
                    verify_mode="demo-local", rate_limit="1000/min", **extra)


def offline_npm() -> None:
    original = modes.clean_env

    def env(workspace, cache=None):
        return {**original(workspace, cache), "npm_config_offline": "true"}

    modes.clean_env = env


def flow(c: TestClient) -> tuple[dict, dict]:
    t, times = time.perf_counter(), {}

    def lap(name):
        nonlocal t
        now = time.perf_counter()
        times[name] = round(now - t, 2)
        t = now

    job_id = c.post("/api/jobs/demo/vuln-demo").json()["job_id"]
    while (job := c.get(f"/api/jobs/{job_id}").json())["status"] not in ("ready", "failed"):
        time.sleep(0.1)
    lap("scan")
    items = c.get(f"/api/jobs/{job_id}/findings").json()["items"]
    qs = next(i for i in items if i["advisory"]["id"] == QS and i["package"]["version"] == "6.7.0")
    c.get(f"/api/jobs/{job_id}/findings/{qs['id']}")
    explanation = c.post(f"/api/jobs/{job_id}/findings/{qs['id']}/explain").json()
    lap("evidence")
    proposal = c.post(f"/api/jobs/{job_id}/findings/{qs['id']}/proposal").json()["items"][0]
    lap("fix")
    c.post(f"/api/jobs/{job_id}/proposals/{proposal['pid']}/approve", json={"confirm": True})
    while (v := c.get(f"/api/jobs/{job_id}/proposals/{proposal['pid']}/verification").json())[
            "status"] not in FINAL:
        time.sleep(0.25)
    lap("verify")
    report = c.get(f"/api/jobs/{job_id}/report").json()
    c.get(f"/api/jobs/{job_id}/report", params={"format": "html", "download": True})
    lap("report")
    return times, {"job": job, "items": items, "explanation": explanation, "proposal": proposal,
                   "verification": v, "report": report}


def checklist(r: dict) -> dict[str, bool]:
    lock = json.loads((ROOT / "samples" / "vuln-demo" / "package-lock.json").read_text("utf-8"))
    pinned = lock.get("lockfileVersion") in (2, 3) and all(
        e.get("version") and e.get("integrity") for k, e in lock["packages"].items() if k)
    want = json.loads((ROOT / "samples" / "_recorded" / "vuln-demo.expected.json")
                      .read_text("utf-8"))
    got = sorted((i["package"]["name"] + "@" + i["package"]["version"], i["advisory"]["id"])
                 for i in r["items"])
    return {
        "pinned lockfile": pinned,
        "expected_findings match": got == sorted((e["package"], e["advisory"]) for e in want),
        "cached scan labeled": any(w["code"] == "W_CACHED_SCAN" for w in r["job"]["warnings"]),
        "works offline (verified via demo-local)": r["verification"]["status"] == "verified"
        and r["verification"]["mode"] == "demo-local"
        and r["report"]["seal"]["label"] == "VERIFIED",
        "template explanation": r["explanation"]["provider"] == "template",
        "no-fix backup (request) present": any(i["package"]["name"] == "request"
                                               for i in r["items"]),
    }


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    data = ROOT / "data" / "rehearsal"
    if "--warm" in argv:
        with TestClient(create_app(settings(data, offline=False))) as c:
            times, r = flow(c)
        print(f"warm-up run: {r['verification']['status']} in {sum(times.values()):.1f}s")
    offline_npm()
    with TestClient(create_app(settings(data, offline=True))) as c:
        times, r = flow(c)
    print("\nstep        seconds  budget")
    for k, v in times.items():
        print(f"{k:<11} {v:>7}  {BUDGET[k]:>6}")
    print(f"{'total':<11} {sum(times.values()):>7.2f}  {sum(BUDGET.values()):>6}\n")
    checks = checklist(r)
    for k, ok in checks.items():
        print(f"[{'x' if ok else ' '}] {k}")
    if r["verification"]["status"] != "verified":
        print("verification:", r["verification"].get("reason"))
    return 0 if all(checks.values()) else 1
