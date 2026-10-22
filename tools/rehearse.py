"""Run the whole live demo once and time each step (needs internet)."""

import json
import sys
import time
from pathlib import Path

from fastapi.testclient import TestClient

from app.config import ROOT, Settings
from app.main import create_app
from app.samples import STORED

QS = "GHSA-hrpp-h998-j3pp"
FINAL = {"verified", "verify_failed", "unable_to_verify"}
BUDGET = {"scan": 40, "evidence": 45, "fix": 45, "verify": 65, "report": 40}


def settings(data: Path) -> Settings:
    return Settings(_env_file=None, data_dir=data, scanner="osv-api", verify_mode="demo-local",
                    rate_limit="1000/min")


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
    if job["status"] == "failed":
        return times, {"job": job}
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
    key = c.get(f"/api/jobs/{job_id}/answer-key").json()
    return times, {"job": job, "items": items, "explanation": explanation, "proposal": proposal,
                   "verification": v, "report": report, "answer_key": key}


def checklist(r: dict) -> dict[str, bool]:
    lock = json.loads((ROOT / "samples" / "vuln-demo" / f"package-lock.json{STORED}")
                      .read_text("utf-8"))
    pinned = lock.get("lockfileVersion") in (2, 3) and all(
        e.get("version") and e.get("integrity") for k, e in lock["packages"].items() if k)
    return {
        "pinned lockfile": pinned,
        "live scan": r["job"]["summary"]["scan"]["source"] == "live",
        "answer key compared": r["answer_key"].get("available") is True,
        "verified via demo-local": r["verification"]["status"] == "verified"
        and r["verification"]["mode"] == "demo-local"
        and r["report"]["seal"]["label"] == "VERIFIED",
        "evidence-based explanation": r["explanation"]["provider"] == "evidence-based",
        "no-fix backup (request) present": any(i["package"]["name"] == "request"
                                               for i in r["items"]),
    }


def main() -> int:
    with TestClient(create_app(settings(ROOT / "data" / "rehearsal"))) as c:
        times, r = flow(c)
    if r["job"]["status"] == "failed":
        e = r["job"]["error"]
        print(f"scan failed: {e['message']} {e['hint']}")
        return 1
    print("\nstep        seconds  budget")
    for k, v in times.items():
        print(f"{k:<11} {v:>7}  {BUDGET[k]:>6}")
    print(f"{'total':<11} {sum(times.values()):>7.2f}  {sum(BUDGET.values()):>6}\n")
    checks = checklist(r)
    for k, ok in checks.items():
        print(f"[{'x' if ok else ' '}] {k}")
    t = r["answer_key"].get("totals")
    if t:
        print(f"answer key: {t['matched']} matched · {t['missed']} missed · {t['extra']} extra "
              f"({t['extra_new']} new since key) · found {t['found_pct']}%")
    if r["verification"]["status"] != "verified":
        print("verification:", r["verification"].get("reason"))
    return 0 if all(checks.values()) else 1


if __name__ == "__main__":
    sys.exit(main())
