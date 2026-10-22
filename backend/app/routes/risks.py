import json

from fastapi import APIRouter, Request

from app import risks
from app.errors import AppError
from app.routes.findings import csv, load_findings

router = APIRouter(prefix="/api/jobs", tags=["risks"])


def load_risks(request: Request, job_id: str) -> list[dict]:
    load_findings(request, job_id)
    try:
        return json.loads((request.app.state.store.job_dir(job_id) / "risks.json")
                          .read_text("utf-8"))
    except FileNotFoundError:
        return []
    except (OSError, ValueError):
        raise AppError("E_NOT_FOUND", "Risk data is unreadable for this job.",
                       "Run the scan again.", 404) from None


@router.get("/{job_id}/risks")
def list_risks(job_id: str, request: Request, kind: str | None = None,
               severity: str | None = None) -> dict:
    kinds, sevs = csv(kind), csv(severity)
    if kinds - set(risks.KINDS) or sevs - set(risks.SEVERITIES):
        raise AppError("E_INVALID", "Unknown risk kind or severity.",
                       f"Kinds: {', '.join(risks.KINDS)}; severities: "
                       f"{', '.join(risks.SEVERITIES)}.", 422)
    items = load_risks(request, job_id)
    shown = [r for r in items if (not kinds or r["kind"] in kinds)
             and (not sevs or r["severity"] in sevs)]
    return {"total": len(items), "count": len(shown), "items": shown,
            "counts": risks.counts(items)}
