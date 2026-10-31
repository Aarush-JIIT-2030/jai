"""Read-only API for generated, provenance-bearing evaluation reports."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from fastapi import APIRouter, HTTPException
from fastapi.responses import FileResponse

router = APIRouter(prefix="/api/evaluation", tags=["Evaluation"])
BASE_DIR = Path(__file__).resolve().parents[2]
EVAL_DIR = BASE_DIR / "outputs" / "evaluation"
PLOTS_DIR = EVAL_DIR / "plots"
REPORT_NAMES = ("summary", "classification", "fusion", "anomaly", "generalization", "calibration", "loao", "temporal", "defense")


def _read_report(name: str) -> dict[str, Any]:
    if name not in REPORT_NAMES:
        raise HTTPException(status_code=404, detail={"code": "UNKNOWN_REPORT", "message": "Unknown evaluation report."})
    path = EVAL_DIR / f"{name}.json"
    if not path.is_file():
        raise HTTPException(status_code=404, detail={"code": "REPORT_NOT_GENERATED", "message": f"{name}.json has not been generated. Run the local evaluation command with authorized data and trained models."})
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise HTTPException(status_code=500, detail={"code": "REPORT_INVALID", "message": f"Could not read {name}.json: {type(exc).__name__}"}) from exc
    if not isinstance(payload, dict):
        raise HTTPException(status_code=500, detail={"code": "REPORT_INVALID", "message": f"{name}.json must contain a JSON object."})
    # The report writer stores provenance beside the result under `data`.
    # Flatten the public response while retaining provenance for the UI.
    if isinstance(payload.get("data"), dict):
        return {**payload["data"], "report_name": payload.get("report_name", name), "metadata": payload.get("metadata", {})}
    return payload


@router.get("/all")
def get_all_reports():
    reports: dict[str, Any] = {}
    missing: list[str] = []
    for name in REPORT_NAMES:
        try:
            reports[name] = _read_report(name)
        except HTTPException as exc:
            if exc.status_code == 404:
                reports[name] = None
                missing.append(name)
            else:
                raise
    present = len(REPORT_NAMES) - len(missing)
    return {"status": "ready" if not missing else "partial" if present else "not_generated",
            "available_reports": present, "expected_reports": len(REPORT_NAMES),
            "missing_reports": missing, "reports": reports}


@router.get("/{report_name}")
def get_report(report_name: str):
    return _read_report(report_name)


@router.get("/plots/{filename}")
def get_plot(filename: str):
    clean_name = Path(filename).name
    if clean_name != filename or not clean_name.lower().endswith((".png", ".svg")):
        raise HTTPException(status_code=400, detail="Invalid plot filename.")
    path = PLOTS_DIR / clean_name
    if not path.is_file():
        raise HTTPException(status_code=404, detail="Evaluation plot not generated.")
    return FileResponse(path, media_type="image/svg+xml" if clean_name.lower().endswith(".svg") else "image/png")
