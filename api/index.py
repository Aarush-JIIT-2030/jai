"""Fail-closed FastAPI endpoints for offline CyberSentinel flow replay."""
from __future__ import annotations

from pathlib import Path
import sys
from typing import Any

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

BASE_DIR = Path(__file__).resolve().parent.parent
SOURCE_DIR = BASE_DIR / "src"
if str(SOURCE_DIR) not in sys.path:
    sys.path.insert(0, str(SOURCE_DIR))

from cybersentinel.pipeline import CyberSentinelPipeline

app = FastAPI(
    title="CyberSentinel API",
    version="0.2.0",
    description="Offline network-flow analysis with simulated policy recommendations only.",
)

THREAT_MODEL = BASE_DIR / "models" / "threat_detection" / "model.joblib"
ANOMALY_MODEL = BASE_DIR / "models" / "anomaly_detection" / "model.joblib"
_pipeline: CyberSentinelPipeline | None = None


class BatchAnalyzeRequest(BaseModel):
    flows: list[dict[str, Any]] = Field(min_length=1, max_length=1000)


def get_pipeline() -> CyberSentinelPipeline | None:
    global _pipeline
    if _pipeline is not None:
        return _pipeline
    if not THREAT_MODEL.is_file() or not ANOMALY_MODEL.is_file():
        return None
    try:
        _pipeline = CyberSentinelPipeline.load_default(THREAT_MODEL, ANOMALY_MODEL)
    except Exception:
        # Never mark the service ready when artifacts are corrupt or incompatible.
        _pipeline = None
    return _pipeline


@app.get("/")
@app.get("/api")
@app.get("/health")
@app.get("/api/health")
def health():
    pipeline = get_pipeline()
    threat_present = THREAT_MODEL.is_file()
    anomaly_present = ANOMALY_MODEL.is_file()
    return {
        "status": "ok",
        "service": "CyberSentinel API",
        "version": "0.2.0",
        "mode": "offline-replay",
        "model_ready": pipeline is not None,
        "agents": {
            "agent_1_threat_detection": threat_present,
            "agent_2_anomaly_detection": anomaly_present,
            "agent_3_evidence_fusion": True,
        },
        "message": "Both model artifacts loaded." if pipeline else "Model artifacts are missing or failed validation.",
    }


@app.get("/api/models/status")
def models_status():
    pipeline = get_pipeline()
    if pipeline is None:
        return {
            "status": "not_ready",
            "models_ready": False,
            "agents": {
                "threat_detection": {"artifact_present": THREAT_MODEL.is_file()},
                "anomaly_detection": {"artifact_present": ANOMALY_MODEL.is_file()},
                "evidence_fusion": {"ready": True},
            },
        }
    return {
        "status": "ready",
        "models_ready": True,
        "agents": {
            "threat_detection": {
                "backend": pipeline.threat_agent.model.metadata.get("backend"),
                "feature_count": len(pipeline.threat_agent.model.feature_columns),
                "training_rows": pipeline.threat_agent.model.metadata.get("training_rows"),
                "classes": list(pipeline.threat_agent.model.label_encoder.classes_),
            },
            "anomaly_detection": {
                "algorithm": "IsolationForest",
                "feature_count": len(pipeline.anomaly_agent.feature_columns),
                "training_rows": pipeline.anomaly_agent.metadata.get("training_rows"),
                "threshold": pipeline.anomaly_agent.threshold,
            },
            "evidence_fusion": {"simulated_actions": ["ALLOW", "BLOCK", "REVIEW"]},
        },
    }


@app.post("/api/analyze")
@app.post("/analyze")
def analyze(payload: dict[str, Any]):
    pipeline = get_pipeline()
    if pipeline is None:
        raise HTTPException(
            status_code=503,
            detail={"code": "MODEL_NOT_READY", "message": "Both verified model artifacts are required for inference."},
        )
    flow = payload.get("flow", payload)
    if not isinstance(flow, dict) or not flow:
        raise HTTPException(status_code=422, detail="Provide a non-empty flow object.")
    return pipeline.analyze(flow)


@app.post("/api/analyze/batch")
@app.post("/analyze/batch")
def analyze_batch(payload: BatchAnalyzeRequest):
    pipeline = get_pipeline()
    if pipeline is None:
        raise HTTPException(
            status_code=503,
            detail={"code": "MODEL_NOT_READY", "message": "Both verified model artifacts are required for inference."},
        )
    results = pipeline.analyze_batch(payload.flows)
    actions = {"ALLOW": 0, "BLOCK": 0, "REVIEW": 0}
    for result in results:
        actions[result["action"]] += 1
    return {"total_analyzed": len(results), "actions": actions, "results": results}
