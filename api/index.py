"""Fail-closed FastAPI endpoints for offline CyberSentinel 5-agent flow replay."""
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
from cybersentinel.agents.anomaly_detection import AnomalyDetectionAgent
from cybersentinel.agents.correlation import TemporalCorrelationAgent
from cybersentinel.agents.adaptive_defense import AdaptiveDefenseAgent
from cybersentinel.replay import ReplayEngine
import pandas as pd

app = FastAPI(
    title="CyberSentinel API",
    version="1.0.0",
    description="Offline 5-agent network-flow intrusion detection and adaptive defense replay system.",
)

THREAT_MODEL = BASE_DIR / "models" / "threat_detection" / "model.joblib"
ANOMALY_MODEL = BASE_DIR / "models" / "anomaly_detection" / "model.joblib"
_pipeline: CyberSentinelPipeline | None = None
_anomaly_agent: AnomalyDetectionAgent | None = None
_correlation_agent = TemporalCorrelationAgent()
_defense_agent = AdaptiveDefenseAgent()


class BatchAnalyzeRequest(BaseModel):
    flows: list[dict[str, Any]] = Field(min_length=1, max_length=1000)


class ReplaySimulationRequest(BaseModel):
    flows: list[dict[str, Any]] = Field(min_length=1, max_length=5000)


def get_pipeline() -> CyberSentinelPipeline | None:
    global _pipeline
    if _pipeline is not None:
        return _pipeline
    if not THREAT_MODEL.is_file() or not ANOMALY_MODEL.is_file():
        return None
    try:
        _pipeline = CyberSentinelPipeline.load_default(THREAT_MODEL, ANOMALY_MODEL)
    except Exception:
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
        "version": "1.0.0",
        "mode": "offline-replay",
        "model_ready": pipeline is not None,
        "agents": {
            "agent_1_threat_detection": threat_present,
            "agent_2_anomaly_detection": anomaly_present,
            "agent_3_evidence_fusion": True,
            "agent_4_temporal_correlation": True,
            "agent_5_adaptive_defense": True,
        },
        "message": "All 5 multi-agent components operational." if pipeline else "Model artifacts are missing or failed validation.",
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
                "temporal_correlation": {"ready": True},
                "adaptive_defense": {"ready": True},
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
            "temporal_correlation": {"window_size": _correlation_agent.window_size},
            "adaptive_defense": {"scope_type": "SOURCE_IP", "action": "BLOCK"},
        },
    }


@app.post("/api/agents/anomaly/score")
def score_anomaly(payload: dict[str, Any]):
    """Run Agent 2 independently without requiring Agent 1 or evidence fusion."""
    global _anomaly_agent
    if _anomaly_agent is None:
        if not ANOMALY_MODEL.is_file():
            raise HTTPException(
                status_code=503,
                detail={"code": "AGENT_2_NOT_READY", "message": "Agent 2 model artifact is not installed."},
            )
        try:
            _anomaly_agent = AnomalyDetectionAgent.load(ANOMALY_MODEL)
        except Exception as exc:
            raise HTTPException(
                status_code=503,
                detail={"code": "AGENT_2_NOT_READY", "message": f"Agent 2 model could not be loaded: {type(exc).__name__}"},
            )
    flow = payload.get("flow", payload)
    if not isinstance(flow, dict) or not flow:
        raise HTTPException(status_code=422, detail="Provide a non-empty flow object.")
    result = _anomaly_agent.score(flow)
    if result.status != "success":
        raise HTTPException(status_code=422, detail={"code": "AGENT_2_SCORING_ERROR", "message": result.message or "Anomaly scoring failed."})
    return result.to_dict()


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

    # Run Tri-Agent pipeline
    analysis = pipeline.analyze(flow)

    # Correlate with Agent 4
    correlation = _correlation_agent.correlate(
        record_id=flow.get("record_id", "live-flow"),
        flow=flow,
        threat_class=analysis.get("final_class"),
        confidence=analysis.get("confidence"),
    )

    # Evaluate with Agent 5
    src_ip, _, _ = TemporalCorrelationAgent.extract_endpoints(flow)
    is_attack = analysis.get("action") == "BLOCK" or (correlation.correlated and correlation.attack_type != "BENIGN")
    defense = _defense_agent.handle_post_analysis(
        record_id=flow.get("record_id", "live-flow"),
        source_ip=src_ip,
        current_step=len(_correlation_agent.history),
        attack_detected=is_attack,
        attack_type=correlation.attack_type or analysis.get("final_class"),
        confidence=analysis.get("confidence"),
    )

    analysis["temporal_correlation"] = {
        "correlated": correlation.correlated,
        "group_id": correlation.group_id,
        "attack_type": correlation.attack_type,
        "evidence": correlation.evidence,
    }
    analysis["adaptive_defense"] = {
        "action": defense.action,
        "applied_policy_id": defense.applied_policy_id,
        "new_policy": {
            "policy_id": defense.new_policy_created.policy_id,
            "scope_type": defense.new_policy_created.scope_type,
            "scope_value": defense.new_policy_created.scope_value,
            "expires_after_record_id": defense.new_policy_created.expires_after_record_id,
        } if defense.new_policy_created else None,
        "rationale": defense.rationale,
    }
    return analysis


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


@app.post("/api/replay/simulate")
def simulate_replay(payload: ReplaySimulationRequest):
    """Run causal chronological replay over provided flow sequence."""
    pipeline = get_pipeline()
    if pipeline is None:
        raise HTTPException(
            status_code=503,
            detail={"code": "MODEL_NOT_READY", "message": "Both verified model artifacts are required for replay."},
        )
    engine = ReplayEngine(
        threat_agent=pipeline.threat_agent,
        anomaly_agent=pipeline.anomaly_agent,
        fusion_agent=pipeline.fusion_agent,
    )
    df = pd.DataFrame(payload.flows)
    results = engine.run_replay(df)
    return {
        "metrics": results["metrics"],
        "policies_sample": results["policy_rows"][:20],
        "replay_sample": results["replay_rows"][:30],
        "classification_sample": results["classification_rows"][:30],
    }
