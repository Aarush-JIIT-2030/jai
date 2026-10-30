"""Vercel Python API for CyberSentinel.

Model inference intentionally fails closed until the organiser dataset has been
used to train and verify the real model artifacts. This endpoint never returns
synthetic predictions.
"""
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

app = FastAPI(
    title="CyberSentinel API",
    version="0.1.0",
    description="Offline network-flow analysis API; simulated policy outputs only.",
)

class AnalyzeRequest(BaseModel):
    flows: list[dict[str, float | int | str | None]] = Field(min_length=1, max_length=1000)

@app.get("/")
@app.get("/api")
@app.get("/health")
@app.get("/api/health")
def health():
    return {
        "status": "ok",
        "service": "CyberSentinel API",
        "model_ready": False,
        "message": "API is online. Real model artifacts are not installed yet.",
    }

@app.post("/analyze")
@app.post("/api/analyze")
def analyze(payload: AnalyzeRequest):
    raise HTTPException(
        status_code=503,
        detail={
            "code": "MODEL_NOT_READY",
            "message": (
                "Inference is disabled until the official organiser dataset is "
                "received, the agents are trained, and validation is completed."
            ),
        },
    )
