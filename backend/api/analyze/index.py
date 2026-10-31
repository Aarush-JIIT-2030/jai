"""Dedicated Vercel function route for /api/analyze."""
from typing import Any
from fastapi import FastAPI
from api.index import analyze

app = FastAPI()

@app.post("/")
@app.post("/analyze")
@app.post("/api/analyze")
def route_analyze(payload: dict[str, Any]):
    return analyze(payload)
