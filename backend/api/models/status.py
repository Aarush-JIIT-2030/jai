"""Dedicated Vercel function route for /api/models/status."""
from fastapi import FastAPI
from backend.api.index import models_status

app = FastAPI()

@app.get("/")
@app.get("/status")
@app.get("/api/models/status")
def route_models_status():
    return models_status()
