"""Dedicated Vercel function route for /api/health."""
from fastapi import FastAPI
from backend.api.index import health

app = FastAPI()

@app.get("/")
@app.get("/health")
@app.get("/api/health")
def route_health():
    return health()
