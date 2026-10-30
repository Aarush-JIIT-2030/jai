from fastapi.testclient import TestClient

from api import index


class ReadyPipeline:
    def analyze(self, flow):
        return {
            "final_class": "BENIGN",
            "evidence_status": "AGREE",
            "action": "ALLOW",
            "rationale": ["Test double only."],
        }

    def analyze_batch(self, flows):
        return [self.analyze(flow) for flow in flows]


def test_health_does_not_claim_models_ready_without_artifacts(monkeypatch, tmp_path):
    monkeypatch.setattr(index, "THREAT_MODEL", tmp_path / "missing-threat.joblib")
    monkeypatch.setattr(index, "ANOMALY_MODEL", tmp_path / "missing-anomaly.joblib")
    monkeypatch.setattr(index, "_pipeline", None)
    response = TestClient(index.app).get("/api/health")
    assert response.status_code == 200
    payload = response.json()
    assert payload["model_ready"] is False
    assert payload["agents"]["agent_3_evidence_fusion"] is True


def test_single_flow_endpoint_fails_closed_without_models(monkeypatch, tmp_path):
    monkeypatch.setattr(index, "THREAT_MODEL", tmp_path / "missing-threat.joblib")
    monkeypatch.setattr(index, "ANOMALY_MODEL", tmp_path / "missing-anomaly.joblib")
    monkeypatch.setattr(index, "_pipeline", None)
    response = TestClient(index.app).post("/api/analyze", json={"flow": {"Flow Duration": 100}})
    assert response.status_code == 503
    assert response.json()["detail"]["code"] == "MODEL_NOT_READY"


def test_single_flow_endpoint_returns_pipeline_result(monkeypatch):
    monkeypatch.setattr(index, "_pipeline", ReadyPipeline())
    response = TestClient(index.app).post("/api/analyze", json={"flow": {"Flow Duration": 100}})
    assert response.status_code == 200
    assert response.json()["action"] == "ALLOW"


def test_batch_endpoint_returns_aggregated_actions(monkeypatch):
    monkeypatch.setattr(index, "_pipeline", ReadyPipeline())
    response = TestClient(index.app).post(
        "/api/analyze/batch",
        json={"flows": [{"Flow Duration": 100}, {"Flow Duration": 200}]},
    )
    assert response.status_code == 200
    assert response.json()["total_analyzed"] == 2
    assert response.json()["actions"]["ALLOW"] == 2


def test_dedicated_vercel_function_routes(monkeypatch):
    from api.health import app as health_app
    from api.models.status import app as models_app
    from api.analyze.index import app as analyze_app
    from api.analyze.batch import app as batch_app

    monkeypatch.setattr(index, "THREAT_MODEL", index.BASE_DIR / "missing-threat-artifact.joblib")
    monkeypatch.setattr(index, "ANOMALY_MODEL", index.BASE_DIR / "missing-anomaly-artifact.joblib")
    monkeypatch.setattr(index, "_pipeline", None)
    client_health = TestClient(health_app)
    client_models = TestClient(models_app)
    client_analyze = TestClient(analyze_app)
    client_batch = TestClient(batch_app)

    assert client_health.get("/").status_code == 200
    assert client_models.get("/").json()["models_ready"] is False
    monkeypatch.setattr(index, "_pipeline", ReadyPipeline())
    assert client_analyze.post("/", json={"flow": {"Flow Duration": 100}}).json()["action"] == "ALLOW"
    assert client_batch.post("/", json={"flows": [{"Flow Duration": 100}]}).json()["total_analyzed"] == 1
