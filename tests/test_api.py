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
