from fastapi.testclient import TestClient

from api import index


class ReadyPipeline:
    def __init__(self):
        class ThreatStub:
            def predict(self, flow):
                from cybersentinel.contracts import ThreatDetectionResult
                return ThreatDetectionResult(predicted_class="BENIGN", confidence=0.99)
        class AnomalyStub:
            def score(self, flow):
                from cybersentinel.contracts import AnomalyDetectionResult
                return AnomalyDetectionResult(anomaly_score=0.01, is_anomaly=False)
        class FusionStub:
            def fuse(self, t, a):
                from cybersentinel.contracts import FusionResult
                return FusionResult(final_class="BENIGN", evidence_status="AGREE", action="ALLOW", rationale=["Stub"])

        self.threat_agent = ThreatStub()
        self.anomaly_agent = AnomalyStub()
        self.fusion_agent = FusionStub()

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
    assert payload["agents"]["agent_4_temporal_correlation"] is True
    assert payload["agents"]["agent_5_adaptive_defense"] is True


def test_single_flow_endpoint_fails_closed_without_models(monkeypatch, tmp_path):
    monkeypatch.setattr(index, "THREAT_MODEL", tmp_path / "missing-threat.joblib")
    monkeypatch.setattr(index, "ANOMALY_MODEL", tmp_path / "missing-anomaly.joblib")
    monkeypatch.setattr(index, "_pipeline", None)
    response = TestClient(index.app).post("/api/analyze", json={"flow": {"Flow Duration": 100}})
    assert response.status_code == 503
    assert response.json()["detail"]["code"] == "MODEL_NOT_READY"


def test_single_flow_endpoint_returns_pipeline_result(monkeypatch):
    monkeypatch.setattr(index, "_pipeline", ReadyPipeline())
    response = TestClient(index.app).post("/api/analyze", json={"flow": {"Flow Duration": 100, "Destination Port": 80}})
    assert response.status_code == 200
    assert response.json()["action"] == "ALLOW"
    assert "temporal_correlation" in response.json()
    assert "adaptive_defense" in response.json()


def test_batch_endpoint_returns_aggregated_actions(monkeypatch):
    monkeypatch.setattr(index, "_pipeline", ReadyPipeline())
    response = TestClient(index.app).post(
        "/api/analyze/batch",
        json={"flows": [{"Flow Duration": 100}, {"Flow Duration": 200}]},
    )
    assert response.status_code == 200
    assert response.json()["total_analyzed"] == 2
    assert response.json()["actions"]["ALLOW"] == 2


def test_replay_simulate_endpoint(monkeypatch):
    monkeypatch.setattr(index, "_pipeline", ReadyPipeline())
    flows = [
        {"record_id": 1, "source_ip": "10.0.0.1", "Destination Port": 443},
        {"record_id": 2, "source_ip": "10.0.0.1", "Destination Port": 443},
    ]
    response = TestClient(index.app).post("/api/replay/simulate", json={"flows": flows})
    assert response.status_code == 200
    data = response.json()
    assert data["metrics"]["total_records"] == 2
    assert len(data["replay_sample"]) == 2


def test_benchmarks_endpoint():
    response = TestClient(index.app).get("/api/benchmarks")
    assert response.status_code == 200
    data = response.json()
    assert "source" in data
    assert "verified_report" in data
    assert isinstance(data["verified_report"], dict)


def test_submission_download_invalid_file():
    response = TestClient(index.app).get("/api/submissions/download/malicious.sh")
    assert response.status_code == 400



def test_fusion_simulator_uses_production_agent_contract():
    response = TestClient(index.app).post(
        "/api/fusion/simulate",
        json={
            "predicted_class": "DOS",
            "confidence": 0.95,
            "anomaly_score": -0.2,
            "is_anomaly": True,
        },
    )
    assert response.status_code == 200
    payload = response.json()
    assert payload["action"] == "BLOCK"
    assert payload["evidence_status"] == "AGREE"
    assert payload["final_class"] == "DOS"


def test_fusion_simulator_rejects_invalid_confidence():
    response = TestClient(index.app).post(
        "/api/fusion/simulate",
        json={
            "predicted_class": "DOS",
            "confidence": 1.5,
            "anomaly_score": 0.2,
            "is_anomaly": True,
        },
    )
    assert response.status_code == 422


def test_correlation_groups_empty_when_no_replay_state(monkeypatch):
    monkeypatch.setattr(index, "_LAST_CORRELATION_GROUPS", [])
    response = TestClient(index.app).get("/api/correlation/groups")
    assert response.status_code == 200
    payload = response.json()
    assert payload["groups"] == []
    assert payload["total"] == 0
    assert payload["synthetic"] is False
