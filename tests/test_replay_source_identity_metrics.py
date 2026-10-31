"""Replay metrics must distinguish observed, synthetic, and unavailable source identities."""
import pandas as pd

from cybersentinel.agents.correlation import TemporalCorrelationAgent
from cybersentinel.contracts import AnomalyDetectionResult, ThreatDetectionResult
from cybersentinel.replay import ReplayEngine


class ThreatAgent:
    def predict(self, flow):
        return ThreatDetectionResult(predicted_class="BENIGN", confidence=0.9)


class AnomalyAgent:
    def score(self, flow):
        return AnomalyDetectionResult(anomaly_score=0.1, is_anomaly=False, evidence=[])


def test_source_identity_metrics_count_only_successful_synthetic_fallbacks():
    fingerprint = {
        "Init_Win_bytes_forward": 64240,
        "min_seg_size_forward": 20,
        "Fwd Header Length": 40,
    }
    frame = pd.DataFrame([
        {"record_id": "observed", "source_ip": "192.0.2.10", **fingerprint},
        {"record_id": "synthetic", **fingerprint},
        {"record_id": "unresolved"},
    ])

    metrics = ReplayEngine(ThreatAgent(), AnomalyAgent()).run_replay(frame)["metrics"]

    assert metrics["missing_native_source_ip_rows"] == 2
    assert metrics["synthetic_source_identity_rows"] == 1
    assert metrics["unresolved_source_identity_rows"] == 1
    assert metrics["source_identity_mode"] == "MIXED_OBSERVED_AND_SYNTHETIC"
    assert metrics["synthetic_source_identity_rows"] == sum(
        not TemporalCorrelationAgent.has_observed_source_ip(row)
        and bool(TemporalCorrelationAgent.derive_source_identity(row))
        for row in frame.to_dict(orient="records")
    )