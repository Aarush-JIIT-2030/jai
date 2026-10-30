import pandas as pd
import pytest
from pathlib import Path

from cybersentinel.replay import ReplayEngine
from cybersentinel.contracts import ThreatDetectionResult, AnomalyDetectionResult


class DummyThreatAgent:
    def predict(self, flow):
        dport = int(flow.get("Destination Port", 0))
        if dport == 80:
            return ThreatDetectionResult(predicted_class="DOS", confidence=0.98)
        return ThreatDetectionResult(predicted_class="BENIGN", confidence=0.99)


class DummyAnomalyAgent:
    def score(self, flow):
        dport = int(flow.get("Destination Port", 0))
        return AnomalyDetectionResult(
            anomaly_score=0.85 if dport == 80 else 0.01,
            is_anomaly=dport == 80,
            evidence=[{"feature": "Destination Port", "value": dport}],
        )


def test_replay_causal_workflow(tmp_path):
    engine = ReplayEngine(
        threat_agent=DummyThreatAgent(),
        anomaly_agent=DummyAnomalyAgent(),
    )

    # 4 flows: 2 attack flows from 1.1.1.1, then 2 benign from 2.2.2.2
    data = [
        {"record_id": 101, "source_ip": "1.1.1.1", "Destination Port": 80, "label": "DOS"},
        {"record_id": 102, "source_ip": "1.1.1.1", "Destination Port": 80, "label": "DOS"},
        {"record_id": 103, "source_ip": "2.2.2.2", "Destination Port": 443, "label": "BENIGN"},
        {"record_id": 104, "source_ip": "2.2.2.2", "Destination Port": 443, "label": "BENIGN"},
    ]
    df = pd.DataFrame(data)

    results = engine.run_replay(df)

    assert len(results["classification_rows"]) == 4
    assert len(results["replay_rows"]) == 4

    # Flow 101: First attack flow -> ALLOW into analyzer, activates policy
    assert results["replay_rows"][0]["record_id"] == 101
    assert results["replay_rows"][0]["action"] == "ALLOW"
    assert results["replay_rows"][0]["applied_policy_id"] == ""

    # Flow 102: Second attack flow from same source -> BLOCKED by active policy!
    assert results["replay_rows"][1]["record_id"] == 102
    assert results["replay_rows"][1]["action"] == "BLOCK"
    assert results["replay_rows"][1]["applied_policy_id"].startswith("POL-")

    # Flow 103 & 104: Benign flows from different source -> ALLOWED!
    assert results["replay_rows"][2]["action"] == "ALLOW"
    assert results["replay_rows"][3]["action"] == "ALLOW"

    # Verify CSV files export
    sub_files = engine.generate_submission_files(df, output_dir=tmp_path)
    assert sub_files["classification"].is_file()
    assert sub_files["policy"].is_file()
    assert sub_files["replay"].is_file()

    # Check header conformity
    class_header = sub_files["classification"].read_text().splitlines()[0]
    assert class_header == "record_id,predicted_class,anomaly score,evidence status"

    policy_header = sub_files["policy"].read_text().splitlines()[0]
    assert policy_header == "policy_id,activated_after_record_id,scope_type,scope_value,expires_after_record_id,policy_action"

    replay_header = sub_files["replay"].read_text().splitlines()[0]
    assert replay_header == "record_id,action,applied_policy_id"

