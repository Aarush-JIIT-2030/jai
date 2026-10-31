from pathlib import Path

import pandas as pd

from scripts.validate_submissions import validate


def write_bundle(tmp_path: Path):
    pd.DataFrame({"record_id": [101, 102, 103], "source_ip": ["192.0.2.1", "192.0.2.1", "192.0.2.2"]}).to_csv(tmp_path / "input.csv", index=False)
    pd.DataFrame([
        [101, "DOS", -0.1, "AGREE"],
        [102, "DOS", -0.2, "AGREE"],
        [103, "BENIGN", 0.1, "AGREE"],
    ], columns=["record_id", "predicted_class", "anomaly score", "evidence status"]).to_csv(tmp_path / "classification.csv", index=False)
    pd.DataFrame([
        ["POL-00001", 101, "SOURCE_IP", "192.0.2.1", 103, "BLOCK"],
    ], columns=["policy_id", "activated_after_record_id", "scope_type", "scope_value", "expires_after_record_id", "policy_action"]).to_csv(tmp_path / "policy.csv", index=False)
    pd.DataFrame([
        [101, "ALLOW", ""], [102, "BLOCK", "POL-00001"], [103, "ALLOW", ""],
    ], columns=["record_id", "action", "applied_policy_id"]).to_csv(tmp_path / "replay.csv", index=False)
    return tmp_path / "input.csv"


def test_valid_bundle_passes(tmp_path):
    input_path = write_bundle(tmp_path)
    assert validate(input_path, tmp_path) == []


def test_rejects_synthetic_policy_scope(tmp_path):
    input_path = write_bundle(tmp_path)
    policies = pd.read_csv(tmp_path / "policy.csv")
    policies.loc[0, "scope_value"] = "10.1.2.3"
    policies.to_csv(tmp_path / "policy.csv", index=False)
    assert any("source IP does not match" in e for e in validate(input_path, tmp_path))


def test_rejects_block_before_activation(tmp_path):
    input_path = write_bundle(tmp_path)
    replay = pd.read_csv(tmp_path / "replay.csv", keep_default_na=False)
    replay.loc[0, ["action", "applied_policy_id"]] = ["BLOCK", "POL-00001"]
    replay.to_csv(tmp_path / "replay.csv", index=False)
    assert any("not active" in e for e in validate(input_path, tmp_path))
