import csv
import json
from pathlib import Path
from cybersentinel.replay.submission import SubmissionValidator
from cybersentinel.storage.history_db import init_db, record_run, list_runs


def test_submission_validator_valid_bundle(tmp_path):
    sub_dir = tmp_path / "submission"
    sub_dir.mkdir()

    # 1. classification.csv
    with (sub_dir / "classification.csv").open("w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["record_id", "predicted_class", "anomaly_score", "evidence_status"])
        writer.writerow(["rec-1", "BENIGN", "0.01000", "AGREE"])
        writer.writerow(["rec-2", "DOS", "0.85000", "AGREE"])

    # 2. policy.csv
    with (sub_dir / "policy.csv").open("w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["policy_id", "activated_after_record_id", "scope_type", "scope_value", "expires_after_record_id", "policy_action"])
        writer.writerow(["POL-00001", "rec-1", "SOURCE_IP", "10.0.0.99", "rec-2", "BLOCK"])

    # 3. replay.csv
    with (sub_dir / "replay.csv").open("w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["record_id", "action", "applied_policy_id"])
        writer.writerow(["rec-1", "ALLOW", ""])
        writer.writerow(["rec-2", "BLOCK", "POL-00001"])

    report = SubmissionValidator.validate_submission_bundle(sub_dir, ["rec-1", "rec-2"])
    assert report["all_valid"] is True
    assert report["status"] == "READY_FOR_SUBMISSION"
    assert (sub_dir / "validation_report.json").is_file()


def test_submission_validator_catches_invalid_class(tmp_path):
    sub_dir = tmp_path / "submission"
    sub_dir.mkdir()

    with (sub_dir / "classification.csv").open("w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["record_id", "predicted_class", "anomaly_score", "evidence_status"])
        writer.writerow(["rec-1", "UNKNOWN_ATTACK", "0.01000", "AGREE"])

    with (sub_dir / "policy.csv").open("w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["policy_id", "activated_after_record_id", "scope_type", "scope_value", "expires_after_record_id", "policy_action"])

    with (sub_dir / "replay.csv").open("w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["record_id", "action", "applied_policy_id"])
        writer.writerow(["rec-1", "ALLOW", ""])

    report = SubmissionValidator.validate_submission_bundle(sub_dir, ["rec-1"])
    assert report["all_valid"] is False
    assert report["status"] == "VALIDATION_FAILED"


def test_submission_validator_accepts_underscore_headers(tmp_path):
    sub_dir = tmp_path / "submission_underscore"
    sub_dir.mkdir()

    with (sub_dir / "classification.csv").open("w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["record_id", "predicted_class", "anomaly_score", "evidence_status"])
        writer.writerow(["rec-1", "BENIGN", "0.01000", "AGREE"])

    with (sub_dir / "policy.csv").open("w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["policy_id", "activated_after_record_id", "scope_type", "scope_value", "expires_after_record_id", "policy_action"])

    with (sub_dir / "replay.csv").open("w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["record_id", "action", "applied_policy_id"])
        writer.writerow(["rec-1", "ALLOW", ""])

    report = SubmissionValidator.validate_submission_bundle(sub_dir, ["rec-1"])
    assert report["all_valid"] is True
    assert report["status"] == "READY_FOR_SUBMISSION"


def test_sqlite_history_db(tmp_path):
    db_file = tmp_path / "test_history.db"
    init_db(db_file)

    run = record_run(
        run_id="RUN-TEST-001",
        dataset_name="eval_prepared.parquet",
        total_records=100,
        blocked_records=10,
        allowed_records=90,
        policies_created=5,
        containment_rate=95.0,
        throughput_fps=1200.0,
        elapsed_seconds=0.08,
        db_path=db_file,
    )
    assert run["id"] == "RUN-TEST-001"

    runs = list_runs(limit=10, db_path=db_file)
    assert len(runs) == 1
    assert runs[0]["id"] == "RUN-TEST-001"
    assert runs[0]["total_records"] == 100

# Independent organizer-contract validator regression tests.
import pandas as pd
from scripts.validate_submissions import validate as validate_official_csvs


def _write_official_bundle(tmp_path):
    pd.DataFrame({"record_id": [101, 102, 103], "source_ip": ["192.0.2.1", "192.0.2.1", "192.0.2.2"]}).to_csv(tmp_path / "input.csv", index=False)
    pd.DataFrame([
        [101, "DOS", 0.1, "AGREE"], [102, "DOS", 0.2, "AGREE"], [103, "BENIGN", 0.1, "AGREE"],
    ], columns=["record_id", "predicted_class", "anomaly_score", "evidence_status"]).to_csv(tmp_path / "classification.csv", index=False)
    pd.DataFrame([
        ["POL-00001", 101, "SOURCE_IP", "192.0.2.1", 103, "BLOCK"],
    ], columns=["policy_id", "activated_after_record_id", "scope_type", "scope_value", "expires_after_record_id", "policy_action"]).to_csv(tmp_path / "policy.csv", index=False)
    pd.DataFrame([
        [101, "ALLOW", ""], [102, "BLOCK", "POL-00001"], [103, "ALLOW", ""],
    ], columns=["record_id", "action", "applied_policy_id"]).to_csv(tmp_path / "replay.csv", index=False)
    return tmp_path / "input.csv"


def test_independent_official_csv_validator_accepts_valid_bundle(tmp_path):
    input_path = _write_official_bundle(tmp_path)
    assert validate_official_csvs(input_path, tmp_path) == []


def test_independent_official_csv_validator_rejects_fingerprint_scope(tmp_path):
    input_path = _write_official_bundle(tmp_path)
    policies = pd.read_csv(tmp_path / "policy.csv")
    policies.loc[0, "scope_value"] = "10.1.2.3"
    policies.to_csv(tmp_path / "policy.csv", index=False)
    assert any("does not match the observed SOURCE_IP" in error for error in validate_official_csvs(input_path, tmp_path))


def test_independent_official_csv_validator_rejects_block_before_activation(tmp_path):
    input_path = _write_official_bundle(tmp_path)
    replay = pd.read_csv(tmp_path / "replay.csv", keep_default_na=False)
    replay.loc[0, ["action", "applied_policy_id"]] = ["BLOCK", "POL-00001"]
    replay.to_csv(tmp_path / "replay.csv", index=False)
    assert any("outside its activation-exclusive/expiry-inclusive window" in error for error in validate_official_csvs(input_path, tmp_path))


def test_bundle_validator_rejects_blocked_record_with_different_observed_source_ip(tmp_path):
    sub_dir = tmp_path / "source_mismatch"
    sub_dir.mkdir()
    pd.DataFrame([
        ["rec-1", "DOS", 0.1, "AGREE"],
        ["rec-2", "DOS", 0.2, "AGREE"],
    ], columns=["record_id", "predicted_class", "anomaly_score", "evidence_status"]).to_csv(sub_dir / "classification.csv", index=False)
    pd.DataFrame([
        ["POL-00001", "rec-1", "SOURCE_IP", "192.0.2.10", "rec-2", "BLOCK"],
    ], columns=["policy_id", "activated_after_record_id", "scope_type", "scope_value", "expires_after_record_id", "policy_action"]).to_csv(sub_dir / "policy.csv", index=False)
    pd.DataFrame([
        ["rec-1", "ALLOW", ""],
        ["rec-2", "BLOCK", "POL-00001"],
    ], columns=["record_id", "action", "applied_policy_id"]).to_csv(sub_dir / "replay.csv", index=False)
    source = pd.DataFrame({"record_id": ["rec-1", "rec-2"], "source_ip": ["192.0.2.10", "192.0.2.11"]})

    report = SubmissionValidator.validate_submission_bundle(sub_dir, ["rec-1", "rec-2"], source_frame=source)

    assert report["all_valid"] is False
    assert any("does not match the input's observed SOURCE_IP scope" in error for error in report["replay"]["errors"])

def test_independent_official_csv_validator_rejects_fingerprint_derived_source_scope(tmp_path):
    fingerprint = {
        "Init_Win_bytes_forward": 64240,
        "min_seg_size_forward": 20,
        "Fwd Header Length": 40,
    }
    input_frame = pd.DataFrame([
        {"record_id": 201, **fingerprint},
        {"record_id": 202, **fingerprint},
    ])
    input_path = tmp_path / "fingerprint-input.csv"
    input_frame.to_csv(input_path, index=False)
    pd.DataFrame([
        [201, "DOS", 0.1, "AGREE"], [202, "DOS", 0.2, "AGREE"],
    ], columns=["record_id", "predicted_class", "anomaly_score", "evidence_status"]).to_csv(tmp_path / "classification.csv", index=False)
    pd.DataFrame([
        ["POL-00001", 201, "SOURCE_IP", "10.1.2.3", 202],
    ], columns=["policy_id", "activated_after_record_id", "scope_type", "scope_value", "expires_after_record_id", "policy_action"]).to_csv(tmp_path / "policy.csv", index=False)
    pd.DataFrame([
        [201, "ALLOW", ""], [202, "BLOCK", "POL-00001"],
    ], columns=["record_id", "action", "applied_policy_id"]).to_csv(tmp_path / "replay.csv", index=False)
    errors = validate_official_csvs(input_path, tmp_path)
    assert any("does not match the observed SOURCE_IP" in error for error in errors)
