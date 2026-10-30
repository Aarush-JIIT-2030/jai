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
        writer.writerow(["record_id", "predicted_class", "anomaly score", "evidence status"])
        writer.writerow(["rec-1", "BENIGN", "0.01000", "AGREE"])
        writer.writerow(["rec-2", "DOS", "0.85000", "AGREE"])

    # 2. policy.csv
    with (sub_dir / "policy.csv").open("w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["policy_id", "activated_after_record_id", "scope_type", "scope_value", "expires_after_record_id", "policy_action"])
        writer.writerow(["POL-00001", "rec-2", "SOURCE_IP", "10.0.0.99", "150", "BLOCK"])

    # 3. replay.csv
    with (sub_dir / "replay.csv").open("w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["record_id", "action", "applied_policy_id"])
        writer.writerow(["rec-1", "ALLOW", ""])
        writer.writerow(["rec-2", "ALLOW", ""])

    report = SubmissionValidator.validate_submission_bundle(sub_dir, ["rec-1", "rec-2"])
    assert report["all_valid"] is True
    assert report["status"] == "READY_FOR_SUBMISSION"
    assert (sub_dir / "validation_report.json").is_file()


def test_submission_validator_catches_invalid_class(tmp_path):
    sub_dir = tmp_path / "submission"
    sub_dir.mkdir()

    with (sub_dir / "classification.csv").open("w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["record_id", "predicted_class", "anomaly score", "evidence status"])
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
