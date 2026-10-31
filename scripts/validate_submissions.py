#!/usr/bin/env python3
"""Independent validator for CyberSentinel's three official replay CSVs."""
from __future__ import annotations

import argparse
import ipaddress
from pathlib import Path
import sys

import numpy as np
import pandas as pd

CLASSES = {"BENIGN", "BRUTE_FORCE", "DOS", "DDOS", "PORT_SCAN"}
EVIDENCE = {"AGREE", "DISAGREE", "INCOMPLETE"}
CLASS_COLUMNS = ["record_id", "predicted_class", "anomaly_score", "evidence_status"]
POLICY_COLUMNS = ["policy_id", "activated_after_record_id", "scope_type", "scope_value", "expires_after_record_id"]
REPLAY_COLUMNS = ["record_id", "action", "active_policy_id"]


def _read(path: Path, expected: list[str]) -> pd.DataFrame:
    frame = pd.read_csv(path, dtype=str, keep_default_na=False)
    if list(frame.columns) != expected:
        raise ValueError(f"{path.name}: expected columns {expected}, got {list(frame.columns)}")
    return frame


def validate(input_path: Path, output_dir: Path) -> list[str]:
    errors: list[str] = []
    source = pd.read_parquet(input_path) if input_path.suffix.lower() == ".parquet" else pd.read_csv(input_path)
    if "record_id" not in source:
        raise ValueError("Input must contain organizer-provided record_id.")
    ids = source["record_id"].astype(str).tolist()
    if len(ids) != len(set(ids)):
        errors.append("Input record_id values are not unique.")
    positions = {record_id: index for index, record_id in enumerate(ids)}

    classification = _read(output_dir / "classification.csv", CLASS_COLUMNS)
    policy = _read(output_dir / "policy.csv", POLICY_COLUMNS)
    replay = _read(output_dir / "replay.csv", REPLAY_COLUMNS)

    for name, frame in (("classification.csv", classification), ("replay.csv", replay)):
        got = frame["record_id"].astype(str).tolist()
        if len(got) != len(ids):
            errors.append(f"{name}: expected {len(ids)} rows, got {len(got)}.")
        if len(got) != len(set(got)):
            errors.append(f"{name}: duplicate record IDs.")
        if got != ids:
            errors.append(f"{name}: record IDs must match input exactly and in original order.")

    if not set(classification["predicted_class"]).issubset(CLASSES):
        errors.append("classification.csv contains an invalid or missing predicted_class.")
    if not set(classification["evidence status"]).issubset(EVIDENCE):
        errors.append("classification.csv contains an invalid or missing evidence status.")
    scores = pd.to_numeric(classification["anomaly score"], errors="coerce")
    if scores.isna().any() or not np.isfinite(scores.to_numpy(dtype=float)).all():
        errors.append("classification.csv contains missing or non-finite anomaly scores.")

    policy_ids = policy["policy_id"].tolist()
    if any(not value for value in policy_ids) or len(policy_ids) != len(set(policy_ids)):
        errors.append("policy.csv policy IDs must be non-empty and unique.")
    policy_by_id = {row["policy_id"]: row for _, row in policy.iterrows()}
    for _, row in policy.iterrows():
        if row["scope_type"] not in {"SOURCE_IP", "DESTINATION_IP", "SRC_DST_PAIR"}:
            errors.append(f"Policy {row['policy_id']}: scope_type must be SOURCE_IP and action must be BLOCK.")
        try:
            ipaddress.ip_address(row["scope_value"])
        except ValueError:
            errors.append(f"Policy {row['policy_id']}: scope_value is not a literal IP address.")
        activation, expiry = row["activated_after_record_id"], row["expires_after_record_id"]
        if activation not in positions:
            errors.append(f"Policy {row['policy_id']}: activation record is absent from replay input.")
        if expiry not in positions:
            errors.append(f"Policy {row['policy_id']}: expiry record is absent from replay input.")
        if activation in positions and expiry in positions and positions[activation] >= positions[expiry]:
            errors.append(f"Policy {row['policy_id']}: expiry must follow activation.")

    for _, row in replay.iterrows():
        action, applied, rid = row["action"], row["active_policy_id"], row["record_id"]
        if action not in {"ALLOW", "BLOCK"}:
            errors.append(f"Record {rid}: action must be ALLOW or BLOCK.")
        if action == "ALLOW" and applied:
            errors.append(f"Record {rid}: ALLOW must have empty applied_policy_id.")
        if action == "BLOCK":
            if not applied or applied not in policy_by_id:
                errors.append(f"Record {rid}: BLOCK must reference a known policy.")
                continue
            pol = policy_by_id[applied]
            activation, expiry = pol["activated_after_record_id"], pol["expires_after_record_id"]
            if rid not in positions or activation not in positions or expiry not in positions:
                continue
            if not (positions[activation] < positions[rid] <= positions[expiry]):
                errors.append(f"Record {rid}: applied policy {applied} is not active at this position.")
            src = ""
            for column in ("source_ip", "Source IP", "Source_IP", "src_ip", "src"):
                if column in source.columns:
                    src = str(source.iloc[positions[rid]][column]).strip()
                    break
            try:
                observed_ip = str(ipaddress.ip_address(src))
                policy_ip = str(ipaddress.ip_address(pol["scope_value"]))
            except ValueError:
                observed_ip = ""
                policy_ip = ""
            if not observed_ip or observed_ip != policy_ip:
                errors.append(f"Record {rid}: applied policy {applied} source IP does not match an observed input IP.")
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True, help="Organizer input CSV or Parquet")
    parser.add_argument("--output-dir", type=Path, required=True, help="Directory containing the three CSVs")
    args = parser.parse_args()
    errors = validate(args.input, args.output_dir)
    if errors:
        print("SUBMISSION VALIDATION FAILED")
        for error in errors:
            print(f"- {error}")
        return 1
    print("SUBMISSION VALIDATION PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
