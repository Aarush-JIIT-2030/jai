#!/usr/bin/env python3
"""Independent validator for the organiser's exact Level 2 CSV templates."""
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
SCOPES = {"SOURCE_IP", "DESTINATION_IP", "SRC_DST_PAIR"}

def _read(path: Path, expected: list[str]) -> pd.DataFrame:
    frame = pd.read_csv(path, dtype=str, keep_default_na=False)
    if list(frame.columns) != expected:
        raise ValueError(f"{path.name}: expected columns {expected}, got {list(frame.columns)}")
    return frame

def _ip(value: object) -> str:
    try:
        return str(ipaddress.ip_address(str(value).strip()))
    except (ValueError, TypeError):
        return ""

def _observed_scope(source: pd.DataFrame, position: int, scope_type: str) -> str:
    row = source.iloc[position]
    aliases = {
        "SOURCE_IP": ("source_ip", "Source IP", "Source_IP", "src_ip", "src"),
        "DESTINATION_IP": ("destination_ip", "Destination IP", "Destination_IP", "dst_ip", "dst"),
    }
    if scope_type == "SRC_DST_PAIR":
        src = next((_ip(row.get(c)) for c in aliases["SOURCE_IP"] if c in source.columns and _ip(row.get(c))), "")
        dst = next((_ip(row.get(c)) for c in aliases["DESTINATION_IP"] if c in source.columns and _ip(row.get(c))), "")
        return f"{src}|{dst}" if src and dst else ""
    return next((_ip(row.get(c)) for c in aliases.get(scope_type, ()) if c in source.columns and _ip(row.get(c))), "")

def validate(input_path: Path, output_dir: Path) -> list[str]:
    errors: list[str] = []
    source = pd.read_parquet(input_path) if input_path.suffix.lower() in {".parquet", ".pq"} else pd.read_csv(input_path)
    if "record_id" not in source:
        raise ValueError("Input must contain organiser-provided record_id.")
    ids = source["record_id"].astype(str).tolist()
    if len(ids) != len(set(ids)):
        errors.append("Input record_id values are not unique.")
    positions = {rid: i for i, rid in enumerate(ids)}

    classification = _read(output_dir / "classification.csv", CLASS_COLUMNS)
    policies = _read(output_dir / "policies.csv", POLICY_COLUMNS)
    replay = _read(output_dir / "replay.csv", REPLAY_COLUMNS)

    for name, frame in (("classification.csv", classification), ("replay.csv", replay)):
        got = frame["record_id"].astype(str).tolist()
        if got != ids:
            errors.append(f"{name}: record IDs must match the input exactly, once each, in original order.")
    if not set(classification["predicted_class"]).issubset(CLASSES):
        errors.append("classification.csv contains an invalid or missing predicted_class.")
    if not set(classification["evidence_status"]).issubset(EVIDENCE):
        errors.append("classification.csv contains an invalid or missing evidence_status.")
    scores = pd.to_numeric(classification["anomaly_score"], errors="coerce")
    if scores.isna().any() or not np.isfinite(scores.to_numpy(dtype=float)).all():
        errors.append("classification.csv contains missing or non-finite anomaly_score values.")

    policy_ids = policies["policy_id"].tolist()
    if any(not x for x in policy_ids) or len(policy_ids) != len(set(policy_ids)):
        errors.append("policies.csv policy IDs must be non-empty and unique.")
    policy_map = {row["policy_id"]: row for _, row in policies.iterrows()}
    for _, row in policies.iterrows():
        pid, scope_type, scope_value = row["policy_id"], row["scope_type"], row["scope_value"]
        if scope_type not in SCOPES:
            errors.append(f"Policy {pid}: unsupported scope_type {scope_type!r}.")
        if scope_type in {"SOURCE_IP", "DESTINATION_IP"} and not _ip(scope_value):
            errors.append(f"Policy {pid}: {scope_type} scope_value must be a literal IP.")
        if scope_type == "SRC_DST_PAIR":
            parts = scope_value.split("|")
            if len(parts) != 2 or not all(_ip(p) for p in parts):
                errors.append(f"Policy {pid}: SRC_DST_PAIR must be literal source|destination IPs.")
        activation, expiry = row["activated_after_record_id"], row["expires_after_record_id"]
        if activation not in positions or expiry not in positions:
            errors.append(f"Policy {pid}: activation/expiry record ID is absent from input.")
        elif positions[activation] >= positions[expiry]:
            errors.append(f"Policy {pid}: expiry must follow activation.")

    if replay["action"].isin(["ALLOW", "BLOCK"]).eq(False).any():
        errors.append("replay.csv contains an action other than ALLOW or BLOCK.")
    for _, row in replay.iterrows():
        rid, action, active_id = row["record_id"], row["action"], row["active_policy_id"]
        if action == "ALLOW" and active_id:
            errors.append(f"Record {rid}: ALLOW must have an empty active_policy_id.")
        elif action == "BLOCK":
            policy = policy_map.get(active_id)
            if not active_id or policy is None:
                errors.append(f"Record {rid}: BLOCK must reference a known policy_id.")
                continue
            if rid not in positions or policy["activated_after_record_id"] not in positions or policy["expires_after_record_id"] not in positions:
                continue
            pos = positions[rid]
            start = positions[policy["activated_after_record_id"]]
            end = positions[policy["expires_after_record_id"]]
            if not (start < pos <= end):
                errors.append(f"Record {rid}: policy {active_id} is outside its activation-exclusive/expiry-inclusive window.")
            scope_type = policy["scope_type"]
            observed = _observed_scope(source, pos, scope_type)
            expected_scope = policy["scope_value"]
            if scope_type in {"SOURCE_IP", "DESTINATION_IP"}:
                expected_scope = _ip(expected_scope)
            elif scope_type == "SRC_DST_PAIR":
                a, b = expected_scope.split("|") if "|" in expected_scope else ("", "")
                expected_scope = f"{_ip(a)}|{_ip(b)}"
            if not observed or observed != expected_scope:
                errors.append(f"Record {rid}: active policy {active_id} does not match the observed {scope_type}.")

    return errors

def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True, help="Organiser hidden replay input CSV or Parquet")
    parser.add_argument("--output-dir", type=Path, required=True, help="Directory containing classification.csv, policies.csv and replay.csv")
    args = parser.parse_args()
    errors = validate(args.input, args.output_dir)
    if errors:
        print("SUBMISSION VALIDATION FAILED")
        for error in errors: print(f"- {error}")
        return 1
    print("SUBMISSION VALIDATION PASSED")
    return 0

if __name__ == "__main__":
    sys.exit(main())
