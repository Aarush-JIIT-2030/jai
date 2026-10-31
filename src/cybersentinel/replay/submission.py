"""Official CSV Submission Exporter and Strict Semantic Validator.

Produces and verifies the three required competition files:
1. classification.csv
2. policies.csv
3. replay.csv
"""
from __future__ import annotations

import csv
import json
import ipaddress
import logging
from pathlib import Path
from typing import Any

logger = logging.getLogger("cybersentinel.replay.submission")

from cybersentinel.agents.correlation import TemporalCorrelationAgent

BENCHMARK_CLASSES = {"BENIGN", "BRUTE_FORCE", "DOS", "DDOS", "PORT_SCAN"}
EVIDENCE_STATUSES = {"AGREE", "CONFLICT", "UNCERTAIN"}
ACTIONS = {"ALLOW", "BLOCK"}


class SubmissionValidator:
    """Rigorous semantic and schema validator for Day 2 competition submissions."""

    @staticmethod
    def validate_classification(
        file_path: Path,
        expected_records: list[str | int],
    ) -> dict[str, Any]:
        issues: list[str] = []
        if not file_path.is_file():
            return {"valid": False, "errors": [f"File not found: {file_path}"]}

        seen_records = set()
        row_count = 0

        with file_path.open("r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            required_headers = ["record_id", "predicted_class", "anomaly_score", "evidence_status"]
            if reader.fieldnames != required_headers:
                issues.append(f"Header mismatch. Expected {required_headers}, found {reader.fieldnames}")

            for idx, row in enumerate(reader):
                row_count += 1
                rec_id = row.get("record_id")
                pred = row.get("predicted_class")
                score_str = row.get("anomaly_score") if "anomaly_score" in row else row.get("anomaly_score")
                ev_status = row.get("evidence_status") if "evidence_status" in row else row.get("evidence_status")

                if rec_id in seen_records:
                    issues.append(f"Row {idx}: Duplicate record_id '{rec_id}'")
                seen_records.add(rec_id)

                if pred not in BENCHMARK_CLASSES:
                    issues.append(f"Row {idx}: Invalid predicted_class '{pred}'")

                try:
                    score = float(score_str)
                    if not (0.0 <= score <= 1.0):
                        issues.append(f"Row {idx}: Anomaly score must be within [0,1]: {score}")
                except (ValueError, TypeError):
                    issues.append(f"Row {idx}: Non-numeric anomaly score '{score_str}'")

                if ev_status not in EVIDENCE_STATUSES:
                    issues.append(f"Row {idx}: Invalid evidence status '{ev_status}'")

        if len(expected_records) != row_count:
            issues.append(f"Row count mismatch: expected {len(expected_records)}, got {row_count}")

        return {
            "file": file_path.name,
            "valid": len(issues) == 0,
            "row_count": row_count,
            "errors": issues[:15],
            "total_errors": len(issues),
        }

    @staticmethod
    def validate_policy(file_path: Path) -> dict[str, Any]:
        issues: list[str] = []
        if not file_path.is_file():
            return {"valid": False, "errors": [f"File not found: {file_path}"]}

        policies: dict[str, dict[str, Any]] = {}
        row_count = 0

        with file_path.open("r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            required_cols = [
                "policy_id", "activated_after_record_id", "scope_type",
                "scope_value", "expires_after_record_id"
            ]
            if reader.fieldnames != required_cols:
                issues.append(f"Header mismatch. Expected {required_cols}, found {reader.fieldnames}")

            for idx, row in enumerate(reader):
                row_count += 1
                pol_id = row.get("policy_id")
                scope_type = row.get("scope_type")

                if pol_id in policies:
                    issues.append(f"Row {idx}: Duplicate policy_id '{pol_id}'")
                policies[pol_id] = row

                if scope_type not in {"SOURCE_IP", "DESTINATION_IP", "SRC_DST_PAIR"}:
                    issues.append(f"Row {idx}: Unsupported scope_type '{scope_type}'")

                scope_value = str(row.get("scope_value", "")).strip()
                try:
                    if scope_type in {"SOURCE_IP", "DESTINATION_IP"}:
                        ipaddress.ip_address(scope_value)
                    elif scope_type == "SRC_DST_PAIR":
                        parts = scope_value.split("|")
                        if len(parts) != 2:
                            raise ValueError("expected source|destination")
                        ipaddress.ip_address(parts[0].strip())
                        ipaddress.ip_address(parts[1].strip())
                except ValueError:
                    issues.append(f"Row {idx}: scope_value does not match the literal IP format for {scope_type}.")

        return {
            "file": file_path.name,
            "valid": len(issues) == 0,
            "policy_count": row_count,
            "policies": policies,
            "errors": issues[:15],
            "total_errors": len(issues),
        }

    @staticmethod
    def validate_replay(
        file_path: Path,
        expected_records: list[str | int],
        valid_policies: dict[str, dict[str, Any]],
    ) -> dict[str, Any]:
        issues: list[str] = []
        if not file_path.is_file():
            return {"valid": False, "errors": [f"File not found: {file_path}"]}

        row_count = 0
        seen_records = set()
        allow_count = 0
        block_count = 0

        with file_path.open("r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            required_cols = ["record_id", "action", "active_policy_id"]
            if reader.fieldnames != required_cols:
                issues.append(f"Header mismatch. Expected {required_cols}, found {reader.fieldnames}")

            for idx, row in enumerate(reader):
                row_count += 1
                rec_id = row.get("record_id")
                action = row.get("action")
                applied_pol = row.get("active_policy_id", "").strip()

                if rec_id in seen_records:
                    issues.append(f"Row {idx}: Duplicate record_id '{rec_id}'")
                seen_records.add(rec_id)

                if action not in ACTIONS:
                    issues.append(f"Row {idx}: Invalid action '{action}'")

                if action == "ALLOW":
                    allow_count += 1
                    if applied_pol != "":
                        issues.append(f"Row {idx}: ALLOW action must use active_policy_id=NONE, got '{applied_pol}'")
                elif action == "BLOCK":
                    block_count += 1
                    if not applied_pol:
                        issues.append(f"Row {idx}: BLOCK action must reference a valid policy ID")
                    elif applied_pol not in valid_policies:
                        issues.append(f"Row {idx}: BLOCK references unknown policy '{applied_pol}'")

        if len(expected_records) != row_count:
            issues.append(f"Row count mismatch: expected {len(expected_records)}, got {row_count}")

        return {
            "file": file_path.name,
            "valid": len(issues) == 0,
            "row_count": row_count,
            "allow_count": allow_count,
            "block_count": block_count,
            "errors": issues[:15],
            "total_errors": len(issues),
        }

    @classmethod
    def validate_submission_bundle(
        cls,
        output_dir: Path,
        expected_records: list[str | int],
        source_frame: Any | None = None,
    ) -> dict[str, Any]:
        """Validate exact templates, endpoint scope, causal windows and policy tie-breaks."""
        class_res = cls.validate_classification(output_dir / "classification.csv", expected_records)
        policy_res = cls.validate_policy(output_dir / "policies.csv")
        replay_res = cls.validate_replay(output_dir / "replay.csv", expected_records, policy_res.get("policies", {}))
        expected = [str(value) for value in expected_records]
        positions = {record_id: index for index, record_id in enumerate(expected)}
        policy_map = policy_res.get("policies", {})
        replay_path = output_dir / "replay.csv"

        if source_frame is not None:
            if len(source_frame) != len(expected):
                replay_res["valid"] = False
                replay_res["errors"].append("Original hidden input row count does not match expected record IDs.")
                replay_res["total_errors"] += 1
            elif "record_id" not in source_frame.columns or source_frame["record_id"].astype(str).tolist() != expected:
                replay_res["valid"] = False
                replay_res["errors"].append("Original hidden input IDs/order do not match the expected organizer records.")
                replay_res["total_errors"] += 1

        def observed_scope(row: Any, scope_type: str) -> str:
            def endpoint(columns: tuple[str, ...]) -> str:
                for column in columns:
                    if column in row:
                        try:
                            return str(ipaddress.ip_address(str(row.get(column)).strip()))
                        except (ValueError, TypeError):
                            continue
                return ""
            source = endpoint(("source_ip", "Source IP", "Source_IP", "src_ip", "src"))
            destination = endpoint(("destination_ip", "Destination IP", "Destination_IP", "dst_ip", "dst"))
            if scope_type == "SOURCE_IP":
                return source
            if scope_type == "DESTINATION_IP":
                return destination
            if scope_type == "SRC_DST_PAIR":
                return f"{source}|{destination}" if source and destination else ""
            return ""

        valid_policy_windows = []
        for policy_id, policy in policy_map.items():
            activation = str(policy.get("activated_after_record_id", ""))
            expiry = str(policy.get("expires_after_record_id", ""))
            if activation not in positions or expiry not in positions:
                policy_res["valid"] = False
                policy_res["errors"].append(f"Policy {policy_id}: activation/expiry record ID is absent from input.")
                policy_res["total_errors"] += 1
                continue
            start_pos, end_pos = positions[activation], positions[expiry]
            if start_pos >= end_pos:
                policy_res["valid"] = False
                policy_res["errors"].append(f"Policy {policy_id}: expiry must follow activation.")
                policy_res["total_errors"] += 1
                continue
            if source_frame is not None:
                trigger_scope = observed_scope(source_frame.iloc[start_pos], str(policy.get("scope_type", "")))
                if not trigger_scope or trigger_scope != str(policy.get("scope_value", "")).strip():
                    policy_res["valid"] = False
                    policy_res["errors"].append(f"Policy {policy_id}: scope_value does not match observed endpoints on its activation record.")
                    policy_res["total_errors"] += 1
                    continue
            valid_policy_windows.append({
                "policy_id": policy_id,
                "scope_type": str(policy.get("scope_type", "")),
                "scope_value": str(policy.get("scope_value", "")).strip(),
                "start": start_pos,
                "end": end_pos,
            })

        if replay_path.is_file():
            with replay_path.open("r", encoding="utf-8", newline="") as handle:
                replay_rows = list(csv.DictReader(handle))
            for position, row in enumerate(replay_rows):
                rid = str(row.get("record_id", ""))
                action = row.get("action", "")
                active_id = str(row.get("active_policy_id", "")).strip()
                matches = []
                if source_frame is not None and position < len(source_frame):
                    flow = source_frame.iloc[position]
                    for policy in valid_policy_windows:
                        if policy["start"] < position <= policy["end"]:
                            scope = observed_scope(flow, policy["scope_type"])
                            if scope and scope == policy["scope_value"]:
                                matches.append(policy["policy_id"])
                expected_id = min(matches) if matches else ""
                if action == "ALLOW":
                    if active_id != "":
                        replay_res["valid"] = False
                        replay_res["errors"].append(f"Record {rid}: ALLOW must use active_policy_id=NONE.")
                        replay_res["total_errors"] += 1
                    if source_frame is not None and matches:
                        replay_res["valid"] = False
                        replay_res["errors"].append(f"Record {rid}: ALLOW is invalid because active policy {expected_id} matches.")
                        replay_res["total_errors"] += 1
                elif action == "BLOCK":
                    if active_id not in policy_map:
                        continue
                    policy = policy_map[active_id]
                    activation = str(policy.get("activated_after_record_id", ""))
                    expiry = str(policy.get("expires_after_record_id", ""))
                    if activation in positions and expiry in positions and not (positions[activation] < positions.get(rid, -1) <= positions[expiry]):
                        replay_res["valid"] = False
                        replay_res["errors"].append(f"Record {rid}: policy {active_id} is not active at this replay position.")
                        replay_res["total_errors"] += 1
                    if source_frame is not None:
                        if not matches:
                            replay_res["valid"] = False
                            replay_res["errors"].append(f"Record {rid}: BLOCK has no matching active observed-endpoint policy.")
                            replay_res["total_errors"] += 1
                        elif active_id != expected_id:
                            replay_res["valid"] = False
                            replay_res["errors"].append(f"Record {rid}: BLOCK must use lexicographically smallest matching policy {expected_id}.")
                            replay_res["total_errors"] += 1

        all_valid = class_res["valid"] and policy_res["valid"] and replay_res["valid"]
        report = {
            "all_valid": all_valid,
            "status": "READY_FOR_SUBMISSION" if all_valid else "VALIDATION_FAILED",
            "classification": class_res,
            "policies": policy_res,
            "replay": replay_res,
        }
        report_file = output_dir / "validation_report.json"
        report_file.write_text(json.dumps(report, indent=2), encoding="utf-8")
        return report
