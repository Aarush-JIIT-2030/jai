"""Replay Engine & Submission Generator for CyberSentinel Level 2."""
from __future__ import annotations
import csv
from io import StringIO
import logging
from pathlib import Path
import time
from typing import Any, Callable
import pandas as pd
from cybersentinel.agents.adaptive_defense import AdaptiveDefenseAgent
from cybersentinel.agents.anomaly_detection import AnomalyDetectionAgent
from cybersentinel.agents.correlation import TemporalCorrelationAgent
from cybersentinel.agents.fusion import EvidenceFusionAgent
from cybersentinel.agents.threat_detection import ThreatDetectionAgent
from cybersentinel.contracts import AnomalyDetectionResult, ThreatDetectionResult

logger = logging.getLogger("cybersentinel.replay")

def _extract_field(obj: Any, name: str, default: Any = None) -> Any:
    val = obj.get(name) if isinstance(obj, dict) else getattr(obj, name, None)
    return val if val is not None else default

class ReplayEngine:
    """Full 5-agent causal replay orchestrator with high-throughput vectorized scoring."""
    def __init__(self, threat_agent: ThreatDetectionAgent, anomaly_agent: AnomalyDetectionAgent,
                 fusion_agent: EvidenceFusionAgent | None = None,
                 correlation_agent: TemporalCorrelationAgent | None = None,
                 defense_agent: AdaptiveDefenseAgent | None = None):
        self.threat_agent = threat_agent
        self.anomaly_agent = anomaly_agent
        self.fusion_agent = fusion_agent or EvidenceFusionAgent()
        self.correlation_agent = correlation_agent or TemporalCorrelationAgent()
        self.defense_agent = defense_agent or AdaptiveDefenseAgent()

    @classmethod
    def load_default(cls, threat_path="models/threat_detection/model.joblib",
                     anomaly_path="models/anomaly_detection/model.joblib"):
        threat_file, anomaly_file = Path(threat_path), Path(anomaly_path)
        if not threat_file.is_file() or not anomaly_file.is_file():
            raise FileNotFoundError(f"Model artifacts missing: {threat_file}, {anomaly_file}")
        return cls(ThreatDetectionAgent.load(threat_file), AnomalyDetectionAgent.load(anomaly_file),
                   EvidenceFusionAgent(), TemporalCorrelationAgent(), AdaptiveDefenseAgent())

    def run_replay(self, df: pd.DataFrame,
                   progress_callback: Callable[[int, int], None] | None = None) -> dict[str, Any]:
        """Execute causal chronological replay across all records in df."""
        self.correlation_agent.reset()
        self.defense_agent.reset()
        total_rows = len(df)
        if "seq" in df.columns:
            sequence = pd.to_numeric(df["seq"], errors="coerce")
            if sequence.isna().any() or sequence.duplicated().any() or not sequence.is_monotonic_increasing:
                raise ValueError("Organizer seq must be present, unique, numeric, and strictly increasing in input order.")
        record_ids = df["record_id"].tolist() if "record_id" in df.columns else list(range(total_rows))
        has_label = "label" in df.columns
        labels = df["label"].astype(str).str.strip().str.upper().tolist() if has_label else [""] * total_rows
        start_time = time.perf_counter()
        logger.info("Computing predictions for Agent 1 and Agent 2...")
        threat_preds = (self.threat_agent.predict_many(df) if hasattr(self.threat_agent, "predict_many")
                        else [self.threat_agent.predict(r.to_dict()) for _, r in df.iterrows()])
        anomaly_results = (self.anomaly_agent.score_frame(df) if hasattr(self.anomaly_agent, "score_frame")
                           else [self.anomaly_agent.score(r.to_dict()) for _, r in df.iterrows()])
        if len(threat_preds) != total_rows or len(anomaly_results) != total_rows:
            raise RuntimeError("Agent 1/2 batch output length does not match replay input.")

        dports = pd.to_numeric(df["Destination Port"], errors="coerce").fillna(0).where(lambda values: values.mod(1).eq(0), 0).clip(0, 65535).astype(int).tolist() if "Destination Port" in df.columns else [0] * total_rows
        src_col = next((c for c in ("source_ip", "Source IP", "Source_IP", "src_ip", "src") if c in df.columns), None)
        flow_records = df.to_dict(orient="records")
        native_src = [str(row.get(src_col, "")).strip() if src_col and pd.notna(row.get(src_col)) else "" for row in flow_records]
        corr_src = [native_src[i] or TemporalCorrelationAgent.derive_source_identity(row) for i, row in enumerate(flow_records)]
        dst_col = next((c for c in ("destination_ip", "Destination IP", "dst_ip", "dst", "Destination_IP") if c in df.columns), None)
        time_col = next((c for c in ("Timestamp", "timestamp", "Flow Start", "flow_start", "start_time") if c in df.columns), None)
        derived_timestamps = None
        if time_col is None and {"day", "time_offset"}.issubset(df.columns):
            dates = pd.to_datetime(df["day"], errors="coerce", utc=True)
            parts = df["time_offset"].astype(str).str.extract(r"^(?P<minutes>\\d+):(?P<seconds>\\d{1,2}(?:\\.\\d+)?)$")
            elapsed_seconds = (pd.to_numeric(parts["minutes"], errors="coerce") * 60 + pd.to_numeric(parts["seconds"], errors="coerce"))
            offsets = pd.to_timedelta(elapsed_seconds, unit="s")
            derived_timestamps = dates + offsets

        classification_rows, replay_rows = [], []
        blocked = allowed = contained = benign_preserved = false_blocks = 0
        for step in range(total_rows):
            record_id, src_ip, correlation_ip = record_ids[step], native_src[step], corr_src[step]
            ground_truth = labels[step]
            threat, anomaly = threat_preds[step], anomaly_results[step]
            t_class = _extract_field(threat, "predicted_class")
            t_conf = _extract_field(threat, "confidence")
            a_score = _extract_field(anomaly, "anomaly_score")
            pre_filter = self.defense_agent.evaluate_pre_filter(record_id, src_ip, step)
            threat_obj = ThreatDetectionResult(t_class, t_conf, status=_extract_field(threat, "status", "success"))
            anomaly_obj = AnomalyDetectionResult(
                a_score, _extract_field(anomaly, "is_anomaly"),
                evidence=_extract_field(anomaly, "evidence", []) or [],
                status=_extract_field(anomaly, "status", "success"),
            )
            fusion = self.fusion_agent.fuse(threat_obj, anomaly_obj)
            classification_rows.append({
                "record_id": record_id,
                "predicted_class": fusion.final_class or (t_class if t_class else ""),
                "anomaly_score": round(float(a_score), 5) if isinstance(a_score, (int, float)) else "",
                "evidence_status": fusion.evidence_status,
            })

            if pre_filter is not None:
                action, applied_id = "BLOCK", pre_filter.applied_policy_id or ""
                blocked += 1
                if ground_truth and ground_truth != "BENIGN":
                    contained += 1
                elif ground_truth == "BENIGN":
                    false_blocks += 1
            else:
                action, applied_id = "ALLOW", ""
                allowed += 1
                if ground_truth == "BENIGN":
                    benign_preserved += 1
                flow_summary = {"source_ip": correlation_ip, "Destination Port": dports[step]}
                if dst_col and pd.notna(flow_records[step].get(dst_col)):
                    flow_summary["destination_ip"] = str(flow_records[step][dst_col]).strip()
                if time_col and pd.notna(flow_records[step].get(time_col)):
                    flow_summary["Timestamp"] = flow_records[step][time_col]
                elif derived_timestamps is not None and pd.notna(derived_timestamps.iloc[step]):
                    flow_summary["Timestamp"] = derived_timestamps.iloc[step]
                correlation = self.correlation_agent.correlate(
                    record_id, flow_summary, threat_class=t_class, confidence=t_conf,
                )
                attack_detected = (
                    fusion.action == "BLOCK"
                    or (correlation.correlated and correlation.attack_type in ("PORT_SCAN", "DOS", "DDOS", "BRUTE_FORCE"))
                )
                # A policy must protect at least one later record. A final-row
                # trigger has no future target and cannot produce a valid expiry ID.
                if step < total_rows - 1:
                    duration = min(self.defense_agent.default_duration, total_rows - step - 1)
                    self.defense_agent.handle_post_analysis(
                        record_id=record_id, source_ip=src_ip, current_step=step,
                        attack_detected=attack_detected,
                        attack_type=correlation.attack_type or t_class or "ATTACK",
                        confidence=t_conf, duration=duration,
                    )
            replay_rows.append({"record_id": record_id, "action": action, "active_policy_id": applied_id})
            if progress_callback and (step % 25000 == 0 or step == total_rows - 1):
                progress_callback(step + 1, total_rows)

        elapsed = time.perf_counter() - start_time
        policy_rows = []
        for policy in self.defense_agent.all_policies:
            expiry_step = int(policy.expires_after_record_id)
            if expiry_step <= int(policy.created_at_step) or expiry_step >= total_rows:
                raise RuntimeError("Defense agent created a policy without a valid later expiry position.")
            policy_rows.append({
                "policy_id": policy.policy_id,
                "activated_after_record_id": policy.activated_after_record_id,
                "scope_type": policy.scope_type, "scope_value": policy.scope_value,
                "expires_after_record_id": record_ids[expiry_step],
                            })
        attack_count = sum(label != "BENIGN" for label in labels) if has_label else None
        benign_count = sum(label == "BENIGN" for label in labels) if has_label else None
        metrics = {
            "total_records": total_rows, "blocked_records": blocked, "allowed_records": allowed,
            "policies_created": len(policy_rows), "attacks_contained": contained,
            "attacks_allowed": max(0, attack_count - contained) if attack_count is not None else None,
            "attack_records": attack_count, "benign_records": benign_count,
            "benign_preserved": benign_preserved, "false_blocks": false_blocks,
            "containment_rate": round(contained / max(1, attack_count) * 100, 2) if attack_count is not None else None,
            "block_precision": round(contained / max(1, blocked) * 100, 2) if has_label else None,
            "benign_preservation_rate": round(benign_preserved / max(1, benign_count) * 100, 2) if benign_count is not None else None,
            "false_block_rate": round(false_blocks / max(1, benign_count) * 100, 2) if benign_count is not None else None,
            "elapsed_seconds": round(elapsed, 2),
            "throughput_fps": round(total_rows / max(0.001, elapsed), 1),
        }
        return {"classification_rows": classification_rows, "policy_rows": policy_rows,
                "replay_rows": replay_rows, "metrics": metrics}

    @staticmethod
    def export_csv(rows: list[dict[str, Any]], fieldnames: list[str]) -> str:
        output = StringIO()
        writer = csv.DictWriter(output, fieldnames=fieldnames, lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)
        return output.getvalue()

    def generate_submission_files(self, df: pd.DataFrame, output_dir: str | Path = "submissions") -> dict[str, Path]:
        out_path = Path(output_dir)
        out_path.mkdir(parents=True, exist_ok=True)
        results = self.run_replay(df)
        files = {
            "classification": (["record_id", "predicted_class", "anomaly_score", "evidence_status"], results["classification_rows"]),
            "policies": (["policy_id", "activated_after_record_id", "scope_type", "scope_value", "expires_after_record_id"], results["policy_rows"]),
            "replay": (["record_id", "action", "active_policy_id"], results["replay_rows"]),
        }
        paths = {}
        for name, (headers, rows) in files.items():
            path = out_path / f"{name}.csv"
            path.write_text(self.export_csv(rows, headers), encoding="utf-8")
            paths[name] = path
        logger.info("Generated submission files in %s", out_path)
        return paths
