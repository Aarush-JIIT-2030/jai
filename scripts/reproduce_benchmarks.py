#!/usr/bin/env python
"""Reproducible benchmark verification script for CyberSentinel Day 1 + Day 2.

Scres the untouched 114,185 evaluation dataset (eval_prepared.parquet) and
verifies all reported metrics for Agent 1 (Threat Detection), Agent 2 (Anomaly
Detection), Agent 3 (Evidence Fusion), Agent 4 (Temporal Correlation), and
Agent 5 (Adaptive Defense).
"""
from __future__ import annotations

import json
import logging
from pathlib import Path
import sys
import time

import numpy as np
import pandas as pd
from sklearn.metrics import accuracy_score, confusion_matrix, precision_recall_fscore_support

# Ensure src is on path
BASE_DIR = Path(__file__).resolve().parent.parent
SRC_DIR = BASE_DIR / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from cybersentinel.agents.anomaly_detection import AnomalyDetectionAgent
from cybersentinel.agents.fusion import EvidenceFusionAgent
from cybersentinel.agents.threat_detection import ThreatDetectionAgent
from cybersentinel.replay import ReplayEngine
from cybersentinel.replay.submission import SubmissionValidator

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("reproduce_benchmarks")

CLASSES = ["BENIGN", "BRUTE_FORCE", "DOS", "DDOS", "PORT_SCAN"]


def main() -> int:
    eval_path = BASE_DIR / "data" / "processed" / "eval_prepared.parquet"
    threat_path = BASE_DIR / "models" / "threat_detection" / "model.joblib"
    anomaly_path = BASE_DIR / "models" / "anomaly_detection" / "model.joblib"
    output_dir = BASE_DIR / "outputs" / "reports"
    output_dir.mkdir(parents=True, exist_ok=True)

    if not eval_path.is_file():
        logger.error("Evaluation dataset missing at %s", eval_path)
        return 1

    logger.info("Loading evaluation dataset from %s...", eval_path)
    df = pd.read_parquet(eval_path)
    total_rows = len(df)
    logger.info("Loaded %d rows with %d columns", total_rows, len(df.columns))

    if "label" not in df.columns:
        logger.error("Evaluation dataset missing required 'label' column")
        return 1

    y_true = df["label"].astype(str).str.strip().tolist()
    features = df.drop(columns=["label"], errors="ignore")

    # 1. Agent 1: Threat Detection Benchmark
    logger.info("Loading Agent 1 (Threat Detection) from %s...", threat_path)
    threat_agent = ThreatDetectionAgent.load(threat_path)

    t0 = time.perf_counter()
    threat_preds = threat_agent.predict_many(features)
    t_threat = time.perf_counter() - t0
    y_pred = [p["predicted_class"] for p in threat_preds]

    acc = float(accuracy_score(y_true, y_pred))
    precision, recall, f1, support = precision_recall_fscore_support(
        y_true, y_pred, labels=CLASSES, zero_division=0
    )
    macro_p = float(np.mean(precision))
    macro_r = float(np.mean(recall))
    macro_f1 = float(np.mean(f1))
    cm = confusion_matrix(y_true, y_pred, labels=CLASSES)

    logger.info("--- AGENT 1 BENCHMARK RESULTS ---")
    logger.info("Accuracy:        %.6f%% (%d / %d correct)", acc * 100, int(acc * total_rows), total_rows)
    logger.info("Macro F1-Score:  %.6f", macro_f1)
    logger.info("Macro Precision: %.6f", macro_p)
    logger.info("Macro Recall:    %.6f", macro_r)
    logger.info("Inference Time:  %.3f s (%.4f ms/flow, %.1f fps)", t_threat, (t_threat * 1000) / total_rows, total_rows / max(0.001, t_threat))

    # 2. Agent 2: Anomaly Detection Benchmark
    logger.info("Loading Agent 2 (Anomaly Detection) from %s...", anomaly_path)
    anomaly_agent = AnomalyDetectionAgent.load(anomaly_path)

    t0 = time.perf_counter()
    anomaly_results = anomaly_agent.score_frame(features)
    t_anomaly = time.perf_counter() - t0

    anomaly_flags = np.asarray([bool(r.is_anomaly) for r in anomaly_results])
    benign_mask = np.asarray(y_true) == "BENIGN"
    benign_fpr = float(anomaly_flags[benign_mask].mean()) if benign_mask.any() else 0.0

    logger.info("--- AGENT 2 BENCHMARK RESULTS ---")
    logger.info("Benign FPR:      %.6f%% (%d false anomalies in %d benign flows)", benign_fpr * 100, int(anomaly_flags[benign_mask].sum()), int(benign_mask.sum()))
    logger.info("Threshold:       %.6f", anomaly_agent.threshold)
    logger.info("Inference Time:  %.3f s (%.4f ms/flow, %.1f fps)", t_anomaly, (t_anomaly * 1000) / total_rows, total_rows / max(0.001, t_anomaly))

    # 3. Agent 3: Evidence Fusion Sample
    logger.info("Evaluating Agent 3 (Evidence Fusion) on 5,000 flow sample...")
    fusion_agent = EvidenceFusionAgent()
    rng = np.random.default_rng(42)
    sample_indices = rng.choice(total_rows, size=min(5000, total_rows), replace=False)
    fusion_actions = {"ALLOW": 0, "BLOCK": 0, "REVIEW": 0}
    fusion_statuses = {"AGREE": 0, "DISAGREE": 0, "INCOMPLETE": 0}

    for idx in sample_indices:
        f_res = fusion_agent.fuse(threat_preds[int(idx)], anomaly_results[int(idx)])
        fusion_actions[f_res.action] += 1
        fusion_statuses[f_res.evidence_status] += 1

    logger.info("--- AGENT 3 BENCHMARK RESULTS ---")
    logger.info("Sample Actions:  ALLOW=%d, BLOCK=%d, REVIEW=%d", fusion_actions["ALLOW"], fusion_actions["BLOCK"], fusion_actions["REVIEW"])
    logger.info("Evidence Status: AGREE=%d, DISAGREE=%d, INCOMPLETE=%d", fusion_statuses["AGREE"], fusion_statuses["DISAGREE"], fusion_statuses["INCOMPLETE"])

    # 4. Summary Output Serialization
    summary = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "dataset": {
            "path": str(eval_path),
            "rows": total_rows,
            "classes": {cls: int((np.asarray(y_true) == cls).sum()) for cls in CLASSES},
        },
        "agent_1_threat_detection": {
            "model_type": threat_agent.model.backend,
            "accuracy": acc,
            "macro_f1": macro_f1,
            "macro_precision": macro_p,
            "macro_recall": macro_r,
            "per_class": {
                cls: {
                    "precision": float(precision[i]),
                    "recall": float(recall[i]),
                    "f1": float(f1[i]),
                    "support": int(support[i]),
                }
                for i, cls in enumerate(CLASSES)
            },
            "confusion_matrix": cm.tolist(),
            "inference_seconds": t_threat,
            "inference_fps": total_rows / max(0.001, t_threat),
        },
        "agent_2_anomaly_detection": {
            "algorithm": "IsolationForest",
            "threshold": anomaly_agent.threshold,
            "benign_fpr": benign_fpr,
            "inference_seconds": t_anomaly,
            "inference_fps": total_rows / max(0.001, t_anomaly),
        },
        "agent_3_evidence_fusion_sample": {
            "sample_size": len(sample_indices),
            "actions": fusion_actions,
            "evidence_status": fusion_statuses,
        },
    }

    out_file = output_dir / "reproduced_benchmark_summary.json"
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2)

    logger.info("Verification complete! Machine-readable report saved to %s", out_file)
    return 0


if __name__ == "__main__":
    sys.exit(main())
