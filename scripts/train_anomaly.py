"""Train Agent 2 using BENIGN rows from the prepared training partition only."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

import pandas as pd

from cybersentinel.agents.anomaly_detection import AnomalyDetectionAgent


def load_frame(path: str) -> pd.DataFrame:
    return pd.read_parquet(path) if path.lower().endswith((".parquet", ".pq")) else pd.read_csv(path, low_memory=False)


def train_anomaly(train_path: str, model_out: str, report_out: str) -> dict:
    frame = load_frame(train_path)
    if "label" not in frame.columns:
        raise ValueError("Prepared training file must contain the canonical 'label' column.")
    labels = frame["label"].astype(str).str.strip()
    unexpected = sorted(set(labels.unique()) - {"BENIGN", "BRUTE_FORCE", "DOS", "DDOS", "PORT_SCAN"})
    if unexpected:
        raise ValueError(f"Unexpected benchmark labels: {unexpected}")
    benign = frame.loc[labels == "BENIGN"].drop(columns=["label"], errors="ignore")
    if benign.empty:
        raise ValueError("No BENIGN training rows available for anomaly baseline.")
    agent = AnomalyDetectionAgent().fit(benign)
    agent.save(model_out)
    report = {
        "agent": "anomaly_detection",
        "model_path": str(model_out),
        "training_scope": "BENIGN rows from training partition only",
        "training_rows": len(benign),
        "feature_count": len(agent.feature_columns),
        "threshold": agent.threshold,
        "metadata": agent.metadata,
        "evaluation": None,
        "note": "No official evaluation data was used to fit the detector or choose its threshold.",
    }
    target = Path(report_out)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(report, indent=2), encoding="utf-8")
    return report


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--train", required=True, help="Prepared training CSV or Parquet file")
    parser.add_argument("--model-out", default="models/anomaly_detection/model.joblib")
    parser.add_argument("--report-out", default="reports/generated/anomaly_training.json")
    args = parser.parse_args()
    print(json.dumps(train_anomaly(args.train, args.model_out, args.report_out), indent=2))


if __name__ == "__main__":
    main()
