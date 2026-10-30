#!/usr/bin/env python
"""CLI tool to run chronological replay and generate the 3 official submission CSVs."""
from __future__ import annotations

import argparse
import json
import logging
from pathlib import Path
import sys

import pandas as pd

from cybersentinel.replay import ReplayEngine

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("generate_submissions")


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate CyberSentinel Level 2 submission files.")
    parser.add_argument(
        "--input",
        type=Path,
        default=Path("data/processed/eval_prepared.parquet"),
        help="Path to input test/eval dataset (parquet or csv)",
    )
    parser.add_argument(
        "--threat-model",
        type=Path,
        default=Path("models/threat_detection/model.joblib"),
        help="Path to trained Agent 1 model",
    )
    parser.add_argument(
        "--anomaly-model",
        type=Path,
        default=Path("models/anomaly_detection/model.joblib"),
        help="Path to trained Agent 2 model",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("submissions"),
        help="Output directory to save classification.csv, policy.csv, and replay.csv",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=None,
        help="Optional limit on rows for quick testing",
    )
    args = parser.parse_args()

    if not args.input.is_file():
        logger.error("Input file not found: %s", args.input)
        return 1

    logger.info("Loading input data from %s...", args.input)
    if args.input.suffix.lower() == ".parquet":
        df = pd.read_parquet(args.input)
    else:
        df = pd.read_csv(args.input)

    if args.limit and args.limit > 0:
        logger.info("Limiting replay to first %d records", args.limit)
        df = df.iloc[:args.limit]

    logger.info("Initializing 5-agent ReplayEngine...")
    engine = ReplayEngine.load_default(
        threat_path=args.threat_model,
        anomaly_path=args.anomaly_model,
    )

    def on_progress(done: int, total: int) -> None:
        pct = done / total * 100
        logger.info("Replay progress: %d/%d records (%.1f%%)", done, total, pct)

    logger.info("Starting chronological replay on %d records...", len(df))
    results = engine.run_replay(df, progress_callback=on_progress)

    args.output_dir.mkdir(parents=True, exist_ok=True)

    # 1. classification.csv
    class_csv = engine.export_csv(
        results["classification_rows"],
        ["record_id", "predicted_class", "anomaly score", "evidence status"],
    )
    (args.output_dir / "classification.csv").write_text(class_csv, encoding="utf-8")
    logger.info("Wrote %s", args.output_dir / "classification.csv")

    # 2. policy.csv
    policy_csv = engine.export_csv(
        results["policy_rows"],
        ["policy_id", "activated_after_record_id", "scope_type", "scope_value", "expires_after_record_id", "policy_action"],
    )
    (args.output_dir / "policy.csv").write_text(policy_csv, encoding="utf-8")
    logger.info("Wrote %s", args.output_dir / "policy.csv")

    # 3. replay.csv
    replay_csv = engine.export_csv(
        results["replay_rows"],
        ["record_id", "action", "applied_policy_id"],
    )
    (args.output_dir / "replay.csv").write_text(replay_csv, encoding="utf-8")
    logger.info("Wrote %s", args.output_dir / "replay.csv")

    # 4. summary.json
    summary_file = args.output_dir / "summary.json"
    summary_file.write_text(json.dumps(results["metrics"], indent=2), encoding="utf-8")
    logger.info("Wrote %s", summary_file)

    logger.info("Replay completed successfully! Summary metrics: %s", results["metrics"])
    return 0


if __name__ == "__main__":
    sys.exit(main())

