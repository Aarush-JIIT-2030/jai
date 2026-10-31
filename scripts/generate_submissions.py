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
from validate_submissions import validate as validate_submission_bundle

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
        help="Output directory to save classification.csv, policies.csv, and replay.csv",
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

    limited_run = args.limit is not None and args.limit > 0 and args.limit < len(df)
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
        ["record_id", "predicted_class", "anomaly_score", "evidence_status"],
    )
    (args.output_dir / "classification.csv").write_text(class_csv, encoding="utf-8")
    logger.info("Wrote %s", args.output_dir / "classification.csv")

    # 2. policies.csv
    policy_csv = engine.export_csv(
        results["policy_rows"],
        ["policy_id", "activated_after_record_id", "scope_type", "scope_value", "expires_after_record_id"],
    )
    (args.output_dir / "policies.csv").write_text(policy_csv, encoding="utf-8")
    logger.info("Wrote %s", args.output_dir / "policies.csv")

    # 3. replay.csv
    replay_csv = engine.export_csv(
        results["replay_rows"],
        ["record_id", "action", "active_policy_id"],
    )
    (args.output_dir / "replay.csv").write_text(replay_csv, encoding="utf-8")
    logger.info("Wrote %s", args.output_dir / "replay.csv")

    # 4. Independently validate full submissions against the original input.
    summary = dict(results["metrics"])
    if limited_run:
        # A limited replay is useful for smoke testing, but can never be accepted
        # as a complete submission because it intentionally omits input records.
        validation = {"valid": False, "status": "SKIPPED_LIMITED_RUN", "errors": []}
        logger.warning("Submission validation skipped: --limit produced an intentionally incomplete replay.")
    else:
        errors = validate_submission_bundle(args.input, args.output_dir)
        validation = {"valid": not errors, "status": "PASSED" if not errors else "FAILED", "errors": errors}
        if errors:
            logger.error("Submission validation failed with %d issue(s).", len(errors))
            for error in errors[:30]:
                logger.error("- %s", error)
    validation_file = args.output_dir / "validation_report.json"
    validation_file.write_text(json.dumps(validation, indent=2), encoding="utf-8")
    logger.info("Wrote %s", validation_file)
    summary["submission_validation"] = validation

    # 5. summary.json
    summary_file = args.output_dir / "summary.json"
    summary_file.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    logger.info("Wrote %s", summary_file)

    if not validation["valid"]:
        logger.error("Replay generated files, but the output is not submission-ready.")
        return 2
    logger.info("Replay and independent submission validation completed. Summary metrics: %s", summary)
    return 0


if __name__ == "__main__":
    sys.exit(main())

