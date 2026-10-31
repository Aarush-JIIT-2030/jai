#!/usr/bin/env python3
"""Train both production agents from the authorized training partition only."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from cybersentinel.agents.anomaly_detection import AnomalyDetectionAgent
from cybersentinel.agents.threat_detection.model import BENCHMARK_CLASSES, ThreatDetectionModel
from cybersentinel.agents.threat_detection.train import train_from_csv
from scripts.train_anomaly import train_anomaly


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def train_models(
    training_path: Path,
    validation_path: Path | None,
    model_dir: Path,
    report_dir: Path,
    label_column: str = "label",
    backend: str = "random_forest",
    n_estimators: int = 400,
    max_benign_fpr: float = 0.02,
    label_map: Path | None = None,
) -> dict:
    if not training_path.is_file():
        raise FileNotFoundError(f"Training partition not found: {training_path}")
    if validation_path is not None and not validation_path.is_file():
        raise FileNotFoundError(f"Separate labelled validation partition not found: {validation_path}")
    if validation_path is not None and validation_path.resolve() == training_path.resolve():
        raise ValueError("Validation data must be a separate partition; training data cannot calibrate itself.")

    model_dir.mkdir(parents=True, exist_ok=True)
    report_dir.mkdir(parents=True, exist_ok=True)
    threat_model_path = model_dir / "threat_detection" / "model.joblib"
    anomaly_model_path = model_dir / "anomaly_detection" / "model.joblib"
    threat_report_path = report_dir / "threat_detection_training.json"
    anomaly_report_path = report_dir / "anomaly_training.json"

    threat_report = train_from_csv(
        str(training_path),
        label_column,
        str(threat_model_path),
        label_map=str(label_map) if label_map else None,
        validation_csv=str(validation_path) if validation_path else None,
        calibration_validation_csv=str(validation_path) if validation_path else None,
        report_out=str(threat_report_path),
        backend=backend,
        n_estimators=n_estimators,
    )
    anomaly_report = train_anomaly(
        str(training_path),
        str(anomaly_model_path),
        str(anomaly_report_path),
        validation_path=str(validation_path) if validation_path else None,
        max_benign_fpr=max_benign_fpr,
    )

    # Reload both persisted artifacts and verify their inference contracts.
    threat = ThreatDetectionModel.load(threat_model_path)
    anomaly = AnomalyDetectionAgent.load(anomaly_model_path)
    if set(threat.label_encoder.classes_) != set(BENCHMARK_CLASSES):
        raise RuntimeError("Reloaded Agent 1 artifact does not expose all five organizer classes.")
    if not threat.feature_columns or not anomaly.feature_columns:
        raise RuntimeError("Reloaded model artifact has an empty feature schema.")
    if threat.metadata.get("training_rows") != anomaly.metadata.get("training_rows") and not anomaly.metadata.get("training_rows"):
        raise RuntimeError("Agent 2 artifact training metadata is invalid.")

    manifest = {
        "status": "TRAINED_AND_RELOADED",
        "training_source": str(training_path),
        "training_sha256": _sha256(training_path),
        "validation_source": str(validation_path) if validation_path else None,
        "validation_sha256": _sha256(validation_path) if validation_path else None,
        "validation_used_for": (
            ["Agent 1 confidence temperature calibration and metrics", "Agent 2 anomaly threshold selection"]
            if validation_path else []
        ),
        "hidden_records_used_for_training_or_calibration": False,
        "agent_1": {
            "artifact": str(threat_model_path),
            "artifact_sha256": _sha256(threat_model_path),
            "backend": backend,
            "training_rows": threat.metadata.get("training_rows"),
            "features": len(threat.feature_columns),
            "classes": sorted(threat.label_encoder.classes_.tolist()),
            "confidence_calibrated": bool(threat.metadata.get("confidence_calibrated")),
            "report": str(threat_report_path),
        },
        "agent_2": {
            "artifact": str(anomaly_model_path),
            "artifact_sha256": _sha256(anomaly_model_path),
            "algorithm": anomaly.metadata.get("algorithm"),
            "training_rows": anomaly.metadata.get("training_rows"),
            "features": len(anomaly.feature_columns),
            "threshold": anomaly.threshold,
            "threshold_calibrated": anomaly_report.get("threshold_calibration") is not None,
            "report": str(anomaly_report_path),
        },
        "disclosure": (
            "Without a separate labelled validation partition, Agent 1 confidence remains uncalibrated "
            "and Agent 2 uses its training-only benign baseline threshold."
        ),
    }
    manifest_path = report_dir / "training_manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return manifest


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--train", type=Path, default=Path("data/raw/training/flows.parquet"))
    parser.add_argument("--validation", type=Path, help="Optional separate labelled validation CSV/Parquet; never pass the hidden input.")
    parser.add_argument("--label-column", default="label")
    parser.add_argument("--label-map", type=Path, help="Exact organizer-provided mapping JSON, required only if raw labels are not canonical.")
    parser.add_argument("--model-dir", type=Path, default=Path("models"))
    parser.add_argument("--report-dir", type=Path, default=Path("reports/generated"))
    parser.add_argument("--backend", choices=("random_forest", "xgboost"), default="random_forest")
    parser.add_argument("--n-estimators", type=int, default=400)
    parser.add_argument("--max-benign-fpr", type=float, default=0.02)
    args = parser.parse_args()
    if args.n_estimators < 10:
        parser.error("--n-estimators must be at least 10.")
    print(json.dumps(train_models(
        args.train, args.validation, args.model_dir, args.report_dir,
        label_column=args.label_column, backend=args.backend,
        n_estimators=args.n_estimators, max_benign_fpr=args.max_benign_fpr,
        label_map=args.label_map,
    ), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
