"""Train Agent 1 on organiser training data; validation is evaluation-only."""
import argparse
import json
from pathlib import Path
import pandas as pd
from .model import BENCHMARK_CLASSES, ThreatDetectionModel
from .metrics import evaluate_predictions

def load_label_mapping(path, observed_labels):
    """Accept only canonical labels or an explicit organiser-supplied mapping."""
    if path is None:
        observed = set(observed_labels)
        if not observed.issubset(set(BENCHMARK_CLASSES)):
            raise ValueError("Original dataset labels found. Supply the exact organiser mapping via --label-map; no mappings are guessed.")
        return {label: label for label in observed}
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    mapping = payload.get("mapping", payload) if isinstance(payload, dict) else None
    if not isinstance(mapping, dict) or not mapping:
        raise ValueError("Label mapping JSON must be a non-empty object.")
    mapping = {str(k): str(v) for k, v in mapping.items()}
    invalid = sorted(set(mapping.values()) - set(BENCHMARK_CLASSES))
    if invalid:
        raise ValueError(f"Mapping targets must be one of {BENCHMARK_CLASSES}; got {invalid}")
    unknown = sorted(set(observed_labels) - set(mapping))
    if unknown:
        raise ValueError(f"Unmapped dataset labels found: {unknown}")
    return mapping

def train_from_csv(train_csv, label_column, model_out="models/threat_detection.joblib",
                   label_map=None, validation_csv=None, validation_label_column=None,
                   backend="random_forest", n_estimators=400, random_state=42,
                   report_out="reports/generated/threat_detection_training.json"):
    frame = pd.read_csv(train_csv, low_memory=False)
    if label_column not in frame.columns:
        raise ValueError(f"Label column {label_column!r} not found in training CSV.")
    raw = frame[label_column].astype("string").str.strip()
    if raw.isna().any() or (raw == "").any():
        raise ValueError("Training CSV contains missing or empty target labels.")
    mapping = load_label_mapping(label_map, raw.unique().tolist())
    labels = raw.map(mapping)
    if labels.isna().any():
        raise ValueError("Some training labels were not mapped.")
    model = ThreatDetectionModel(backend=backend, n_estimators=n_estimators,
                                 random_state=random_state).fit(frame.drop(columns=[label_column]), labels.astype(str))
    model.save(model_out)
    result = {"model_path": str(model_out), "backend": backend, "training_rows": len(frame),
              "feature_count": len(model.feature_columns), "class_counts": model.metadata["class_counts"],
              "classes": list(BENCHMARK_CLASSES), "validation": None}
    if validation_csv:
        valid = pd.read_csv(validation_csv, low_memory=False)
        target = validation_label_column or label_column
        if target not in valid.columns:
            raise ValueError(f"Validation label column {target!r} not found.")
        raw_valid = valid[target].astype("string").str.strip()
        if raw_valid.isna().any():
            raise ValueError("Validation labels contain missing values.")
        unknown = sorted(set(raw_valid.unique()) - set(mapping))
        if unknown:
            raise ValueError(f"Unmapped validation labels: {unknown}")
        truth = raw_valid.map(mapping).astype(str).tolist()
        predicted = [p["predicted_class"] for p in model.predict_frame(valid.drop(columns=[target]))]
        result["validation"] = evaluate_predictions(truth, predicted)
    if report_out:
        destination = Path(report_out)
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(json.dumps(result, indent=2), encoding="utf-8")
    return result

def main():
    parser = argparse.ArgumentParser(description="Train CyberSentinel Agent 1.")
    parser.add_argument("--train-csv", required=True)
    parser.add_argument("--label-column", required=True)
    parser.add_argument("--model-out", default="models/threat_detection.joblib")
    parser.add_argument("--label-map")
    parser.add_argument("--validation-csv")
    parser.add_argument("--validation-label-column")
    parser.add_argument("--backend", choices=["random_forest", "xgboost"], default="random_forest")
    parser.add_argument("--n-estimators", type=int, default=400)
    parser.add_argument("--random-state", type=int, default=42)
    parser.add_argument("--report-out", default="reports/generated/threat_detection_training.json")
    args = parser.parse_args()
    result = train_from_csv(args.train_csv, args.label_column, args.model_out, args.label_map,
                            args.validation_csv, args.validation_label_column, args.backend,
                            args.n_estimators, args.random_state, args.report_out)
    print(json.dumps(result, indent=2))

if __name__ == "__main__":
    main()
