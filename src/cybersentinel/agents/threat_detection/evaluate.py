"""Five-class evaluation: accuracy, macro-F1, class metrics and confusion matrix."""
import argparse, json
from pathlib import Path
import pandas as pd
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix, f1_score, precision_recall_fscore_support
from .model import BENCHMARK_CLASSES, ThreatDetectionModel
from .train import load_label_mapping

def evaluate_predictions(y_true, y_pred):
    if len(y_true) != len(y_pred) or not y_true:
        raise ValueError("Evaluation requires equally sized, non-empty lists.")
    precision, recall, f1, support = precision_recall_fscore_support(
        y_true, y_pred, labels=list(BENCHMARK_CLASSES), zero_division=0)
    per_class = {label: {"precision": float(precision[i]), "recall": float(recall[i]),
                         "f1": float(f1[i]), "support": int(support[i])}
                 for i, label in enumerate(BENCHMARK_CLASSES)}
    return {"accuracy": float(accuracy_score(y_true, y_pred)),
            "macro_f1": float(f1_score(y_true, y_pred, labels=list(BENCHMARK_CLASSES),
                                       average="macro", zero_division=0)),
            "per_class": per_class,
            "classification_report": classification_report(
                y_true, y_pred, labels=list(BENCHMARK_CLASSES), output_dict=True, zero_division=0),
            "confusion_matrix": confusion_matrix(
                y_true, y_pred, labels=list(BENCHMARK_CLASSES)).tolist(),
            "class_order": list(BENCHMARK_CLASSES), "evaluation_rows": len(y_true)}

def evaluate_csv(model_path, validation_csv, label_column, label_map=None, report_out=None):
    frame = pd.read_csv(validation_csv, low_memory=False)
    if label_column not in frame.columns:
        raise ValueError(f"Label column {label_column!r} not found.")
    raw = frame[label_column].astype("string").str.strip()
    if raw.isna().any():
        raise ValueError("Validation labels contain missing values.")
    mapping = load_label_mapping(label_map, raw.unique().tolist())
    truth = raw.map(mapping).astype(str).tolist()
    model = ThreatDetectionModel.load(model_path)
    predictions = [p["predicted_class"] for p in model.predict_frame(frame.drop(columns=[label_column]))]
    report = evaluate_predictions(truth, predictions)
    report["model"] = {"backend": model.backend,
                       "training_rows": model.metadata.get("training_rows"),
                       "feature_count": len(model.feature_columns)}
    if report_out:
        path = Path(report_out)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    return report

def main():
    parser = argparse.ArgumentParser(description="Evaluate a saved Agent 1 model.")
    parser.add_argument("--model", required=True)
    parser.add_argument("--validation-csv", required=True)
    parser.add_argument("--label-column", required=True)
    parser.add_argument("--label-map")
    parser.add_argument("--report-out", default="reports/generated/threat_detection_evaluation.json")
    args = parser.parse_args()
    print(json.dumps(evaluate_csv(args.model, args.validation_csv, args.label_column,
                                  args.label_map, args.report_out), indent=2))

if __name__ == "__main__":
    main()
