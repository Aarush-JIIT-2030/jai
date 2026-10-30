"""Shared metrics for the supervised threat-detection workstream."""
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_recall_fscore_support,
)
from .model import BENCHMARK_CLASSES

def evaluate_predictions(y_true, y_pred):
    if len(y_true) != len(y_pred) or not y_true:
        raise ValueError("Evaluation requires equally sized, non-empty lists.")
    precision, recall, f1, support = precision_recall_fscore_support(
        y_true, y_pred, labels=list(BENCHMARK_CLASSES), zero_division=0
    )
    per_class = {
        label: {
            "precision": float(precision[i]),
            "recall": float(recall[i]),
            "f1": float(f1[i]),
            "support": int(support[i]),
        }
        for i, label in enumerate(BENCHMARK_CLASSES)
    }
    return {
        "accuracy": float(accuracy_score(y_true, y_pred)),
        "macro_f1": float(f1_score(
            y_true, y_pred, labels=list(BENCHMARK_CLASSES),
            average="macro", zero_division=0
        )),
        "per_class": per_class,
        "classification_report": classification_report(
            y_true, y_pred, labels=list(BENCHMARK_CLASSES),
            output_dict=True, zero_division=0
        ),
        "confusion_matrix": confusion_matrix(
            y_true, y_pred, labels=list(BENCHMARK_CLASSES)
        ).tolist(),
        "class_order": list(BENCHMARK_CLASSES),
        "evaluation_rows": len(y_true),
    }
