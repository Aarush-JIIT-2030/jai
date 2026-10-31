"""Leakage-aware confidence calibration evaluation for Agent 1.

Calibration is fitted only on a stratified holdout carved from the supplied
training partition. The evaluation partition is never used to fit the model
or calibrator.
"""
from __future__ import annotations

from typing import Any
import numpy as np
import pandas as pd
from sklearn.metrics import log_loss
from sklearn.model_selection import train_test_split

from cybersentinel.agents.threat_detection.model import BENCHMARK_CLASSES, ThreatDetectionModel, numeric_features


def _canonical_probabilities(model: ThreatDetectionModel, frame: pd.DataFrame) -> np.ndarray:
    model._ready()
    x = numeric_features(frame).reindex(columns=model.feature_columns)
    raw = np.asarray(model.estimator.predict_proba(model.imputer.transform(x)), dtype=np.float64)
    trained = model.label_encoder.inverse_transform(np.asarray(model.estimator.classes_, dtype=int))
    aligned = np.zeros((len(frame), len(BENCHMARK_CLASSES)), dtype=np.float64)
    for source_index, label in enumerate(trained):
        aligned[:, BENCHMARK_CLASSES.index(str(label))] = raw[:, source_index]
    temperature = max(float(model.calibration_temperature), 1e-6)
    logits = np.log(np.clip(aligned, np.finfo(float).eps, 1.0)) / temperature
    logits -= logits.max(axis=1, keepdims=True)
    exp = np.exp(logits)
    return exp / exp.sum(axis=1, keepdims=True)


def calculate_expected_calibration_error(y_indices: np.ndarray, probabilities: np.ndarray, n_bins: int = 10):
    confidence = probabilities.max(axis=1)
    predicted = probabilities.argmax(axis=1)
    correct = (predicted == y_indices).astype(float)
    bins = []
    ece = 0.0
    edges = np.linspace(0.0, 1.0, n_bins + 1)
    for i in range(n_bins):
        mask = (confidence >= edges[i]) & ((confidence <= edges[i + 1]) if i == n_bins - 1 else (confidence < edges[i + 1]))
        count = int(mask.sum())
        mean_conf = float(confidence[mask].mean()) if count else 0.0
        accuracy = float(correct[mask].mean()) if count else 0.0
        if count:
            ece += count / max(1, len(y_indices)) * abs(mean_conf - accuracy)
        bins.append({"bin_index": i, "bin_lower": float(edges[i]), "bin_upper": float(edges[i + 1]),
                     "sample_count": count, "mean_confidence": mean_conf,
                     "observed_accuracy": accuracy, "calibration_gap": abs(mean_conf - accuracy)})
    return float(ece), bins


def calculate_multiclass_brier_score(y_indices: np.ndarray, probabilities: np.ndarray, n_classes: int) -> float:
    one_hot = np.eye(n_classes, dtype=np.float64)[y_indices]
    return float(np.mean(np.sum((probabilities - one_hot) ** 2, axis=1)))


def evaluate_probability_calibration(
    train_df: pd.DataFrame,
    eval_df: pd.DataFrame,
    cal_fraction: float = 0.20,
    n_estimators: int = 100,
    random_state: int = 42,
) -> dict[str, Any]:
    if "label" not in train_df or "label" not in eval_df:
        raise ValueError("Both training and evaluation data must contain a 'label' column.")
    if not 0.05 <= cal_fraction <= 0.5:
        raise ValueError("cal_fraction must be between 0.05 and 0.5.")
    labels = train_df["label"].astype(str).str.strip().str.upper()
    fit_idx, cal_idx = train_test_split(
        np.arange(len(train_df)), test_size=cal_fraction, random_state=random_state, stratify=labels
    )
    fit_df, cal_df = train_df.iloc[fit_idx], train_df.iloc[cal_idx]
    features = [c for c in train_df.columns if c != "label"]
    model = ThreatDetectionModel(n_estimators=n_estimators, random_state=random_state)
    model.fit(fit_df[features], fit_df["label"])
    model.calibration_temperature = 1.0
    raw = _canonical_probabilities(model, eval_df[features])
    calibration_result = model.calibrate_confidence(cal_df[features], cal_df["label"])
    calibrated = _canonical_probabilities(model, eval_df[features])

    y_eval = eval_df["label"].astype(str).str.strip().str.upper().tolist()
    unknown = sorted(set(y_eval) - set(BENCHMARK_CLASSES))
    if unknown:
        raise ValueError(f"Evaluation labels outside benchmark classes: {unknown}")
    y_idx = np.asarray([BENCHMARK_CLASSES.index(label) for label in y_eval], dtype=int)

    def metrics(probabilities):
        ece, bins = calculate_expected_calibration_error(y_idx, probabilities)
        return {
            "ece": ece,
            "brier_score": calculate_multiclass_brier_score(y_idx, probabilities, len(BENCHMARK_CLASSES)),
            "log_loss": float(log_loss(y_idx, np.clip(probabilities, 1e-15, 1.0), labels=list(range(len(BENCHMARK_CLASSES))))),
            "mean_confidence": float(probabilities.max(axis=1).mean()),
            "reliability_bins": bins,
        }

    uncalibrated = metrics(raw)
    calibrated_metrics = metrics(calibrated)
    return {
        "evaluation_samples": len(eval_df),
        "training_samples": len(fit_df),
        "calibration_samples": len(cal_df),
        "calibration_provenance": "stratified holdout from supplied training partition only",
        "method": "scalar temperature scaling",
        "temperature": calibration_result["temperature"],
        "uncalibrated": uncalibrated,
        "calibrated": calibrated_metrics,
        "comparison_summary": {
            "ece_reduction": uncalibrated["ece"] - calibrated_metrics["ece"],
            "brier_score_reduction": uncalibrated["brier_score"] - calibrated_metrics["brier_score"],
            "log_loss_reduction": uncalibrated["log_loss"] - calibrated_metrics["log_loss"],
        },
    }
