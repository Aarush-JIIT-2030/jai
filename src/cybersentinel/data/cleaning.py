#!/usr/bin/env python3
"""Inspect and prepare CyberSentinel network-flow records.

The fitted preprocessor learns medians, feature pruning, and robust-scaling
statistics from the training split only. `record_id` is returned separately
for traceability and is never included in the model feature matrix.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd


LABELS = ("BENIGN", "BRUTE_FORCE", "DOS", "DDOS", "PORT_SCAN")
LABEL_TO_ID = {label: index for index, label in enumerate(LABELS)}
ID_COLUMN = "record_id"
TARGET_COLUMN = "label"
# These fields represent byte lengths and cannot be negative. In this release,
# a small number of BENIGN rows contain negative values in these columns.
NONNEGATIVE_LENGTH_COLUMNS = (
    "Fwd Header Length",
    "Bwd Header Length",
    "Fwd Header Length_duplicated_0",
)
STATE_VERSION = 1


def _json_safe(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(k): _json_safe(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_safe(v) for v in value]
    if isinstance(value, (np.integer,)):
        return int(value)
    if isinstance(value, (np.floating,)):
        return float(value)
    if isinstance(value, (np.bool_,)):
        return bool(value)
    if pd.isna(value):
        return None
    return value


def _class_counts(frame: pd.DataFrame) -> dict[str, int]:
    counts = frame[TARGET_COLUMN].value_counts(dropna=False)
    return {label: int(counts.get(label, 0)) for label in LABELS}


def _macro_f1(y_true: np.ndarray, y_pred: np.ndarray) -> float:
    scores = []
    for label in LABELS:
        true_mask = y_true == label
        pred_mask = y_pred == label
        tp = int(np.logical_and(true_mask, pred_mask).sum())
        fp = int(np.logical_and(~true_mask, pred_mask).sum())
        fn = int(np.logical_and(true_mask, ~pred_mask).sum())
        precision = tp / (tp + fp) if tp + fp else 0.0
        recall = tp / (tp + fn) if tp + fn else 0.0
        scores.append(2 * precision * recall / (precision + recall) if precision + recall else 0.0)
    return float(np.mean(scores))


def _identifier_only_diagnostic(train: pd.DataFrame, evaluation: pd.DataFrame) -> dict[str, float]:
    """Measure the leakage signal in the sequential ID using train-only bins."""
    def numeric_ids(frame: pd.DataFrame) -> np.ndarray:
        pieces = frame[ID_COLUMN].astype(str).str.extract(r"^[A-Za-z]+(\d+)$", expand=False)
        if pieces.isna().any():
            raise ValueError("record_id values must end in a numeric sequence")
        return pieces.astype("int64").to_numpy()

    train_ids = numeric_ids(train)
    eval_ids = numeric_ids(evaluation)
    edges = np.linspace(int(train_ids.min()), int(train_ids.max()), 11)
    train_bins = np.searchsorted(edges[1:-1], train_ids, side="right")
    eval_bins = np.searchsorted(edges[1:-1], eval_ids, side="right")
    global_majority = str(train[TARGET_COLUMN].value_counts().idxmax())
    majority_by_bin: dict[int, str] = {}
    for bucket in np.unique(train_bins):
        majority_by_bin[int(bucket)] = str(train.loc[train_bins == bucket, TARGET_COLUMN].value_counts().idxmax())
    predictions = np.asarray([majority_by_bin.get(int(b), global_majority) for b in eval_bins], dtype=object)
    truth = evaluation[TARGET_COLUMN].astype(str).to_numpy()
    return {
        "accuracy": float(np.mean(predictions == truth)),
        "macro_f1": _macro_f1(truth, predictions),
        "bins": 10,
    }


def _raw_dataset_stats(frame: pd.DataFrame) -> dict[str, Any]:
    numeric = frame.select_dtypes(include=[np.number])
    feature_columns = [c for c in frame.columns if c not in (ID_COLUMN, TARGET_COLUMN)]
    feature_frame = frame[feature_columns]
    duplicate_feature_rows = feature_frame.duplicated(keep=False)
    duplicated_feature_groups = int(feature_frame.loc[duplicate_feature_rows].drop_duplicates().shape[0])
    feature_labels = pd.DataFrame({"features": pd.util.hash_pandas_object(feature_frame, index=False), "label": frame[TARGET_COLUMN].astype(str)})
    conflicting_feature_groups = int((feature_labels.groupby("features")["label"].nunique() > 1).sum())
    exact_duplicate_column_pairs = []
    for index, left in enumerate(feature_columns):
        for right in feature_columns[index + 1 :]:
            if frame[left].equals(frame[right]):
                exact_duplicate_column_pairs.append([left, right])
    constants = [c for c in feature_columns if frame[c].nunique(dropna=False) <= 1]
    negative_header_counts = {
        c: int((frame[c] < 0).sum())
        for c in NONNEGATIVE_LENGTH_COLUMNS
        if c in frame.columns
    }
    numeric_values = numeric.to_numpy(dtype=np.float64, copy=False)
    return {
        "rows": int(len(frame)),
        "columns": int(len(frame.columns)),
        "numeric_feature_columns": len(feature_columns),
        "null_cells": int(frame.isna().sum().sum()),
        "infinite_numeric_cells": int(np.isinf(numeric_values).sum()),
        "full_duplicate_rows": int(frame.duplicated().sum()),
        "duplicate_record_ids": int(frame[ID_COLUMN].duplicated().sum()),
        "unique_record_ids": int(frame[ID_COLUMN].nunique()),
        "feature_duplicate_rows": int(duplicate_feature_rows.sum()),
        "feature_duplicate_groups": duplicated_feature_groups,
        "feature_groups_with_label_conflicts": conflicting_feature_groups,
        "constant_features": constants,
        "exact_duplicate_feature_pairs": exact_duplicate_column_pairs,
        "negative_header_length_values": negative_header_counts,
        "negative_header_length_label_counts": {
            c: {str(label): int(count) for label, count in frame.loc[frame[c] < 0, TARGET_COLUMN].value_counts().items()}
            for c in negative_header_counts
        },
        "class_counts": _class_counts(frame),
    }


def inspect_frame(frame: pd.DataFrame) -> dict[str, Any]:
    """Summarize a frame's schema and data-quality issues without modifying it."""
    if ID_COLUMN in frame.columns and TARGET_COLUMN in frame.columns:
        return _raw_dataset_stats(frame)
    numeric = frame.select_dtypes(include=[np.number])
    values = numeric.to_numpy(dtype=np.float64, copy=False)
    return {
        "rows": int(len(frame)),
        "columns": int(len(frame.columns)),
        "column_names": [str(c) for c in frame.columns],
        "missing_by_column": frame.isna().sum().astype(int).to_dict(),
        "infinite_numeric_values": int(np.isinf(values).sum()),
        "duplicate_rows": int(frame.duplicated().sum()),
    }


class FlowPreprocessor:
    """Fit once on training data, then apply unchanged to eval or live replays."""

    def __init__(self) -> None:
        self.fitted = False

    @staticmethod
    def _validate_labeled_frame(frame: pd.DataFrame) -> None:
        missing_meta = {ID_COLUMN, TARGET_COLUMN} - set(frame.columns)
        if missing_meta:
            raise ValueError(f"Missing required metadata columns: {sorted(missing_meta)}")
        FlowPreprocessor._validate_labels(frame)

    @staticmethod
    def _validate_labels(frame: pd.DataFrame) -> None:
        if TARGET_COLUMN not in frame.columns:
            return
        unknown_labels = sorted(set(frame[TARGET_COLUMN].dropna().astype(str)) - set(LABELS))
        if unknown_labels:
            raise ValueError(f"Unexpected labels: {unknown_labels}")
        if frame[TARGET_COLUMN].isna().any():
            raise ValueError("Target labels contain missing values")

    @staticmethod
    def _sanitize(frame: pd.DataFrame, columns: list[str]) -> pd.DataFrame:
        values = frame.loc[:, columns].copy()
        for column in columns:
            values[column] = pd.to_numeric(values[column], errors="raise")
        values = values.replace([np.inf, -np.inf], np.nan)
        for column in NONNEGATIVE_LENGTH_COLUMNS:
            if column in values.columns:
                values.loc[values[column] < 0, column] = np.nan
        return values

    def fit(self, train: pd.DataFrame) -> "FlowPreprocessor":
        self._validate_labeled_frame(train)
        self.raw_columns = list(train.columns)
        self.raw_feature_columns = [c for c in self.raw_columns if c not in (ID_COLUMN, TARGET_COLUMN)]
        non_numeric = [c for c in self.raw_feature_columns if not pd.api.types.is_numeric_dtype(train[c])]
        if non_numeric:
            raise ValueError(f"Expected numeric traffic features; found {non_numeric}")

        sanitized = self._sanitize(train, self.raw_feature_columns)
        self.invalid_value_counts = {
            column: int((train[column] < 0).sum())
            for column in NONNEGATIVE_LENGTH_COLUMNS
            if column in train.columns
        }

        self.constant_columns = [
            column for column in self.raw_feature_columns
            if sanitized[column].nunique(dropna=True) <= 1
        ]
        candidates = [c for c in self.raw_feature_columns if c not in self.constant_columns]
        self.duplicate_columns: dict[str, str] = {}
        kept: list[str] = []
        for column in candidates:
            duplicate_of = next((prior for prior in kept if sanitized[column].equals(sanitized[prior])), None)
            if duplicate_of is None:
                kept.append(column)
            else:
                self.duplicate_columns[column] = duplicate_of
        self.feature_columns = kept
        if not self.feature_columns:
            raise ValueError("No usable numeric feature columns remain")

        clean_kept = sanitized.loc[:, self.feature_columns]
        self.medians = clean_kept.median(axis=0).fillna(0.0)
        imputed = clean_kept.fillna(self.medians)
        self.robust_centers = imputed.median(axis=0)
        iqr = imputed.quantile(0.75) - imputed.quantile(0.25)
        self.robust_scales = iqr.where(iqr > 0, 1.0)
        self.fitted = True
        return self

    def transform_features(self, frame: pd.DataFrame, *, scaled: bool = False) -> pd.DataFrame:
        if not self.fitted:
            raise RuntimeError("Call fit(training_frame) before transform_features")
        self._validate_labels(frame)
        input_features = set(frame.columns) - {ID_COLUMN, TARGET_COLUMN}
        expected_features = set(self.raw_feature_columns)
        missing = expected_features - input_features
        extra = input_features - expected_features
        if missing or extra:
            raise ValueError(f"Schema mismatch; missing={sorted(missing)}, extra={sorted(extra)}")
        sanitized = self._sanitize(frame, self.raw_feature_columns)
        features = sanitized.loc[:, self.feature_columns].fillna(self.medians)
        if scaled:
            features = (features - self.robust_centers) / self.robust_scales
        return features.astype(np.float32)

    def transform(self, frame: pd.DataFrame, *, scaled: bool = False, include_label: bool = True) -> pd.DataFrame:
        """Return model-ready features; IDs are intentionally excluded."""
        result = self.transform_features(frame, scaled=scaled)
        if include_label:
            if TARGET_COLUMN not in frame.columns:
                raise ValueError(f"Cannot include target: {TARGET_COLUMN!r} is absent")
            result[TARGET_COLUMN] = frame[TARGET_COLUMN].astype(str).to_numpy()
        return result

    def labels_and_ids(self, frame: pd.DataFrame) -> tuple[pd.Series, pd.Series]:
        """Return target and ID separately so neither can leak into X by accident."""
        self._validate_labeled_frame(frame)
        return frame[TARGET_COLUMN].astype(str).copy(), frame[ID_COLUMN].astype(str).copy()

    def state(self) -> dict[str, Any]:
        if not self.fitted:
            raise RuntimeError("Cannot serialize an unfitted preprocessor")
        return _json_safe({
            "state_version": STATE_VERSION,
            "labels": list(LABELS),
            "label_to_id": LABEL_TO_ID,
            "id_column": ID_COLUMN,
            "target_column": TARGET_COLUMN,
            "raw_columns": self.raw_columns,
            "raw_feature_columns": self.raw_feature_columns,
            "feature_columns": self.feature_columns,
            "constant_columns": self.constant_columns,
            "duplicate_columns": self.duplicate_columns,
            "invalid_value_counts_in_training": self.invalid_value_counts,
            "medians": self.medians.to_dict(),
            "robust_centers": self.robust_centers.to_dict(),
            "robust_scales": self.robust_scales.to_dict(),
        })

    def save(self, path: Path) -> None:
        path.write_text(json.dumps(self.state(), indent=2) + "\n", encoding="utf-8")

    @classmethod
    def load(cls, path: Path) -> "FlowPreprocessor":
        state = json.loads(path.read_text(encoding="utf-8"))
        if state.get("state_version") != STATE_VERSION:
            raise ValueError(f"Unsupported preprocessing state version: {state.get('state_version')}")
        obj = cls()
        obj.raw_columns = state["raw_columns"]
        obj.raw_feature_columns = state["raw_feature_columns"]
        obj.feature_columns = state["feature_columns"]
        obj.constant_columns = state["constant_columns"]
        obj.duplicate_columns = state["duplicate_columns"]
        obj.invalid_value_counts = state["invalid_value_counts_in_training"]
        obj.medians = pd.Series(state["medians"], dtype=np.float64).reindex(obj.feature_columns)
        obj.robust_centers = pd.Series(state["robust_centers"], dtype=np.float64).reindex(obj.feature_columns)
        obj.robust_scales = pd.Series(state["robust_scales"], dtype=np.float64).reindex(obj.feature_columns)
        obj.fitted = True
        return obj


def clean_training_frame(frame: pd.DataFrame) -> pd.DataFrame:
    """Clean one labeled training frame, retaining its target but excluding its ID.

    For train/eval pairs, prefer fitting one `FlowPreprocessor` on training and
    calling `transform` on both frames so all learned values are shared.
    """
    return FlowPreprocessor().fit(frame).transform(frame, include_label=True)


def build_profile(train: pd.DataFrame, evaluation: pd.DataFrame) -> dict[str, Any]:
    train_stats = _raw_dataset_stats(train)
    eval_stats = _raw_dataset_stats(evaluation)
    train_features = [c for c in train.columns if c not in (ID_COLUMN, TARGET_COLUMN)]

    train_hashes = pd.util.hash_pandas_object(train[train_features], index=False).to_numpy(dtype=np.uint64)
    eval_hashes = pd.util.hash_pandas_object(evaluation[train_features], index=False).to_numpy(dtype=np.uint64)
    train_unique = np.unique(train_hashes)
    eval_unique = np.unique(eval_hashes)
    shared_hashes = np.intersect1d(train_unique, eval_unique, assume_unique=True)
    train_seen_in_eval = np.isin(train_hashes, eval_unique)
    eval_seen_in_train = np.isin(eval_hashes, train_unique)
    train_hash_labels = pd.DataFrame({"hash": train_hashes, "label": train[TARGET_COLUMN].astype(str)})
    eval_hash_labels = pd.DataFrame({"hash": eval_hashes, "label": evaluation[TARGET_COLUMN].astype(str)})
    train_label_sets = train_hash_labels.groupby("hash")["label"].agg(lambda x: frozenset(x))
    eval_label_sets = eval_hash_labels.groupby("hash")["label"].agg(lambda x: frozenset(x))
    label_conflicts = sum(train_label_sets.get(int(h)) != eval_label_sets.get(int(h)) for h in shared_hashes)

    classes = {}
    for label in LABELS:
        tr_count = train_stats["class_counts"][label]
        ev_count = eval_stats["class_counts"][label]
        classes[label] = {
            "training_count": tr_count,
            "training_percent": 100.0 * tr_count / len(train),
            "eval_count": ev_count,
            "eval_percent": 100.0 * ev_count / len(evaluation),
        }

    schema_match = list(train.columns) == list(evaluation.columns)
    if not schema_match:
        raise ValueError("Training and eval schemas differ; refusing to create a shared artifact")
    return _json_safe({
        "source_files": {"training": "training/flows.parquet", "eval": "eval/flows.parquet"},
        "schema": {
            "columns": len(train.columns),
            "numeric_features_before_pruning": len(train_features),
            "columns_match_in_order": schema_match,
            "raw_columns": list(train.columns),
            "target_column": TARGET_COLUMN,
            "record_id_column": ID_COLUMN,
            "canonical_labels": list(LABELS),
            "label_to_id": LABEL_TO_ID,
        },
        "training": train_stats,
        "eval": eval_stats,
        "class_distribution": classes,
        "feature_overlap_across_splits": {
            "distinct_shared_feature_vectors": int(len(shared_hashes)),
            "training_rows_in_shared_vectors": int(train_seen_in_eval.sum()),
            "eval_rows_in_shared_vectors": int(eval_seen_in_train.sum()),
            "eval_percent_in_shared_vectors": 100.0 * float(eval_seen_in_train.mean()),
            "shared_vector_label_set_conflicts": int(label_conflicts),
            "method": "64-bit pandas row hashes over numeric features, excluding record_id and label",
        },
        "record_id_leakage_diagnostic": _identifier_only_diagnostic(train, evaluation),
    })


def write_report(profile: dict[str, Any], processor: FlowPreprocessor, path: Path) -> None:
    lines = [
        "# CyberSentinel dataset intelligence report",
        "",
        "## Scope",
        "",
        "This audit covers the provided training and eval Parquet files. It is a data-preparation handoff for Member 1; no classifier, anomaly detector, fusion policy, or API submission was performed.",
        "",
        "## Schema and labels",
        "",
        f"- Training: **{profile['training']['rows']:,} rows**; eval: **{profile['eval']['rows']:,} rows**.",
        f"- Both files have **{profile['schema']['columns']} columns** in the same order: **{profile['schema']['numeric_features_before_pruning']} numeric traffic features**, `{ID_COLUMN}`, and `{TARGET_COLUMN}`.",
        f"- The target is `{TARGET_COLUMN}`. The labels already match the five organizer classes: `{', '.join(LABELS)}`.",
        f"- `record_id` is retained in the raw data for tracing but excluded from prepared model inputs.",
        "",
        "| Class | Training rows | Training % | Eval rows | Eval % |",
        "|---|---:|---:|---:|---:|",
    ]
    for label in LABELS:
        item = profile["class_distribution"][label]
        lines.append(f"| {label} | {item['training_count']:,} | {item['training_percent']:.2f}% | {item['eval_count']:,} | {item['eval_percent']:.2f}% |")
    lines.extend([
        "",
        "BRUTE_FORCE is the minority class at about 1.21% of each split (about 43 times fewer rows than BENIGN). Use class-aware training and report macro-F1; do not rebalance the official eval split.",
        "",
        "## Data quality findings",
        "",
        f"- Null cells: **{profile['training']['null_cells']} training**, **{profile['eval']['null_cells']} eval**. Infinite numeric values: **{profile['training']['infinite_numeric_cells']} training**, **{profile['eval']['infinite_numeric_cells']} eval**.",
        f"- Full-row duplicates: **{profile['training']['full_duplicate_rows']} training**, **{profile['eval']['full_duplicate_rows']} eval**. Duplicate IDs: **{profile['training']['duplicate_record_ids']} training**, **{profile['eval']['duplicate_record_ids']} eval**.",
        f"- Repeated feature vectors (excluding ID and label): **{profile['training']['feature_duplicate_rows']:,} training rows** across {profile['training']['feature_duplicate_groups']:,} repeated groups; **{profile['eval']['feature_duplicate_rows']:,} eval rows** across {profile['eval']['feature_duplicate_groups']:,} repeated groups. Feature groups with label conflicts: **{profile['training']['feature_groups_with_label_conflicts']} training**, **{profile['eval']['feature_groups_with_label_conflicts']} eval**.",
        f"- Cross-split feature overlap: **{profile['feature_overlap_across_splits']['eval_rows_in_shared_vectors']:,} eval rows ({profile['feature_overlap_across_splits']['eval_percent_in_shared_vectors']:.2f}%)** have a feature vector also seen in training. Shared vectors have {profile['feature_overlap_across_splits']['shared_vector_label_set_conflicts']} label-set conflicts. Keep the official eval records unchanged, and disclose this overlap when interpreting scores.",
        "- Negative byte-header lengths appear in a small number of rows despite being impossible for a length field:",
    ])
    for split in ("training", "eval"):
        counts = profile[split]["negative_header_length_values"]
        lines.append(f"  - {split}: " + ", ".join(f"`{c}` {n}" for c, n in counts.items()) + ".")
    lines.extend([
        "- All negative header-length values are in BENIGN rows. The preprocessor treats them as invalid/missing and fills them with the corresponding **training median**; eval medians are never fitted.",
        "",
        "## Leakage and redundant columns",
        "",
        f"- A diagnostic using only ten `record_id` ranges, with majority labels learned from training, gets **{profile['record_id_leakage_diagnostic']['accuracy']:.1%} eval accuracy** and **{profile['record_id_leakage_diagnostic']['macro_f1']:.3f} macro-F1**. This is evidence that IDs encode source-row ordering associated with labels. Never pass `record_id` to either ML agent.",
        "- Constant training features removed: " + (", ".join(f"`{c}`" for c in processor.constant_columns) or "none") + ".",
        "- Exact duplicate columns removed (the first schema occurrence is retained): " + (", ".join(f"`{c}` (same as `{prior}`)" for c, prior in processor.duplicate_columns.items()) or "none") + ".",
        f"- Prepared matrix has **{len(processor.feature_columns)} numeric features** after removing constants and duplicate columns, with the original row order preserved.",
        "",
        "## Handoff artifacts",
        "",
        "- `data/processed/`: local model-ready Parquet files and preprocessing state. These are generated from organiser data and are git-ignored.",
        "- `preprocessing_state.json`: fitted feature list, dropped-column reasons, medians, and robust-scaling statistics. Load it with `FlowPreprocessor.load(...)` to apply the exact same transform later.",
        "- `training_prepared.parquet` and `eval_prepared.parquet`: all original rows, model-ready numeric features plus string label, no ID, no full-row drops. Training-only imputation values are used in both.",
        "- `dataset_profile.json`: machine-readable audit summary.",
        "",
        "Example use:",
        "```python",
        "from pathlib import Path",
        "import pandas as pd",
        "from flow_preprocessor import FlowPreprocessor",
        "processor = FlowPreprocessor.load(Path('preprocessing_state.json'))",
        "raw_eval = pd.read_parquet('/path/to/eval/flows.parquet')",
        "X_eval_scaled = processor.transform_features(raw_eval, scaled=True)  # anomaly agent",
        "y_eval, eval_ids = processor.labels_and_ids(raw_eval)  # metadata stays separate",
        "```",
        "",
        "Dependencies: Python 3, pandas, NumPy, and PyArrow.",
    ])
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--train", required=True, type=Path, help="Training flows Parquet file")
    parser.add_argument("--eval", required=True, type=Path, help="Official eval flows Parquet file")
    parser.add_argument("--out-dir", required=True, type=Path, help="Directory for prepared data and audit artifacts")
    args = parser.parse_args()

    train = pd.read_parquet(args.train)
    evaluation = pd.read_parquet(args.eval)
    if list(train.columns) != list(evaluation.columns):
        raise ValueError("Training and eval columns/order differ")

    profile = build_profile(train, evaluation)
    processor = FlowPreprocessor().fit(train)
    args.out_dir.mkdir(parents=True, exist_ok=True)
    prepared_train = processor.transform(train, include_label=True)
    prepared_eval = processor.transform(evaluation, include_label=True)
    prepared_train.to_parquet(args.out_dir / "training_prepared.parquet", index=False)
    prepared_eval.to_parquet(args.out_dir / "eval_prepared.parquet", index=False)
    processor.save(args.out_dir / "preprocessing_state.json")
    (args.out_dir / "dataset_profile.json").write_text(
        json.dumps(profile, indent=2) + "\n", encoding="utf-8"
    )
    write_report(profile, processor, args.out_dir / "dataset_intelligence_report.md")
    print(json.dumps({
        "output_dir": str(args.out_dir.resolve()),
        "training_rows": len(prepared_train),
        "eval_rows": len(prepared_eval),
        "prepared_feature_count": len(processor.feature_columns),
        "dropped_constants": processor.constant_columns,
        "dropped_duplicate_columns": processor.duplicate_columns,
        "prepared_columns": list(prepared_train.columns),
    }, indent=2))


if __name__ == "__main__":
    main()
