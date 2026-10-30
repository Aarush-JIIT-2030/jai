"""
CyberSentinel Agent 1 training entry point.
Usage: python train_agent1.py --train train.csv --out artifacts
Requires: pandas, numpy, scikit-learn, joblib
"""
import argparse
import json
import os
import time

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.impute import SimpleImputer
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix, f1_score
from sklearn.model_selection import train_test_split
from sklearn.utils.class_weight import compute_sample_weight

parser = argparse.ArgumentParser()
parser.add_argument("--train", required=True)
parser.add_argument("--out", default="artifacts")
args = parser.parse_args()
os.makedirs(args.out, exist_ok=True)

df = pd.read_csv(args.train)
if "label" not in df.columns:
    raise ValueError("Expected target column named 'label'")

y = df["label"].astype(str).str.strip()
X = df.drop(columns=["label", "record_id"], errors="ignore")
X = X.apply(pd.to_numeric, errors="coerce").replace([np.inf, -np.inf], np.nan)
X = X.dropna(axis=1, how="all")
X = X.loc[:, X.nunique(dropna=True) > 1]

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)
imputer = SimpleImputer(strategy="median")
X_train = imputer.fit_transform(X_train)
X_test = imputer.transform(X_test)

model = HistGradientBoostingClassifier(
    max_iter=120, learning_rate=0.12, max_leaf_nodes=31,
    l2_regularization=1.0, random_state=42
)
started = time.time()
model.fit(
    X_train, y_train,
    sample_weight=compute_sample_weight("balanced", y_train),
)
predictions = model.predict(X_test)

report = {
    "rows": int(len(df)),
    "features": int(X.shape[1]),
    "train_rows": int(len(y_train)),
    "holdout_rows": int(len(y_test)),
    "training_seconds": round(time.time() - started, 2),
    "accuracy": float(accuracy_score(y_test, predictions)),
    "macro_f1": float(f1_score(y_test, predictions, average="macro")),
    "classification_report": classification_report(
        y_test, predictions, output_dict=True, zero_division=0
    ),
    "confusion_matrix": confusion_matrix(
        y_test, predictions, labels=model.classes_
    ).tolist(),
    "class_order": model.classes_.tolist(),
    "class_counts": {str(k): int(v) for k, v in y.value_counts().items()},
    "note": (
        "Random stratified internal holdout only. Evaluate on the organiser's "
        "official untouched evaluation set before claiming benchmark performance."
    ),
}
joblib.dump(
    {
        "imputer": imputer,
        "model": model,
        "feature_names": X.columns.tolist(),
        "classes": model.classes_.tolist(),
        "version": "1.0.0",
    },
    os.path.join(args.out, "threat_detection_model.joblib"),
    compress=3,
)
with open(os.path.join(args.out, "training_report.json"), "w", encoding="utf-8") as f:
    json.dump(report, f, indent=2)
print(json.dumps({
    key: report[key] for key in (
        "rows", "features", "train_rows", "holdout_rows",
        "accuracy", "macro_f1", "training_seconds"
    )
}, indent=2))
