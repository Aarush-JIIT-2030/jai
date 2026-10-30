# CyberSentinel Agent 1 — supervised threat detection

Baseline artifact generated with scikit-learn `HistGradientBoostingClassifier`.

- Input: uploaded `train (2).csv` (288,750 rows; 75 numeric features after filtering).
- Preprocessing: numeric coercion, infinities to missing, median imputation; excludes `label` and `record_id`.
- Class imbalance: balanced sample weights.
- Evaluation: stratified random 80/20 internal split.
- Internal holdout: accuracy 1.000, macro-F1 1.000 (57,750 rows).

## Important limitations

The CSV export is incomplete compared with the earlier Colab count of 456,737 training rows. The reported perfect metrics are suspicious and require duplicate/leakage investigation. They are not official evaluation results and must not be represented as real-world generalisation. Retrain using the complete official training set and evaluate once on the untouched official evaluation set before final submission.

Run:
```bash
python train_agent1.py --train path/to/train.csv --out artifacts
```

The trained `threat_detection_model.joblib` is distributed separately in the ChatGPT artifact bundle; this commit contains the reproducible trainer and report, not the binary model.
