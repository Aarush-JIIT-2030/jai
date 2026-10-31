# Evaluation Status and Reproduction

## Current status

No current full-data evaluation is reproducible from this repository alone. The organizer dataset, prepared Parquet files, trained model artifacts, and generated submission outputs are excluded from Git. CI verifies code and frontend build; it does not verify model metrics or a full organizer replay.

See [data-intelligence.md](data-intelligence.md) for the recorded dataset audit. It reports 8,161 exact feature vectors shared by training and evaluation, covering 9,795 evaluation rows (8.58%). Keep this caveat with any measured holdout score. Do not alter the official evaluation file to remove the overlap.

Historical scores and throughput figures describe earlier artifacts. Treat them as historical until reproduced using the current code and authorized data.

## Reproduction procedure

1. Obtain the organizer-provided training and labelled validation files, the exact organizer class mapping, and the hidden replay input/API contract.
2. Run cleaning/preparation on the permitted labelled training and validation files. Fit feature selection and imputation on training data only. Keep replay metadata (organizer record IDs, endpoints and timestamps, if supplied) separate from the ML feature matrix.
3. Train Agent 1 on training data. Use a separate labelled validation split for temperature calibration; never calibrate on hidden replay records.
4. Train Agent 2 on BENIGN rows from training data only. Its optional threshold calibration uses labelled validation rows and records the configured benign false-positive ceiling.
5. Evaluate on a separate permitted labelled evaluation split, if supplied. Hidden replay records are unlabeled for decision-making and must never be used for fitting, calibration, threshold selection, or tuning.

### Agent 1 training

~~~bash
python -m cybersentinel.agents.threat_detection.train \
  --train data/processed/training_prepared.parquet \
  --label-column label \
  --calibration-validation data/processed/labelled_validation_prepared.parquet \
  --model-out models/threat_detection/model.joblib \
  --report-out reports/generated/threat_detection_training.json
~~~

Omit --calibration-validation only when no separate labelled validation file is supplied. In that case the artifact explicitly remains uncalibrated; do not describe its maximum predict_proba output as calibrated confidence.

### Agent 2 training

~~~bash
python scripts/train_anomaly.py \
  --train data/processed/training_prepared.parquet \
  --validation data/processed/labelled_validation_prepared.parquet \
  --max-benign-fpr 0.02 \
  --model-out models/anomaly_detection/model.joblib \
  --report-out reports/generated/anomaly_training.json
~~~

The validation file must contain the canonical label column and both BENIGN and attack rows. Threshold selection maximizes validation attack recall subject to the configured benign FPR ceiling. These are tuning metrics, not an unbiased final performance estimate.

### Evaluation and replay

~~~bash
python scripts/evaluate_benchmark.py \
  --eval data/processed/heldout_evaluation_prepared.parquet \
  --threat-model models/threat_detection/model.joblib \
  --anomaly-model models/anomaly_detection/model.joblib \
  --output reports/generated/official-evaluation.json

python scripts/generate_submissions.py \
  --input data/processed/hidden_replay_input.parquet \
  --output-dir outputs/submission

python scripts/validate_submissions.py \
  --input data/processed/hidden_replay_input.parquet \
  --output-dir outputs/submission
~~~

Use the organizer's exact input and record order. Do not use hidden ground-truth labels or future rows to make replay decisions. A limited --limit run is a smoke test only and is not submission-ready.

Save each report with the code revision, source file hashes, split sizes, class-level metrics, calibration provenance, and the dataset-overlap caveat. Do not describe a score as current unless it came from that exact run.

Dataset, model, and submission artifacts belong in local ignored paths unless the organizers explicitly authorize publishing them.
