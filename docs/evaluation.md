# Evaluation Status and Reproduction

## Current status

No current full-data evaluation is reproducible from this repository alone. The organizer dataset, prepared Parquet files, trained model artifacts, and generated submission outputs are excluded from Git. The latest GitHub Actions runs verify the Python test suite and frontend build; they do not verify model metrics or a full replay.

See [`docs/data-intelligence.md`](data-intelligence.md) for the recorded dataset audit. It reports 8,161 exact feature vectors shared by training and evaluation, covering 9,795 evaluation rows (8.58%). Keep this caveat with any measured holdout score. Do not alter the official evaluation file to remove the overlap.

The scores and throughput figures in older release reports describe earlier artifacts. Treat them as historical until reproduced using the current code and authorized data.

## Reproduction procedure

1. Obtain the organizer-provided training and evaluation files and the exact organizer class mapping.
2. Run the cleaning/preparation workflow on the training split; fit feature selection and imputation on training data only.
3. Train Agent 1 and Agent 2 from the training split. Agent 2 uses benign training rows only.
4. Evaluate on the untouched evaluation split with the current scripts:

```bash
python -m cybersentinel.data.cleaning \
  --train data/raw/training/flows.parquet \
  --eval data/raw/eval/flows.parquet \
  --out-dir data/processed

python -m cybersentinel.agents.threat_detection.train \
  --train data/processed/training_prepared.parquet \
  --label-column label \
  --model-out models/threat_detection/model.joblib \
  --report-out reports/generated/threat_detection_training.json

python scripts/train_anomaly.py \
  --train data/processed/training_prepared.parquet \
  --model-out models/anomaly_detection/model.joblib

python scripts/evaluate_benchmark.py \
  --eval data/processed/eval_prepared.parquet \
  --threat-model models/threat_detection/model.joblib \
  --anomaly-model models/anomaly_detection/model.joblib \
  --output reports/generated/official-evaluation.json
```

5. Save the report with the code revision, dataset file hashes, split sizes, class-level metrics, and overlap caveat. Do not describe a score as current unless it came from that run.

For the replay workflow, use `scripts/generate_submissions.py` and validate the generated files locally. Dataset, model, and submission artifacts belong in local ignored paths unless the organizers explicitly authorize publishing them.
