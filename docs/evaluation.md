# Model Training, Evaluation and Hidden Replay

## Dataset boundaries

The organizer's `cyber-pack.zip` contains the labelled CICIDS2017 training and evaluation partitions. Its manifest records 456,737 training rows and 114,185 evaluation rows with five canonical classes. The separate `cyber-hidden.zip` contains exactly 200 unlabelled Level 2 records with literal source/destination endpoints and organizer sequence/time metadata.

The data audit found 8,161 exact feature vectors shared by training and evaluation, covering 9,795 evaluation rows (8.58%). Keep this overlap caveat with any evaluation score. Do not alter the official evaluation partition to remove it.

## 1. Install and verify organizer packs

```bash
python scripts/prepare_challenge_data.py \
  --training-pack cyber-pack.zip \
  --hidden-pack cyber-hidden.zip
```

This writes the training and evaluation Parquet partitions plus `data/processed/hidden_replay_input.csv` into ignored local paths. The installer verifies the training/evaluation byte counts and SHA-256 hashes against the organizer manifest, checks the hidden input's 200 unique IDs and exact 1..200 sequence, confirms the 78 numeric flow features and validates observed endpoint fields. It does not add labels to hidden rows.

Install the ML dependencies:

```bash
python -m pip install -e ".[dev,ml]"
```

## 2. Train both production agents

```bash
python scripts/train_models.py \
  --train data/raw/training/flows.parquet
```

This trains A1 on the five labelled classes and A2 on BENIGN training rows only. It reloads both saved artifacts and writes per-agent reports plus `reports/generated/training_manifest.json`. The hidden input is not read by the training command.

A separate labelled validation partition is optional. If and only if organizers provide one, pass it with `--validation path/to/labelled_validation.parquet`. A1 uses it for temperature calibration and validation metrics; A2 uses it for threshold selection under the configured benign-FPR ceiling. Do not pass the hidden input. Do not use the held-out evaluation partition as a calibration/tuning set.

When no separate labelled validation file is supplied, A1 confidence remains uncalibrated and A2 uses its training-only benign baseline threshold. This is explicitly recorded in the training manifest.

## 3. Evaluate on the untouched labelled evaluation partition

```bash
python scripts/evaluate_benchmark.py \
  --eval data/raw/evaluation/flows.parquet \
  --threat-model models/threat_detection/model.joblib \
  --anomaly-model models/anomaly_detection/model.joblib \
  --output reports/generated/official_evaluation.json
```

This command loads existing artifacts and scores the labelled evaluation partition. It does not fit, calibrate, or select thresholds. Treat its output as the current evaluation only when it was produced by the exact current code revision and verified input hashes. Include the 8.58% repeated-feature overlap caveat.

## 4. Generate and independently validate all 200 hidden records

```bash
python scripts/generate_submissions.py \
  --input data/processed/hidden_replay_input.csv \
  --output-dir outputs/submission

python scripts/validate_submissions.py \
  --input data/processed/hidden_replay_input.csv \
  --output-dir outputs/submission
```

The exact templates are:

- `classification.csv`: `record_id,predicted_class,anomaly_score,evidence_status`
- `replay.csv`: `record_id,action,active_policy_id`
- `policies.csv`: `policy_id,activated_after_record_id,scope_type,scope_value,expires_after_record_id`

The validator verifies exact headers, all hidden IDs in original order, five-class labels, finite 0–1 anomaly scores, organizer evidence states, literal observed endpoint scopes, activation-exclusive/expiry-inclusive policy windows, `ALLOW` with `NONE`, and the lexicographically smallest matching policy for every `BLOCK`.

A limited `--limit` run is a smoke test only and cannot be submitted. The hidden set has no labels, so attack/benign accuracy, false-block rate, and containment rate must not be inferred from its predictions. A local validation pass is not organizer acceptance; only an actual successful organizer response/receipt proves acceptance.

## Artifact hygiene

Organizer data, fitted model binaries, reports, generated CSVs, and local databases are excluded from Git. Do not commit them unless organizers explicitly authorize publication. Preserve local SHA-256 hashes, code revision, training provenance, and validation report for reproducibility.
