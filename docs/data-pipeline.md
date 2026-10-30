# CyberSentinel Data Pipeline & Quality Controls

## Dataset Specifications

- **Archive:** `cyber-pack.zip` (CICIDS2017 flow data).
- **Partitions:**
  - `Cyber/training/flows.parquet`: 456,737 records, 80 raw columns.
  - `Cyber/eval/flows.parquet`: 114,185 records, 80 raw columns.
- **Labels:** Five canonical classes: `BENIGN`, `BRUTE_FORCE`, `DOS`, `DDOS`, `PORT_SCAN`.

## Preprocessing & Data Cleaning Discipline

1. **Identifier Leakage Exclusion:**
   - Diagnostic tests confirmed `record_id` clusters sequential labels (yielding 69.1% trivial accuracy).
   - `record_id` is excluded from all training and inference feature sets.
2. **Redundant Feature Pruning:**
   - 3 constant zero columns dropped: `Fwd URG Flags`, `Bwd URG Flags`, `URG Flag Count`.
   - 4 exact duplicate columns dropped: `Average Packet Size`, `Avg Fwd Segment Size`, `Avg Bwd Segment Size`, `Fwd Header Length_duplicated_0`.
   - Resulting feature space: **71 numeric predictors**.
3. **Imputation & Normalization:**
   - Impossible negative header lengths (found in 37 training flows and 10 eval flows) are sanitized and imputed using **training-set medians only**.
   - No evaluation records or labels are ever used to fit imputers or scalers.

## Execution Command

```bash
python -m cybersentinel.data.cleaning \
  --train data/raw/training/flows.parquet \
  --eval data/raw/eval/flows.parquet \
  --out-dir data/processed
```
Outputs `training_prepared.parquet` and `eval_prepared.parquet`.
