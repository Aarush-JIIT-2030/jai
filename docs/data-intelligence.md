# Official flow dataset: Member 1 data handoff

This audit uses the organizer-provided training and eval Parquet files. It records measured data properties and preprocessing decisions for the Day 1 five-class benchmark. No raw or processed challenge rows are included in this document.

## Dataset shape and target

| Split | Rows | Columns | Numeric traffic features |
|---|---:|---:|---:|
| Training | 456,737 | 80 | 78 |
| Eval | 114,185 | 80 | 78 |

Both files have the same schema and column order. The 80 columns consist of 78 numeric flow measurements, `record_id`, and `label`. The target values are already the organizer's five canonical labels: `BENIGN`, `BRUTE_FORCE`, `DOS`, `DDOS`, and `PORT_SCAN`.

## Class distribution

| Class | Training rows | Training % | Eval rows | Eval % |
|---|---:|---:|---:|---:|
| BENIGN | 240,000 | 52.55% | 60,001 | 52.55% |
| BRUTE_FORCE | 5,537 | 1.21% | 1,384 | 1.21% |
| DOS | 96,000 | 21.02% | 24,000 | 21.02% |
| DDOS | 57,600 | 12.61% | 14,400 | 12.61% |
| PORT_SCAN | 57,600 | 12.61% | 14,400 | 12.61% |

The class mix is nearly identical across the two files. BRUTE_FORCE is the rare class (about 43 times fewer training rows than BENIGN), so evaluation should include macro-F1 and class-level results. Keep the official eval set unchanged.

## Data quality and repeated observations

- Neither file contains null cells or infinite numeric values.
- Neither file contains duplicate full rows or duplicate `record_id` values.
- Repeated feature vectors do exist even though IDs differ: 39,423 training rows across 15,291 repeated groups; 4,066 eval rows across 1,793 groups. There are no feature groups with conflicting labels within either split.
- 8,161 distinct feature vectors appear in both splits. They cover 15,884 training rows and 9,795 eval rows (8.58% of eval); the shared vectors have no label conflicts. This overlap may make eval performance optimistic for repeated flows, so disclose it when reporting results. Do not remove rows from the official eval set.
- Some byte-header lengths are negative, which is not valid for a length measurement. Negative `Fwd Header Length` values occur in 37 training and 10 eval rows; negative `Bwd Header Length` values occur in 70 training and 16 eval rows. All are BENIGN. `Fwd Header Length_duplicated_0` exactly repeats the forward field.

## Leakage and redundant features

`record_id` is a sequential source-row identifier. Labels cluster across ranges of these IDs. A diagnostic that divides the training ID range into ten bins, assigns each bin its most common training label, and applies those labels to eval reaches 69.1% accuracy and 0.513 macro-F1. This is not a classifier result; it demonstrates that the identifier can leak label information. Keep IDs for traceability, but exclude them from model inputs.

Three numeric columns are constant zero: `Fwd URG Flags`, `Bwd URG Flags`, and `URG Flag Count`. Four more columns are exact copies of an earlier feature:

- `Avg Fwd Segment Size` duplicates `Fwd Packet Length Mean`.
- `Avg Bwd Segment Size` duplicates `Bwd Packet Length Mean`.
- `Fwd Header Length_duplicated_0` duplicates `Fwd Header Length`.
- `Average Packet Size` duplicates `Packet Length Mean`.

The prepared matrix therefore has 71 numeric features plus the string target label.

## Preprocessing contract

`src/cybersentinel/data/cleaning.py` provides `FlowPreprocessor` for shared train/eval preparation:

1. Fit the preprocessor on the labeled training frame only.
2. Convert infinities to missing values and mark negative header lengths as invalid.
3. Remove constant features and exact duplicate feature columns, based only on training data.
4. Fill missing/invalid values with the training median for each retained feature.
5. Transform eval with the same retained columns and training medians. Keep the row order and every row.
6. Exclude `record_id` from X. The ID can be returned separately for traceability; the label stays separate from X.
7. Use `transform_features(..., scaled=True)` when an algorithm needs comparable feature scales. Robust centers and interquartile ranges are learned on training data only; the default prepared files remain on the original measurement scales.

Example:

```python
import pandas as pd
from cybersentinel.data.cleaning import FlowPreprocessor

train = pd.read_parquet("data/raw/training/flows.parquet")
evaluation = pd.read_parquet("data/raw/eval/flows.parquet")
prep = FlowPreprocessor().fit(train)
train_ready = prep.transform(train)          # 71 features + label; no ID
eval_ready = prep.transform(evaluation)       # same columns and train-fitted rules
X_eval_scaled = prep.transform_features(evaluation, scaled=True)
labels, record_ids = prep.labels_and_ids(evaluation)
prep.save("data/processed/preprocessing_state.json")
```

To generate the local prepared Parquet files and audit JSON from the command line:

```bash
pip install -e ".[ml]"
python -m cybersentinel.data.cleaning \
  --train data/raw/training/flows.parquet \
  --eval data/raw/eval/flows.parquet \
  --out-dir data/processed
```

`data/processed/` is git-ignored. Do not commit organizer records, prepared Parquet files, or fitted preprocessing state. This documentation contains aggregate audit results only.

## Scope

This is the Member 1 dataset and preprocessing handoff. It does not train the supervised classifier, anomaly detector, or evidence-fusion agent, and it does not submit results to the organizer API. The challenge remains an offline flow-replay task.
