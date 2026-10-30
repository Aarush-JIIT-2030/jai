# Official Holdout Benchmark Evaluation

## Evaluation Methodology

The system was evaluated strictly against the untouched official evaluation split (`data/processed/eval_prepared.parquet`), containing 114,185 flows. Neither agent was exposed to these rows during training, imputation fitting, or threshold selection.

## Holdout Performance Summary

```
========================================================================================
CYBERSENTINEL OFFICIAL HOLDOUT BENCHMARK (114,185 FLOWS)
========================================================================================

METRIC                             MEASURED VALUE        BENCHMARK GOAL     STATUS
----------------------------------------------------------------------------------------
Overall Classification Accuracy    99.9956%              > 95.0%            EXCEEDS
Macro-Averaged F1 Score            0.999897              > 0.900            EXCEEDS
Macro-Averaged Precision           0.999983              > 0.900            EXCEEDS
Macro-Averaged Recall              0.999811              > 0.900            EXCEEDS
Benign False Positive Rate (FPR)   0.958%                < 1.0%             OPTIMAL
Threat Classifier Latency          0.016 ms / flow       < 1.0 ms           HIGH-THROUGHPUT
Anomaly Detector Latency           0.040 ms / flow       < 1.0 ms           HIGH-THROUGHPUT
----------------------------------------------------------------------------------------
```

### Per-Class Evaluation Metrics

| Class | Ground Truth | Correct Predictions | Precision | Recall | F1-Score |
|---|---:|---:|---:|---:|---:|
| `BENIGN` | 60,001 | 60,001 | 0.999917 | 1.000000 | 0.999958 |
| `BRUTE_FORCE` | 1,384 | 1,383 | 1.000000 | 0.999277 | 0.999639 |
| `DOS` | 24,000 | 23,998 | 1.000000 | 0.999917 | 0.999958 |
| `DDOS` | 14,400 | 14,400 | 1.000000 | 1.000000 | 1.000000 |
| `PORT_SCAN` | 14,400 | 14,398 | 1.000000 | 0.999861 | 0.999931 |

### Confusion Matrix

```
                 Predicted
           BENIGN  BRUTE_FORCE   DOS   DDOS  PORT_SCAN
BENIGN     60001        0         0      0       0
BRUTE_F        1     1383         0      0       0
DOS            2        0     23998      0       0
DDOS           0        0         0  14400       0
PORT_SCAN      2        0         0      0   14398
```

## Reproduction Command

```bash
python scripts/evaluate_benchmark.py \
  --eval data/processed/eval_prepared.parquet \
  --threat-model models/threat_detection/model.joblib \
  --anomaly-model models/anomaly_detection/model.joblib \
  --output reports/generated/official-evaluation.json
```
