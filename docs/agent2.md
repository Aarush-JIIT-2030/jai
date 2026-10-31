# Agent 2: Independent Anomaly Detection

## Architecture & Algorithm

- **Model:** Isolation Forest (200 trees, 50,000 max samples per tree, `n_jobs=-1`).
- **Baseline Training Data:** 240,000 `BENIGN` rows from the training partition only.
- **Independence:** Never ingests or depends on Agent 1 predictions or ground truth labels during inference.
- **Threshold Calibration:** Operating threshold is calibrated to the 1st percentile of benign training decision function scores ($\theta \approx 0.0332$).
- **Evidence Extraction:** For flows whose raw decision-function score falls below the threshold, individual features deviating beyond $Q_{01}$ or $Q_{99}$ relative to benign training interquartile ranges are mapped to human-readable evidence tags (e.g., `unusual_packet_rate`, `abnormal_flow_duration`).

## Training Command

```bash
python scripts/train_anomaly.py \
  --train data/processed/training_prepared.parquet \
  --model-out models/anomaly_detection/model.joblib \
  --report-out reports/generated/agent2-training.json
```

## Evaluation Status

No current official-evaluation FPR, attack recall, or latency result is reproducible from this repository alone because the evaluation data and trained model artifact are not committed. Older release reports contain different values; treat them as historical and do not cite them as current.

To produce current metrics, train from the authorized benign training rows, evaluate against the untouched evaluation split, and retain the report with the code revision and dataset hashes. See [`docs/evaluation.md`](evaluation.md).
