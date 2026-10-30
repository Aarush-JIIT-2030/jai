# Agent 2: Independent Anomaly Detection

## Architecture & Algorithm

- **Model:** Isolation Forest (200 trees, 50,000 max samples per tree, `n_jobs=-1`).
- **Baseline Training Data:** 240,000 `BENIGN` rows from the training partition only.
- **Independence:** Never ingests or depends on Agent 1 predictions or ground truth labels during inference.
- **Threshold Calibration:** Operating threshold is calibrated to the 1st percentile of benign training decision function scores ($\theta \approx 0.0332$).
- **Evidence Extraction:** For flows scoring below threshold, individual features deviating beyond $Q_{01}$ or $Q_{99}$ relative to benign training interquartile ranges are mapped to human-readable evidence tags (e.g., `unusual_packet_rate`, `abnormal_flow_duration`).

## Training Command

```bash
python scripts/train_anomaly.py \
  --train data/processed/training_prepared.parquet \
  --model-out models/anomaly_detection/model.joblib \
  --report-out reports/generated/agent2-training.json
```

## Measured Holdout Performance (114,185 Flows)

- **Benign False Positive Rate (FPR):** 0.958% (< 1.0% operational target).
- **Attack Anomaly Recall:** 11.71% (identifies high-volume / destructive outlier flows).
- **Inference Latency:** ~0.040 ms/flow.
