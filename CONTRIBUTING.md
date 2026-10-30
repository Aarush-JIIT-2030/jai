# Team contribution guide

## Workstreams
1. Data engineering: inspect organiser CSVs, document schema/labels, clean missing/infinite values, assess duplicates and leakage, build train-fitted preprocessing.
2. Threat detection: supervised five-class classifier, model-derived confidence, saved artifacts and evaluation in src/cybersentinel/agents/threat_detection/.
3. Anomaly detection: independent anomaly score and feature evidence; never use Agent 1 prediction as input.
4. Fusion/integration: shared contracts, orchestration, evidence fusion, tests, metrics and submission adapter.

## Branch workflow
Use focused branches from latest main. Open pull requests to main with summary, tests and limitations. Keep main runnable. Commit from your own GitHub account and accurately represent your own work.

## Data rules
Use organiser files and exact organiser label mapping. Never commit challenge data without permission. Fit preprocessing/resampling on training data only. Keep official validation untouched. Record cleaning decisions and report only measured metrics.

## Safety
Offline flow replay only. Do not add packet sniffing, active scanning, exploitation, or real firewall changes. ALLOW/BLOCK/REVIEW are simulated recommendations.

## Before merge
Run pip install -e ".[dev]" and pytest. Add tests for new behavior and update docs when contracts change.
