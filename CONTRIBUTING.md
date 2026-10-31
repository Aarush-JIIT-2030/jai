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

## Repository hygiene

Keep these out of Git:

- Secrets, access tokens, private keys, and real `.env` files. Use `.env.example` with placeholders.
- Organizer-provided CSV, Parquet, PCAP, or other challenge records unless the organizers explicitly authorize publication.
- Prepared datasets, fitted model binaries, generated benchmark reports, submission CSVs, local databases, and run outputs.
- Dependency folders, build outputs, local virtual environments, and downloaded archives such as ZIP files.

The existing `.gitignore` covers these local artifacts. Before committing, check `git status --short` and confirm ignored files remain ignored. Publish an artifact separately only when it is authorized and needed for release.

## Before merge
Run pip install -e ".[dev]" and pytest. Add tests for new behavior and update docs when contracts change.
