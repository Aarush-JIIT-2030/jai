# CyberSentinel

**JAI 2026 · Track 1 — Agentic AI for Cybersecurity**

CyberSentinel is an offline network-flow intrusion-detection prototype. It analyses organiser-provided CICIDS2017-derived flow records using independent detection agents, fuses their evidence, and produces explainable simulated policy recommendations.

> **Scope and safety:** Offline dataset analysis and traffic replay only. No packet sniffing, active attacks, or real firewall changes. ALLOW/BLOCK/REVIEW are simulated recommendations.

## Application stack

- **Frontend:** React + TypeScript + Vite, deployed on Vercel.
- **API:** Python + FastAPI on Vercel Functions.
- **Authentication and run history:** Supabase Auth + Postgres with row-level security.
- **ML training:** Python, Pandas, NumPy, scikit-learn, Joblib and PyArrow. Train locally; do not train large models inside a Vercel request.
- **Inference status:** The API health endpoint is available. Agent 1 software and Member 1 data preprocessing are implemented. Official classifier metrics and complete inference remain pending; the API stays fail-closed until trained artifacts and both agents are integrated.

## Day 1 benchmark

The organiser benchmark classes are BENIGN, BRUTE_FORCE, DOS, DDOS and PORT_SCAN. Use the exact label mapping and official train/eval files. The supplied files for the current data work are Parquet files; their `label` values already use the five canonical classes. Keep the official eval data unchanged.

## Architecture

1. **Threat Detection Agent** — supervised five-class classifier; returns predicted class and model-derived confidence.
2. **Anomaly Agent** — independent anomaly score and feature evidence; must not consume Agent 1's prediction.
3. **Evidence Fusion Agent** — combines both outputs, records agreement/disagreement, final class, rationale and simulated action.

Shared contracts are in `src/cybersentinel/contracts.py`. Pipeline orchestration is in `src/cybersentinel/pipeline.py`.

## Local setup

Node.js 20+ and Python 3.10+ recommended.

```bash
npm install
cp .env.example .env.local
npm run dev
```

Set `VITE_SUPABASE_URL` and `VITE_SUPABASE_ANON_KEY` in `.env.local` for local auth. Never put a service-role key in frontend variables.

For Python API and ML development:

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev,ml]"
```

Optional XGBoost experiment:

```bash
pip install -e ".[ml,xgboost]"
```

Run frontend build and tests:

```bash
npm run build
pytest
```

## Agent 1 — Member 2 workstream

The supervised classifier is implemented in `src/cybersentinel/agents/threat_detection/`:

- `model.py` — Random Forest baseline and optional XGBoost backend, train-fitted preprocessing, model-derived confidence, versioned save/load.
- `train.py` — organiser-label mapping validation, training and optional official validation evaluation.
- `predict.py` — adapter preserving the main pipeline's `ThreatDetectionAgent` interface.
- `predict_cli.py` — batch CSV predictions.
- `evaluate.py` — accuracy, macro-F1, class-wise precision/recall/F1 and confusion matrix.

Detailed instructions and commands: [`docs/AGENT1.md`](docs/AGENT1.md).

The current Agent 1 training and prediction command-line tools read CSV. The Member 1 data-preparation tool reads the supplied Parquet files and writes prepared Parquet files. Convert prepared files to CSV or add Parquet support to the Agent 1 CLI before training this exact dataset with that command.

If source labels are not already the five canonical classes, pass `--label-map` with the exact organiser-provided JSON mapping. The software deliberately refuses to guess mappings. The official eval file is evaluation-only and must never be used to fit preprocessing or the classifier.

## Dataset handling — Member 1 workstream

The inspected files contain 456,737 training rows and 114,185 eval rows, with 78 numeric measurements, `record_id`, and `label`. The audit found no null or infinite values and no duplicate full rows or IDs. It also found class imbalance, repeated feature vectors across splits, sequential-ID leakage risk, and a small number of impossible negative header lengths. Full findings and limitations are in [`docs/data-intelligence.md`](docs/data-intelligence.md).

Place the organiser files locally under `data/raw/` (this directory is git-ignored), then run:

```bash
python -m cybersentinel.data.cleaning \
  --train data/raw/training/flows.parquet \
  --eval data/raw/eval/flows.parquet \
  --out-dir data/processed
```

The preprocessor learns feature selection and fill values from training only, excludes `record_id` from model inputs, preserves every row, and applies the same rules to eval. The output and fitted preprocessing state go under `data/processed/`, which is git-ignored. Never commit raw or processed challenge data unless organisers explicitly permit redistribution.

The progress Q&A based on work completed to date is in [`docs/day1-progress-questionnaire.md`](docs/day1-progress-questionnaire.md). It is a working status document, not an organiser-provided form.

## Supabase and Vercel

The `analysis_runs` table stores per-user run metadata and measured metrics only. RLS restricts access to the authenticated row owner. Raw flow records and datasets are not stored in Supabase.

The Python API is in `api/index.py`. `GET /api/health` reports service readiness. `POST /api/analyze` remains fail-closed with `MODEL_NOT_READY` until the complete real inference pipeline and model artifacts are integrated.

## Team ownership

| Workstream | Suggested owner | Main paths |
|---|---|---|
| Data inspection and preprocessing | Member 1 | `src/cybersentinel/data/` |
| Supervised threat classifier | Member 2 | `src/cybersentinel/agents/threat_detection/` |
| Independent anomaly detector | Member 3 | `src/cybersentinel/agents/anomaly_detection.py` |
| Fusion, integration and submission | Team lead / integrator | `src/cybersentinel/agents/fusion.py`, `pipeline.py`, `evaluation/` |

## Metrics and disclosure

Report measured accuracy, macro-F1, per-class precision/recall/F1, confusion matrix, data cleaning, split strategy and limitations. Never publish invented scores. Fit preprocessing on training data only. Disclose datasets, libraries, AI assistance and reused boilerplate as required by the hackathon rulebook.

## Current status

- **Member 1 data audit and preprocessing:** completed for the supplied Parquet files; code and aggregate findings are merged in [PR #6](https://github.com/kaustubhdua/jai-hack/pull/6). No challenge rows or fitted values are committed.
- **Agent 1 software:** implemented and merged in [PR #5](https://github.com/kaustubhdua/jai-hack/pull/5). It has not yet produced official benchmark metrics on the supplied files.
- **Agent 2 anomaly detector:** not implemented yet; the current module is a placeholder.
- **Evidence fusion:** not implemented yet; the current module is a placeholder.
- **Official evaluation and submission:** benchmark accuracy/macro-F1 and API submission are still pending. The API remains fail-closed until the full inference pipeline is ready.
