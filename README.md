# CyberSentinel

**JAI 2026 · Track 1 — Agentic AI for Cybersecurity**

CyberSentinel is an offline network-flow intrusion-detection prototype. It analyses organiser-provided CICIDS2017-derived flow records using independent detection agents, fuses their evidence, and produces explainable simulated policy recommendations.

> **Scope and safety:** Offline dataset analysis and traffic replay only. No packet sniffing, active attacks, or real firewall changes. ALLOW/BLOCK/REVIEW are simulated recommendations.

## Application stack

- **Frontend:** React + TypeScript + Vite, deployed on Vercel.
- **API:** Python + FastAPI on Vercel Functions.
- **Authentication and run history:** Supabase Auth + Postgres with row-level security.
- **ML training:** Python, Pandas, NumPy, scikit-learn and Joblib. Train locally; do not train large models inside a Vercel request.
- **Inference status:** The API health endpoint is available. The Agent 1 training/prediction code is implemented, but official inference remains gated until the organiser dataset is used to train and validate the model.

## Day 1 benchmark

The organiser benchmark classes are BENIGN, BRUTE_FORCE, DOS, DDOS and PORT_SCAN. Use the exact label mapping and train/validation files supplied by organisers. Do not infer mappings. Keep official validation data unchanged.

## Architecture

1. **Threat Detection Agent** — supervised five-class classifier; returns predicted class and model-derived confidence.
2. **Anomaly Agent** — independent anomaly score and feature evidence; must not consume Agent 1's prediction.
3. **Evidence Fusion Agent** — combines both outputs, records agreement/disagreement, final class, rationale and simulated action.

Shared contracts are in src/cybersentinel/contracts.py. Pipeline orchestration is in src/cybersentinel/pipeline.py.

## Local setup

Node.js 20+ and Python 3.10+ recommended.

    npm install
    cp .env.example .env.local
    npm run dev

Set VITE_SUPABASE_URL and VITE_SUPABASE_ANON_KEY in .env.local for local auth. Never put a service-role key in frontend variables.

For Python API and ML development:

    python -m venv .venv
    source .venv/bin/activate
    pip install -e ".[dev]"

Optional XGBoost experiment:

    pip install -e ".[xgboost]"

Run frontend build and tests:

    npm run build
    pytest

## Agent 1 — Member 2 workstream

The supervised classifier is implemented in src/cybersentinel/agents/threat_detection/:

- model.py — trainable Random Forest baseline and optional XGBoost backend, preprocessing, model-derived confidence, versioned save/load.
- train.py — organiser-label mapping validation, training and optional official validation evaluation.
- predict.py — adapter preserving the main pipeline's ThreatDetectionAgent interface.
- predict_cli.py — batch CSV predictions.
- evaluate.py — accuracy, macro-F1, class-wise precision/recall/F1 and confusion matrix.

Detailed instructions and commands: docs/AGENT1.md.

Training example (replace file names and label column with the organiser's actual files/schema):

    python -m cybersentinel.agents.threat_detection.train --train-csv data/raw/train.csv --label-column Label --validation-csv data/raw/validation.csv

If source labels are not already the five canonical classes, pass --label-map with the exact organiser-provided JSON mapping. The software deliberately refuses to guess mappings. The official validation file is evaluation-only and is never used to fit preprocessing or the classifier.

## Dataset handling

Put organiser-provided CSV files under data/raw/ (git-ignored). Never commit raw or processed challenge data unless organisers explicitly permit redistribution. The web console inspects CSV headers and label distribution locally in the browser; it does not claim to perform model inference.

## Supabase and Vercel

The analysis_runs table stores per-user run metadata and measured metrics only. RLS restricts access to the authenticated row owner. Raw flow records and datasets are not stored in Supabase.

The Python API is in api/index.py. GET /api/health reports service readiness. POST /api/analyze remains fail-closed with MODEL_NOT_READY until the complete real inference pipeline and model artifacts are integrated.

## Team ownership

| Workstream | Suggested owner | Main paths |
|---|---|---|
| Data inspection and preprocessing | Teammate 1 | src/cybersentinel/data/ |
| Supervised threat classifier | Teammate 2 | src/cybersentinel/agents/threat_detection/ |
| Independent anomaly detector | Teammate 3 | src/cybersentinel/agents/anomaly_detection.py |
| Fusion, integration and submission | Team lead / integrator | src/cybersentinel/agents/fusion.py, pipeline.py, evaluation/ |

## Metrics and disclosure

Report measured accuracy, macro-F1, per-class precision/recall/F1, confusion matrix, data cleaning, split strategy and limitations. Never publish invented scores. Fit preprocessing on training data only. Disclose datasets, libraries, AI assistance and reused boilerplate as required by the hackathon rulebook.

## Current status

Agent 1's software implementation and synthetic unit tests are in place. Training and benchmark metrics on the official dataset are still pending receipt and inspection of the organiser files and exact label mapping. Agent 2, Evidence Fusion, and end-to-end official API submission remain separate integration workstreams.
