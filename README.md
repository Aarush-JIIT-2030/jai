# CyberSentinel

**JAI 2026 · Track 1 — Agentic AI for Cybersecurity**

CyberSentinel is an offline network-flow intrusion-detection prototype. It analyses organiser-provided CICIDS2017-derived flow records using independent detection agents, fuses their evidence, and produces explainable simulated policy recommendations.

> **Scope and safety:** Offline dataset analysis and traffic replay only. No packet sniffing, active attacks, or real firewall changes. ALLOW/BLOCK/REVIEW are simulated recommendations.

## Application stack

- **Frontend:** React + TypeScript + Vite, deployed on Vercel.
- **API:** Python + FastAPI on Vercel Functions.
- **Authentication and run history:** Supabase Auth + Postgres with row-level security.
- **ML training:** Python, Pandas, NumPy, scikit-learn and Joblib. Train locally; do not train large models inside a Vercel request.
- **Inference status:** API health endpoint is available. Predictions intentionally remain disabled until real models are trained and verified on organiser data.

## Day 1 benchmark

The organiser benchmark classes are `BENIGN`, `BRUTE_FORCE`, `DOS`, `DDOS`, and `PORT_SCAN`. Use the exact label mapping and train/validation files supplied by organisers. Do not infer mappings. Keep official validation data unchanged.

## Architecture

1. **Threat Detection Agent** — supervised five-class classifier; returns predicted class and confidence.
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

Set `VITE_SUPABASE_URL` and `VITE_SUPABASE_ANON_KEY` in `.env.local` for local auth. The publishable key is intended for browser use; database access is protected by RLS. Never put a service-role key in frontend variables.

For Python API development:

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

For local ML training and evaluation dependencies:

```bash
pip install -r requirements-ml.txt
```

Run frontend build and tests:

```bash
npm run build
pytest
```

## Dataset handling

Put organiser-provided CSV files under `data/raw/` (git-ignored). Never commit raw or processed challenge data unless organisers explicitly permit redistribution. The current web console inspects CSV headers and label distribution locally in the browser; it does not upload the file. It does not claim to perform model inference.

## Supabase

The `analysis_runs` table stores per-user run metadata and measured metrics only. RLS restricts select/insert/update/delete to the authenticated row owner. Raw flow records and uploaded datasets are not stored in Supabase.

## Vercel deployment

The Vercel project is connected to `kaustubhdua/jai-hack` and configured for Vite. Required frontend variables:

- `VITE_SUPABASE_URL`
- `VITE_SUPABASE_ANON_KEY`

The Python API is in `api/index.py`. `GET /api/health` reports service readiness. `POST /api/analyze` fails closed with `MODEL_NOT_READY` until the real inference pipeline and model artifacts are integrated.

## Team ownership

| Workstream | Suggested owner | Main paths |
|---|---|---|
| Data inspection and preprocessing | Teammate 1 | `src/cybersentinel/data/` |
| Supervised threat classifier | Teammate 2 | `src/cybersentinel/agents/threat_detection.py` |
| Independent anomaly detector | Teammate 3 | `src/cybersentinel/agents/anomaly_detection.py` |
| Fusion, integration, evaluation | Team lead / integrator | `src/cybersentinel/agents/fusion.py`, `pipeline.py`, `evaluation/` |

See [CONTRIBUTING.md](CONTRIBUTING.md) for branches, interface rules and data safety.

## Metrics and disclosure

Report measured accuracy, macro-F1, per-class precision/recall/F1, confusion matrix, data cleaning, split strategy and limitations. Never publish invented scores. Fit preprocessing on training data only. Disclose datasets, libraries, AI assistance and reused boilerplate as required by the hackathon rulebook.

## Current status

The web console, Supabase auth/history foundation, RLS-protected metadata table and Vercel API health endpoint are scaffolded. Model training, actual predictions, fusion decisions and official validation metrics remain pending receipt and inspection of the organiser dataset and label mapping.
