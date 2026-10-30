# CyberSentinel — Local Setup & Execution Guide

## Requirements

* Python 3.10+ (tested on Python 3.14)
* Node.js 18+ & npm
* Offline environment (no external cloud services required)

---

## 1. Backend Setup & Pytest Execution

```powershell
# Set Python path to src directory
$env:PYTHONPATH="src"

# Run the complete test suite (36 tests)
python -m pytest tests -q

# Start the FastAPI backend locally
uvicorn api.index:app --host 127.0.0.1 --port 8000
```

Backend endpoints will be available at `http://127.0.0.1:8000`:
* `/api/health` — 5-agent health status
* `/api/models/status` — Model artifacts & metadata
* `/api/history` — Local SQLite run history
* `/api/analyze` — Single-flow analysis through all 5 agents
* `/api/replay/simulate` — Replay simulation endpoint
* `/api/replay/validate` — Submission bundle validation

---

## 2. Frontend Setup & Build

```powershell
# Install frontend dependencies
npm install

# Run Vite development server
npm run dev

# Or build the production bundle
npm run build
```

Web console opens at `http://localhost:5173`.
* Full offline Guest Mode is enabled (no Supabase credentials needed).
* WebGL 3D network topology runs hardware-accelerated with dynamic 2D canvas fallback.

---

## 3. Generate Submission CSV Files

To replay any dataset (e.g. `eval_prepared.parquet` or Day 2 hidden test data) and generate the official 3 CSV files:

```powershell
$env:PYTHONPATH="src"
python scripts/generate_submissions.py `
  --input data/processed/eval_prepared.parquet `
  --output-dir outputs/submission
```

Output files produced in `outputs/submission/`:
1. `classification.csv`
2. `policy.csv`
3. `replay.csv`
4. `summary.json`
5. `validation_report.json`
