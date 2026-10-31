# CyberSentinel

**Multi-Agent Network Intrusion Detection & Adaptive Defense**  
*JAI Agentic AI International Summit 2026 · Track 1: Agentic AI for Cybersecurity*

[![Python tests](https://github.com/kaustubhdua/jai-hack/actions/workflows/python-tests.yml/badge.svg?branch=main)](https://github.com/kaustubhdua/jai-hack/actions/workflows/python-tests.yml)
[![Frontend build](https://github.com/kaustubhdua/jai-hack/actions/workflows/frontend-build.yml/badge.svg?branch=main)](https://github.com/kaustubhdua/jai-hack/actions/workflows/frontend-build.yml)

CyberSentinel is an offline multi-agent cybersecurity command platform that analyzes network-flow records, correlates multi-flow attack campaigns, fuses supervised and unsupervised evidence, and enforces temporary simulated quarantine policies. All tactical decisions—`ALLOW`, `BLOCK`, and `REVIEW`—are simulated. CyberSentinel never monitors live network sockets, injects malicious packets, or alters host operating system firewalls.

---

## 1. System Architecture & Five Cooperative Agents

CyberSentinel decomposes enterprise threat response into five specialized, cooperating agents:

```
                  ┌────────────────────────────────────────┐
                  │    Network Flow Packet Stream (CICIDS) │
                  └───────────────────┬────────────────────┘
                                      │
                 [Agent 5 Pre-Filter: Active Block Check]
                                      │
                   ┌──────────────────┴──────────────────┐
                   ▼                                     ▼
        ┌───────────────────────┐             ┌─────────────────────┐
        │  Agent 1: Threat Det  │             │ Agent 2: Anomaly Det│
        │ (Random Forest)      │             │ (Isolation Forest)  │
        └──────────┬────────────┘             └──────────┬──────────┘
                   │                                     │
                   └──────────────────┬──────────────────┘
                                      ▼
                         ┌─────────────────────────┐
                         │ Agent 3: Evidence Fusion│
                         │ (Tactical ALLOW/BLOCK)  │
                         └────────────┬────────────┘
                                      │
                                      ▼
                         ┌─────────────────────────┐
                         │Agent 4: Temp Correlation│
                         │ (Scan / DDoS / Brute)   │
                         └────────────┬────────────┘
                                      │
                                      ▼
                         ┌─────────────────────────┐
                         │Agent 5: Adaptive Defense│
                         │(Forward Policy POL-XXXX)│
                         └─────────────────────────┘
```

1. **Agent 1 (Threat Detection):** Supervised five-class Random Forest (400 estimators by default; optional XGBoost backend) for `BENIGN`, `BRUTE_FORCE`, `DOS`, `DDOS`, and `PORT_SCAN`. Its confidence is the maximum `predict_proba` output and is not calibrated.
2. **Agent 2 (Anomaly Detection):** Independent Isolation Forest trained on benign training rows only. The current implementation uses 200 trees and sets its threshold from the first percentile of training decision scores; anomaly scores are not probabilities.
3. **Agent 3 (Evidence Fusion):** Tactical arbiter combining classification and anomaly signals into deterministic `ALLOW`, `BLOCK`, or `REVIEW` decisions (`AGREE`, `DISAGREE`, `INCOMPLETE`). Disagreements are explicitly routed to analyst review.
4. **Agent 4 (Temporal Correlation):** Stateful chronological correlator maintaining a 150-flow sliding window to detect distributed Port Scans ($\ge 5$ distinct destination ports), DDoS volumetric surges, and repeated SSH/FTP authentication sweeps.
5. **Agent 5 (Adaptive Defense):** Dynamic policy lifecycle manager that evaluates incoming flows against active unexpired rules before analysis and generates forward-looking temporary quarantine policies (`POL-XXXXX`, `scope_type = "SOURCE_IP"`, `expires_after = step + 150`).

---

## 2. Evaluation Status & Dataset Boundaries

The data audit in [`docs/data-intelligence.md`](docs/data-intelligence.md) records the supplied split sizes, schema, cleaning decisions, and class counts. It also found 8,161 distinct feature vectors shared by training and evaluation, covering 9,795 evaluation rows (8.58%). Keep this overlap caveat with any score; the official evaluation set remains unchanged, but repeated feature vectors can make holdout results optimistic.

The repository does not include organizer data, prepared Parquet files, trained model artifacts, or generated submission CSVs. Those local files are excluded by `.gitignore`. Historical metrics in the release reports are snapshots from earlier code/data runs, not current performance claims. Reproduce the benchmark with the current code and authorized local inputs before quoting results.

## 3. Causal Replay Behavior

The chronological replay engine enforces these invariants:

1. Only policies active before record `N` may affect record `N`.
2. A record cannot trigger a policy that blocks itself.
3. Classifications are recorded for every input flow, including flows later blocked by an already-active simulated policy.
4. Policies expire after their configured replay interval.

All actions are simulated. The system does not modify a host firewall or inspect live network traffic.

---

## 4. Local Replay Outputs

The repository includes a generator for the three replay CSVs:

```bash
python scripts/generate_submissions.py \
  --input data/processed/eval_prepared.parquet \
  --output-dir outputs/submission
```

This requires locally supplied evaluation data and trained model artifacts. Generated files and validation reports are ignored by Git. The current checkout alone therefore does not establish that a fresh full-data replay passed or that a submission is ready. See [`docs/level2-brief.md`](docs/level2-brief.md) for the repository’s replay output schemas.

---

## 5. WebGL 3D SOC Command Center

The frontend provides a dark SOC command platform with 11 operational consoles. Screens show actual backend data when available and explicit unavailable/empty states otherwise; fabricated fallback incidents, policy rows, benchmark matrices, and replay progress are not presented. The console includes:
1. **Overview / SOC Command Center:** WebGL 3D network topology with 5-agent satellite orbits, interactive pointer tilt, threat-level toggle (`LOW`, `ELEVATED`, `CRITICAL`), real aggregate telemetry, and 2D canvas fallback.
2. **Five-Agent Architecture:** Deep-dive cards showing model parameters, input/output schemas, and microsecond latencies for Agents 1–5.
3. **Flow Inspector:** Granular flow lookup by ID, preset attack injections (Slowloris DoS, PortScan probe, SSH Brute), feature importance, and multi-agent evidence breakdown.
4. **Evidence Fusion:** Live interactive 3x3 decision matrix simulator with confidence sliders and explainable rationale output.
5. **Temporal Investigations:** Multi-flow incident tracker grouping coordinated Port Scans, DDoS amplification, and brute force campaigns.
6. **Adaptive Defense:** Stateful policy manager displaying active vs. expired host quarantine rules and interactive pre-filter tester.
7. **Replay Studio:** Interactive chronological playback with speed toggles (1x, 5x, 20x), progress bar, and streaming event telemetry.
8. **Submission Studio:** One-click official CSV bundle downloads (`/api/submissions/download/*`) and automated submission auditor.
9. **Model Intelligence:** Interactive 5x5 confusion matrix, per-class PR/F1 tables, and isolation forest calibration curves.
10. **Audit & Local History:** Offline SQLite persistence (`data/cybersentinel_history.db`) logging historical runs.
11. **Settings & System Health:** Service readiness checklist, model artifact verifier, and offline safety disclosures.

---

## 6. Installation & Quickstart

### Prerequisites
* Python 3.10+ (CI currently uses Python 3.11)
* Node.js 20+ and npm (CI uses Node 20)

### 1. Backend Setup
```bash
# Clone repository
git clone https://github.com/kaustubhdua/jai-hack.git
cd jai-hack

# Install Python ML dependencies
pip install -e ".[dev,ml]"
```

### 2. Run Reproducible Benchmark Suite
```bash
# Recomputes metrics from the authorized local dataset and model artifacts
python scripts/reproduce_benchmarks.py
```

### 3. Generate Local Replay Files
```bash
# Generates local replay CSVs when data and models are available
python scripts/generate_submissions.py --input data/processed/eval_prepared.parquet --output-dir outputs/submission
```

### 4. Run the Pytest Suite
```bash
python -m pytest tests -q
```

### 5. Frontend Setup & Build
```bash
# Install frontend dependencies
npm install

# Type-check and build
npm run build

# Start local development server
npm run dev
```

### 6. Start FastAPI Backend Server
```bash
uvicorn api.index:app --host 0.0.0.0 --port 8000 --reload
```

---



### Backend endpoints added for the final SOC workflow

- `GET /api/system/diagnostics` — reports actual local model, dataset, SQLite and submission artifact presence.
- `GET /api/overview` — computes evaluation KPIs from the installed labelled evaluation dataset and generated CSVs; labels are used only for offline metrics.
- `POST /api/fusion/simulate` — invokes the production Python Agent 3 fusion contract.
- `POST /api/replay/run-official` — runs the installed evaluation parquet chronologically and writes the three official CSVs.
- `GET /api/correlation/groups` — returns groups from the latest completed replay in the current API process, or an empty list when none exist.

If the dataset or models are missing, the API returns an explicit unavailable response. It does not substitute synthetic benchmark values or sample incidents.

### SOURCE_IP identity limitation

The prepared feature dataset may not contain native Layer 3 source IP fields. In that case the system derives a synthetic, stable identity from TCP-stack fingerprint fields. This is not an observed IP address and can collide for clients with identical fingerprints. If the required fingerprint fields are missing, policy creation fails closed rather than inventing a host identity. See `release/benchmarks/source-ip-scope-audit.md`.

## 7. Third-Party, Reference & AI Disclosures

* **Dependencies:** `scikit-learn`, `pandas`, `numpy`, `joblib`, `fastapi`, `pydantic`, `three`, `react`, `lucide-react`, and `vite`. Their respective licenses apply.
* **Project license:** No project-level `LICENSE` file is currently present. The maintainers should choose and add one before presenting this repository as reusable open-source software; no license is inferred here.
* **Dataset:** CICIDS2017 flow data and the challenge’s class mapping are governed by their respective providers and organizer terms. No challenge data is committed.
* **AI assistance:** The team reports using Antigravity and ChatGPT for code review, debugging, test design, documentation, and UI implementation assistance. Team members remain responsible for understanding and presenting the submitted code.


Historical release and QA documents are indexed in [`release/README.md`](release/README.md); their old pass statuses are not current verification.
