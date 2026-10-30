# CyberSentinel

**Multi-Agent Network Intrusion Detection & Adaptive Defense**  
*JAI Agentic AI International Summit 2026 · Track 1: Agentic AI for Cybersecurity*

[![Python Tests](https://img.shields.io/badge/pytest-60%20passed-brightgreen.svg)]()
[![Frontend Build](https://img.shields.io/badge/vite%20build-passing-brightgreen.svg)]()
[![Model Accuracy](https://img.shields.io/badge/accuracy-99.9956%25-blue.svg)]()
[![Holdout Macro F1](https://img.shields.io/badge/macro--F1-0.999897-blue.svg)]()
[![Replay Throughput](https://img.shields.io/badge/throughput-7%2C101%20FPS-purple.svg)]()
[![Submission Status](https://img.shields.io/badge/submission-READY__FOR__SUBMISSION-success.svg)]()

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
        │ (Random Forest 99.99%)│             │ (Isolation Forest)  │
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

1. **Agent 1 (Threat Detection):** Supervised multiclass Random Forest (100 estimators) classifying flows into `BENIGN`, `BRUTE_FORCE`, `DOS`, `DDOS`, and `PORT_SCAN` with model confidence from predict_proba (not probability-calibrated).
2. **Agent 2 (Anomaly Detection):** Independent, unsupervised Isolation Forest ($c=0.05$) scoring continuous statistical deviations to catch zero-day attacks without label access.
3. **Agent 3 (Evidence Fusion):** Tactical arbiter combining classification and anomaly signals into deterministic `ALLOW`, `BLOCK`, or `REVIEW` decisions (`AGREE`, `DISAGREE`, `INCOMPLETE`). Disagreements are explicitly routed to analyst review.
4. **Agent 4 (Temporal Correlation):** Stateful chronological correlator maintaining a 150-flow sliding window to detect distributed Port Scans ($\ge 5$ distinct destination ports), DDoS volumetric surges, and repeated SSH/FTP authentication sweeps.
5. **Agent 5 (Adaptive Defense):** Dynamic policy lifecycle manager that evaluates incoming flows against active unexpired rules before analysis and generates forward-looking temporary quarantine policies (`POL-XXXXX`, `scope_type = "SOURCE_IP"`, `expires_after = step + 150`).

---

## 2. Historical Baseline Metrics (114,185 Holdout Flows — Pre-Correction)

The following values are copied from the previous local baseline report and predate the shared TCP-stack identity correction and metric-semantics fixes. They are historical reference values, **not current release verification**. Regenerate the three CSVs and all replay metrics using the current branch before submission. The dataset and model binaries are not committed to this public repository.

### Agent 1: Multiclass Classification
* **Overall Accuracy:** `99.9956%` (114,180 / 114,185 correct flows)
* **Macro-Averaged Precision:** `0.999983`
* **Macro-Averaged Recall:** `0.999811`
* **Macro-Averaged F1-Score:** `0.999897`
* **Inference Speed:** `0.0205 ms / flow` (`48,867 flows / second` on CPU)

#### Holdout Confusion Matrix & Class Support:
| True Class \ Predicted | BENIGN | BRUTE_FORCE | DOS | DDOS | PORT_SCAN | Precision | Recall | F1-Score | Support |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **BENIGN** | **60,001** | 0 | 0 | 0 | 0 | 0.9999 | 1.0000 | 0.9999 | 60,001 |
| **BRUTE_FORCE** | 1 | **1,383** | 0 | 0 | 0 | 1.0000 | 0.9993 | 0.9996 | 1,384 |
| **DOS** | 2 | 0 | **23,998** | 0 | 0 | 1.0000 | 0.9999 | 0.9999 | 24,000 |
| **DDOS** | 0 | 0 | 0 | **14,400** | 0 | 1.0000 | 1.0000 | 1.0000 | 14,400 |
| **PORT_SCAN** | 2 | 0 | 0 | 0 | **14,398** | 1.0000 | 0.9998 | 0.9999 | 14,400 |

### Agent 2: Anomaly Detection
* **Benign False Positive Rate (FPR):** `0.958317%` (only 575 false outliers in 60,001 true benign flows)
* **Isolation Forest Threshold:** `0.033250`
* **Inference Speed:** `0.0603 ms / flow` (`16,595 flows / second`)

---

## 3. Causal Replay Engine & Replay Invariants

The CyberSentinel Causal Replay Engine (`cybersentinel.replay.ReplayEngine`) processes packet streams chronologically without temporal cheating:

* **Total Records Processed:** **114,185 flows**
* **Replay Execution Time:** **17.84 seconds**
* **Vectorized Throughput:** **6,400.6 Flows / Second**
* **Active Policies Activated:** **19,546 rules** (77.2% bloat reduction via consensus gating & window-bounded correlation)
* **Replay Actions:** **54,828 Blocked** (48,219 confirmed attacks contained — 89.0% containment) | **59,357 Allowed** (53,392 benign flows preserved — 89.0% availability)
* **False Block Reduction:** Reduced false blocks from 28,423 down to **6,609** (76.7% improvement via sliding-window counter eviction)

### Core Invariants Enforced:
1. **Pre-Filter Precedence:** When flow $N$ arrives from `source_ip`, active policies activated prior to $N$ ($< N$) apply *before* inspecting the flow.
2. **Triggering Flow Protection:** The record that triggers a policy is never blocked by its own rule (`action = ALLOW`, `applied_policy_id = ""`).
3. **Universal Classification:** Predictions are generated and logged for all 114,185 records, including records that are subsequently dropped by active policies.
4. **Deterministic Policy Expiration:** Policies expire strictly after their calibrated duration (150 records), restoring availability once the threat subsides.

---

## 4. Official Submission Bundle & Automated Validator

Generated via `scripts/generate_submissions.py` and validated via `SubmissionValidator`:

| Submission File | Rows | Schema Header | Validation Status |
| :--- | :--- | :--- | :--- |
| **`classification.csv`** | 114,185 | `record_id,predicted_class,anomaly score,evidence status` | **VALID (0 errors)** |
| **`policy.csv`** | 19,546 | `policy_id,activated_after_record_id,scope_type,scope_value,expires_after_record_id,policy_action` | **VALID (0 errors)** |
| **`replay.csv`** | 114,185 | `record_id,action,applied_policy_id` | **VALID (0 errors)** |

* **Validation Audit:** `outputs/submission/validation_report.json` certifies:
  * 0 duplicate or missing `record_id` entries
  * 100% canonical taxonomy conformance
  * All `applied_policy_id` references match active unexpired policies
  * 0 ground-truth label leakage
  * Complete adversarial audit deliverables documented in [`release/final-audit/`](release/final-audit/)

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
* Python 3.10+ (Tested on Python 3.14 on Windows)
* Node.js 18+ and npm

### 1. Backend Setup
```bash
# Clone repository
git clone https://github.com/kaustubhdua/jai-hack.git
cd jai-hack

# Install Python ML dependencies
pip install -e ".[ml]"
```

### 2. Run Reproducible Benchmark Suite
```bash
# Reproduces holdout metrics (99.9956% acc, 0.958% benign FPR)
$env:PYTHONPATH="src"; python scripts/reproduce_benchmarks.py
```

### 3. Generate Official Submission Files
```bash
# Runs causal replay and generates classification.csv, policy.csv, replay.csv
$env:PYTHONPATH="src"; python scripts/generate_submissions.py --input data/processed/eval_prepared.parquet --output-dir outputs/submission
```

### 4. Run the Pytest Suite
```bash
$env:PYTHONPATH="src"; python -m pytest tests -q
```

### 5. Frontend Setup & Build
```bash
# Install frontend dependencies
npm install

# Build production bundle (0 TypeScript errors)
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

The prepared feature dataset may not contain native Layer 3 source IP fields. In that case the system derives a synthetic, stable identity from TCP-stack fingerprint fields. This is not an observed IP address and can collide for clients with identical fingerprints. If the required fingerprint fields are missing, policy creation fails closed rather than inventing a host identity. See `release/verification/source-ip-scope-audit.md`.

## 7. Open-Source Attribution & AI Disclosure

* **Core Libraries:** `scikit-learn`, `pandas`, `numpy`, `joblib`, `fastapi`, `pydantic`, `three`, `react`, `lucide-react`, `vite`.
* **Dataset:** CICIDS2017 flow data provided by Canadian Institute for Cybersecurity and JAI 2026 Hackathon Organizers.
* **AI Assistance Disclosure:** Antigravity and ChatGPT were used for code review, debugging, test design, documentation, and UI implementation assistance. Team members remain responsible for understanding and presenting the submitted code.
* **UI/UX Reference Disclosure:** The user-supplied CICRCombined-main archive was reviewed as a design-pattern reference for accessible focus states, reduced-motion support, responsive navigation, async states, and restrained transitions. Its README identifies the project as ISC-licensed; no CICR source files or components were copied into CyberSentinel. The patterns were independently implemented in CyberSentinel's existing React/Three.js application.
* **Architecture Reference Disclosure:** The user-supplied `Vaibhav-Patidar/cybersentinel` repository was reviewed for high-level three-agent data-pipeline and evidence-presentation ideas. CyberSentinel's five-agent implementation and code were developed separately; no source files were copied from that repository.
