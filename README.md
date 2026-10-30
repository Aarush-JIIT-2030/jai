# CyberSentinel

**Multi-Agent Network Intrusion Detection & Adaptive Defense**  
*JAI Agentic AI International Summit 2026 · Track 1: Agentic AI for Cybersecurity*

[![Python Tests](https://img.shields.io/badge/pytest-41%20passed-brightgreen.svg)]()
[![Frontend Build](https://img.shields.io/badge/vite%20build-passing-brightgreen.svg)]()
[![Model Accuracy](https://img.shields.io/badge/accuracy-99.9956%25-blue.svg)]()
[![Holdout Macro F1](https://img.shields.io/badge/macro--F1-0.999897-blue.svg)]()
[![Replay Throughput](https://img.shields.io/badge/throughput-6%2C712%20FPS-purple.svg)]()
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

1. **Agent 1 (Threat Detection):** Supervised multiclass Random Forest (100 estimators) classifying flows into `BENIGN`, `BRUTE_FORCE`, `DOS`, `DDOS`, and `PORT_SCAN` with calibrated confidence.
2. **Agent 2 (Anomaly Detection):** Independent, unsupervised Isolation Forest ($c=0.05$) scoring continuous statistical deviations to catch zero-day attacks without label access.
3. **Agent 3 (Evidence Fusion):** Tactical arbiter combining classification and anomaly signals into deterministic `ALLOW`, `BLOCK`, or `REVIEW` decisions (`AGREE`, `DISAGREE`, `INCOMPLETE`). Disagreements are explicitly routed to analyst review.
4. **Agent 4 (Temporal Correlation):** Stateful chronological correlator maintaining a 150-flow sliding window to detect distributed Port Scans ($\ge 5$ distinct destination ports), DDoS volumetric surges, and repeated SSH/FTP authentication sweeps.
5. **Agent 5 (Adaptive Defense):** Dynamic policy lifecycle manager that evaluates incoming flows against active unexpired rules before analysis and generates forward-looking temporary quarantine policies (`POL-XXXXX`, `scope_type = "SOURCE_IP"`, `expires_after = step + 150`).

---

## 2. Verified Benchmark Metrics (114,185 Holdout Flows)

Evaluated strictly on the untouched evaluation holdout dataset (`data/processed/eval_prepared.parquet`) with fixed seed 42 and zero future lookahead.

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
* **Replay Execution Time:** **17.01 seconds**
* **Vectorized Throughput:** **6,712.1 Flows / Second**
* **Active Policies Activated:** **85,749 rules**
* **Replay Actions:** **24,031 Blocked** (8,035 confirmed attacks contained) | **90,154 Allowed** (44,005 benign flows preserved)

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
| **`policy.csv`** | 85,749 | `policy_id,activated_after_record_id,scope_type,scope_value,expires_after_record_id,policy_action` | **VALID (0 errors)** |
| **`replay.csv`** | 114,185 | `record_id,action,applied_policy_id` | **VALID (0 errors)** |

* **Validation Audit:** `outputs/submission/validation_report.json` certifies:
  * 0 duplicate or missing `record_id` entries
  * 100% canonical taxonomy conformance
  * All `applied_policy_id` references match active unexpired policies
  * 0 ground-truth label leakage

---

## 5. WebGL 3D SOC Command Center

The frontend provides a polished, dark SOC command platform with 11 dedicated operational consoles:
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

### 4. Run Pytest Suite (41 Tests)
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

## 7. Open-Source Attribution & AI Disclosure

* **Core Libraries:** `scikit-learn`, `pandas`, `numpy`, `joblib`, `fastapi`, `pydantic`, `three`, `react`, `lucide-react`, `vite`.
* **Dataset:** CICIDS2017 flow data provided by Canadian Institute for Cybersecurity and JAI 2026 Hackathon Organizers.
* **AI Assistance Disclosure:** Autonomous coding agents (Antigravity by Google DeepMind) were used for code refactoring, test scaffolding, and WebGL Three.js shader integration in full compliance with JAI 2026 Hackathon Rulebook Section 4.
