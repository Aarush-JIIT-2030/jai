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
                   [A1/A2 classification pass for every row]
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
                         │ Agent 5: Active Policy  │
                         │ Gate: BLOCK or ALLOW    │
                         └────────────┬────────────┘
                                      │ ALLOW only
                                      ▼
                         ┌─────────────────────────┐
                         │Agent 4: Temp Correlation│
                         │ (Scan / DDoS / Brute)   │
                         └────────────┬────────────┘
                                      │
                                      ▼
                         ┌─────────────────────────┐
                         │Agent 5: Adaptive Defense│
                         │Policy gate + forward rule│
                         └─────────────────────────┘
```

1. **Agent 1 (Threat Detection):** Supervised five-class Random Forest (400 estimators by default; optional XGBoost backend) for `BENIGN`, `BRUTE_FORCE`, `DOS`, `DDOS`, and `PORT_SCAN`. Confidence is the maximum temperature-scaled `predict_proba` output when the optional held-out validation calibration workflow is run; otherwise it is explicitly uncalibrated.
2. **Agent 2 (Anomaly Detection):** Independent Isolation Forest trained on benign training rows only. The baseline threshold is the first percentile of benign training decision scores; the optional held-out validation workflow selects a threshold that maximizes attack recall under a configured benign false-positive ceiling. The exported anomaly value is a bounded 0–1 index (higher means more anomalous), not a probability; the threshold is applied to the underlying decision function.
3. **Agent 3 (Evidence Fusion):** Tactical arbiter combining classification and anomaly signals into deterministic `ALLOW`, `BLOCK`, or `REVIEW` decisions (`AGREE`, `CONFLICT`, `UNCERTAIN`). Disagreements are explicitly routed to analyst review.
4. **Agent 4 (Temporal Correlation):** Stateful chronological correlator maintaining a 150-flow sliding window to detect distributed Port Scans ($\ge 5$ distinct destination ports), DDoS volumetric surges, and repeated SSH/FTP authentication sweeps.
5. **Agent 5 (Adaptive Defense):** Dynamic policy lifecycle manager that checks active unexpired rules before correlation and policy updates and generates forward-looking temporary quarantine policies (`POL-XXXXX`, `scope_type = "SOURCE_IP"`, `expires_after = step + 150`).

---

## 2. Evaluation Status & Dataset Boundaries

The data audit in [`docs/data-intelligence.md`](docs/data-intelligence.md) records the supplied split sizes, schema, cleaning decisions, and class counts. It also found 8,161 distinct feature vectors shared by training and evaluation, covering 9,795 evaluation rows (8.58%). Keep this overlap caveat with any score; the official evaluation set remains unchanged, but repeated feature vectors can make holdout results optimistic.

The repository does not include organizer data, prepared Parquet files, trained model artifacts, or generated submission CSVs. Those local files are excluded by `.gitignore`. Historical metrics in the release reports are snapshots from earlier code/data runs, not current performance claims. Reproduce the benchmark with the current code and authorized local inputs before quoting results.

## 3. Known Limitations & Judge Disclosure

Read [`docs/judge-disclosures.md`](docs/judge-disclosures.md) before the live demo. In brief:

- The CICIDS2017 feature-only split does not provide native Layer-3 source/destination addresses. When a native source IP is absent, the current implementation derives an IP-shaped `SOURCE_IP` identity from `Init_Win_bytes_forward`, `min_seg_size_forward`, and `Fwd Header Length`. **That identity is synthetic, not observed; identical fingerprints map to the same identity and the truncated 24-bit hash can collide across different clients, potentially causing false blocks.** Destination IPs are never synthesized.
- The documented train/eval feature overlap is 8.58% of evaluation rows and can make repeated-flow results optimistic.
- Agent 1 confidence is uncalibrated unless the separate held-out calibration workflow was run. Agent 2 exports a bounded 0–1 anomaly index (higher means more anomalous), not a probability; its operating threshold is applied to the underlying Isolation Forest decision function.
- The temporal correlator has a fixed 150-record cap and a configured 300-second time window when timestamps are available. Adaptive-defense policy duration defaults to 150 replay positions; these are fixed configuration values, not learned/adaptive parameters.
- Validation is limited to CICIDS2017. The workflow is offline replay, not live network monitoring; generalization to other datasets and live environments is untested.

## 4. Causal Replay Behavior

The chronological replay engine enforces these invariants:

1. Only policies active before record `N` may affect record `N`.
2. A record cannot trigger a policy that blocks itself.
3. Classifications are recorded for every input flow, including flows later blocked by an already-active simulated policy.
4. Policies expire after their configured replay interval.

All actions are simulated. The system does not modify a host firewall or inspect live network traffic.

---

## 5. Local Replay Outputs

The repository includes a generator for the three replay CSVs:

```bash
python scripts/generate_submissions.py \
  --input data/processed/hidden_replay_input.csv \
  --output-dir outputs/submission
```

This requires locally supplied evaluation data and trained model artifacts. Generated files and validation reports are ignored by Git. Place the organizer's unlabelled hidden input at data/processed/hidden_replay_input.csv before running the final Level 2 replay. The current checkout alone therefore does not establish that a fresh full-data replay passed or that a submission is ready. See [`docs/level2-brief.md`](docs/level2-brief.md) for the repository’s replay output schemas.

---

## 6. WebGL 3D SOC Command Center

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

## 7. Installation & Quickstart

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
python scripts/generate_submissions.py --input data/processed/hidden_replay_input.csv --output-dir outputs/submission
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
- `GET /api/overview` — reports operational counts from unlabelled hidden replay outputs; ground-truth performance metrics remain unavailable.
- `POST /api/fusion/simulate` — invokes the production Python Agent 3 fusion contract.
- `POST /api/replay/run-official` — runs the installed unlabelled hidden replay input chronologically and writes the three official CSVs.
- `GET /api/correlation/groups` — returns groups from the latest completed replay in the current API process, or an empty list when none exist.

If the dataset or models are missing, the API returns an explicit unavailable response. It does not substitute synthetic benchmark values or sample incidents.

### SOURCE_IP identity limitation

The prepared CICIDS2017 feature dataset does not contain native Layer-3 endpoints. The replay engine prefers a literal observed source IP; otherwise it derives a deterministic IP-shaped identity from the TCP-stack fingerprint tuple (`Init_Win_bytes_forward`, `min_seg_size_forward`, `Fwd Header Length`). This synthetic identity enables source grouping and simulated SOURCE_IP policies but is not an observed address. Identical tuples share an identity and the 24-bit suffix can collide, so unrelated clients can be grouped or blocked together. Destination IP remains unknown unless it is explicitly present. Replay metrics report how many rows used synthetic identities. See `release/benchmarks/source-ip-scope-audit.md`.

## 8. Third-Party, Reference & AI Disclosures

* **Dependencies:** `scikit-learn`, `pandas`, `numpy`, `joblib`, `fastapi`, `pydantic`, `three`, `react`, `lucide-react`, and `vite`. Their respective licenses apply.
* **Project license:** MIT License; see [`LICENSE`](LICENSE). Third-party dependencies and CICIDS2017/challenge datasets retain their own licenses and terms.
* **Dataset:** CICIDS2017 flow data and the challenge’s class mapping are governed by their respective providers and organizer terms. No challenge data is committed.
* **AI assistance:** The team reports using Antigravity and ChatGPT for code review, debugging, test design, documentation, and UI implementation assistance. Team members remain responsible for understanding and presenting the submitted code.
* **UI/UX reference:** The team reports reviewing the user-supplied `CICRCombined-main` archive for design patterns only. The related public project is [amancodes8/CICRCombined](https://github.com/amancodes8/CICRCombined). The team reports that no source files or components were copied; verify the exact archive’s license before any code reuse.
* **Architecture reference:** [Vaibhav-Patidar/cybersentinel](https://github.com/Vaibhav-Patidar/cybersentinel) was reviewed for high-level data-pipeline and evidence-presentation ideas. The team reports that no source files were copied.

Historical release and QA documents are indexed in [`release/README.md`](release/README.md); their old pass statuses are not current verification.

### Deployment boundary

The authoritative full-data workflow is local/offline. The Vercel-connected frontend/API bundle can build, but Git deployments do not include the ignored organiser dataset or fitted model artifacts; model-backed API routes therefore remain unavailable until authorised artifacts are provisioned. The Vercel function timeout is currently 30 seconds, and run history uses local SQLite rather than durable shared storage. Do not treat a READY Vercel deployment as proof of a production-ready replay service. See [`docs/deployment.md`](docs/deployment.md) for the exact runtime boundaries and local run instructions.