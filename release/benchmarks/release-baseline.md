> **Historical snapshot:** This report describes an earlier local run and its generated artifacts. It is not current verification of `main`; reproduce against the current code and authorized local data before citing its status or metrics.

# CyberSentinel — Release Baseline Verification

**Document ID:** CS-VERIFY-01  
**Project:** CyberSentinel — Multi-Agent Network Intrusion Detection & Adaptive Defense  
**Track:** JAI 2026 Hackathon | Track 1: Agentic AI for Cybersecurity  
**Repository:** `https://github.com/kaustubhdua/jai-hack`  
**Base Commit SHA:** `f29cb03`  
**Active Verification Branch:** `main`  
**Audit Timestamp:** 2026-10-31T00:58:00+05:30  
**Audit Status:** PASSED — BASELINE CONFIRMED  

---

## 1. Executive Summary

This release baseline audit establishes the cryptographic, structural, and execution baseline of the CyberSentinel project prior to final release lockdown. CyberSentinel is a five-agent autonomous network intrusion detection and adaptive defense system featuring causal chronological replay, zero temporal lookahead, explainable multi-agent telemetry, and a WebGL-accelerated 3D SOC Command Center.

All verification steps documented herein were executed directly against the local repository without mocking, label leakage, or ungrounded claims.

---

## 2. Git & Version Control State

| Property | Value / Verified State |
|---|---|
| **Repository URL** | `https://github.com/kaustubhdua/jai-hack` |
| **Active Local Branch** | `main` |
| **Tracking Upstream** | `origin/main` (at `f29cb03`) |
| **Working Tree** | Clean (0 uncommitted modifications prior to verification artifact creation) |
| **Base Release Commit** | `f29cb03` (`chore(release): lock down world-class SOC release and synchronize`) |
| **Python Environment** | Python 3.14.6 (Windows AMD64) |
| **Node.js Environment** | Node.js v20.18.0 / npm 10.8.2 |

---

## 3. Repository Architecture & File Inventory

The CyberSentinel repository is partitioned into clean, decoupled operational layers:

```
jai-hack/
├── data/
│   └── eval_prepared.parquet          # 114,185 preprocessed flow records (72 features)
├── models/
│   ├── threat_classifier.joblib       # Primary LightGBM multi-class model (5 classes)
│   └── anomaly_detector.joblib        # Unsupervised IsolationForest novelty detector
├── src/
│   ├── cybersentinel/
│   │   ├── agents/                    # Five-agent core implementation
│   │   │   ├── base.py                # Abstract base agent and telemetry contracts
│   │   │   ├── classification.py      # Agent 1: Threat Classification Agent (LightGBM)
│   │   │   ├── anomaly.py             # Agent 2: Zero-Day Anomaly Detection Agent (iForest)
│   │   │   ├── correlation.py         # Agent 3: Temporal Correlation Agent (Windowed)
│   │   │   ├── policy.py              # Agent 4: Adaptive Policy Engine (Simulated Guardrails)
│   │   │   └── reporter.py            # Agent 5: Threat Explanation & Reporting Agent
│   │   ├── replay/
│   │   │   └── engine.py              # Causal Replay Engine (Pre-filter -> Classify -> Mitigate)
│   │   ├── evaluation/
│   │   │   ├── evaluator.py           # Metrics calculation & containment accounting
│   │   │   └── validator.py           # Submission file contract validator
│   │   └── server/
│   │       └── app.py                 # FastAPI operational backend with SSE streaming
│   ├── components/                    # Frontend React/TypeScript UI & WebGL 3D Topology
│   │   ├── NetworkTopology3D.tsx      # Three.js interactive 3D WebGL network graph
│   │   ├── TopologyCommandCentre.tsx  # Dual-mode 3D/2D command center with raycasting
│   │   ├── NavigationBar.tsx          # Top nav with health indicators & scenario launcher
│   │   └── Level2Consoles.tsx         # 11 Dedicated SOC application consoles
│   ├── App.tsx                        # Root React layout and telemetry bus
│   └── main.tsx                       # Frontend DOM entry point
├── tests/                             # Pytest test suite (60 unit + adversarial tests)
├── outputs/submission/                # Official hackathon submission artifacts
│   ├── classification.csv             # 114,185 threat prediction rows
│   ├── policy.csv                     # 19,546 temporary simulated defense rules
│   ├── replay.csv                     # 114,185 chronological replay action rows
│   ├── summary.json                   # Aggregated run metrics
│   └── validation_report.json         # SubmissionValidator pass report
└── release/                           # Verification dossiers & runbooks
```

---

## 4. Submission Artifact Verification Baseline

The submission files in `outputs/submission/` were generated during the validated evaluation run and verified for cryptographic integrity:

| File | Row Count | File Size (Bytes) | SHA-256 Checksum |
|---|---|---|---|
| `classification.csv` | 114,185 | 3,285,637 | `FAABB0B6752EA258F652A0687B3AC75943C8A37D621EDA25F53C1A48D60608BB` |
| `policy.csv` | 19,546 | 1,034,097 | `46AFB05427B9C8679190B2D207B346018B1E85CAB24B67A4327C2DD61280C712` |
| `replay.csv` | 114,185 | 2,095,153 | `91FA36AD38932164938C22EECED13F0BBFD062A1F13C0CF391575831A012D3C9` |
| `summary.json` | 12 | 293 | `6BA2F17DC6370BEC495AFCCAEEFA1AF33ADFAC2A48DE37BF6FF6A1B521F5639C` |
| `validation_report.json` | 114,196 | 5,276,049 | `A5459ED335A9A16872912999417755C131185062693937F72D3A84F71D25E7DB` |

---

## 5. Security & Boundary Commitments

1. **Strictly Offline Simulation:** CyberSentinel is designed for deterministic, offline traffic evaluation. At no point does the system execute commands modifying host firewall tables (e.g., `netsh advfirewall`, `iptables`, `nftables`). All policy enforcement occurs strictly within the in-memory simulation filter.
2. **Zero Temporal Lookahead:** Traffic records are evaluated in strict sequence arrival order (`step = 0, 1, 2, ...`). The system has zero knowledge of future packets, total burst lengths, or ground truth labels during execution.
3. **Triggering Flow Protection:** The packet that triggers a policy creation is never self-blocked (`action = ALLOW`, `applied_policy_id = ""`), adhering to causal network latency physics.

