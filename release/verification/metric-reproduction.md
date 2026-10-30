# CyberSentinel — Metric Reproduction & Mathematical Identity Verification

**Document ID:** CS-VERIFY-02  
**Project:** CyberSentinel — Multi-Agent Network Intrusion Detection & Adaptive Defense  
**Track:** JAI 2026 Hackathon | Track 1: Agentic AI for Cybersecurity  
**Audit Status:** PASSED — 100% REPRODUCIBILITY CONFIRMED  
**Dataset:** `data/eval_prepared.parquet` (114,185 records, 72 features)  
**Execution Timestamp:** 2026-10-31T00:36:58+05:30  

---

## 1. Executive Summary

This document presents the independent, script-verified evaluation metrics and conservation identities derived from the complete 114,185-record test evaluation. Every figure reported is calculated directly from `outputs/submission/replay.csv` and `data/eval_prepared.parquet` without interpolation, estimation, or smoothing.

All six fundamental conservation identities pass with zero discrepancy.

---

## 2. Core Replay Accounting Table

| Metric | Verified Value | Percentage / Basis | Description |
|---|---|---|---|
| **Total Evaluation Flows** | **114,185** | 100.00% | Complete test evaluation dataset |
| **Total Attack Flows** | **54,184** | 47.45% of total | Ground-truth malicious traffic flows |
| **Total Benign Flows** | **60,001** | 52.55% of total | Ground-truth normal background traffic |
| **Total Blocked Flows** | **54,828** | 48.02% of total | Total flows dropped by active defense policies |
| **Total Allowed Flows** | **59,357** | 51.98% of total | Total flows permitted through simulation filter |
| **Correctly Contained Attacks** | **48,219** | **88.99%** of attacks | Malicious flows actively blocked |
| **Attacks Permitted (Misses)** | **5,965** | 11.01% of attacks | Attacks allowed before policy activation or after TTL |
| **Benign Preserved (Passing)** | **53,392** | **88.99%** of benign | Legitimate traffic allowed without disruption |
| **False Blocks** | **6,609** | 11.01% of benign | Legitimate traffic dropped due to temporal cluster collision |
| **Block Precision** | **87.95%** | 48,219 / 54,828 | Percentage of blocked packets that were confirmed attacks |
| **Policies Generated** | **19,546** | — | Temporary simulated firewall defense rules |
| **Active Blocking Policies** | **7,787** | 39.84% of policies | Policies that intercepted $\ge 1$ subsequent flow |
| **Replay Execution Time** | **17.84 seconds** | — | End-to-end chronological replay duration |
| **Replay Throughput** | **6,400.6 FPS** | — | Sustained flows processed per second |

---

## 3. Mathematical Identity Proofs

In a rigorous cybersecurity evaluation, the conservation of packet flow counts across decision boundaries must hold strictly. The following identities were tested programmatically against `outputs/submission/replay.csv`:

### Identity 1: Conservation of Total Actions
$$\text{Total Records} = \text{Blocked Records} + \text{Allowed Records}$$
$$114{,}185 = 54{,}828 + 59{,}357 \implies \mathbf{114{,}185 = 114{,}185} \quad [\textbf{PASS}]$$

### Identity 2: Decomposition of Block Actions
$$\text{Blocked Records} = \text{Correctly Blocked Attacks} + \text{False Blocks}$$
$$54{,}828 = 48{,}219 + 6{,}609 \implies \mathbf{54{,}828 = 54{,}828} \quad [\textbf{PASS}]$$

### Identity 3: Decomposition of Allow Actions
$$\text{Allowed Records} = \text{Benign Preserved} + \text{Attacks Allowed}$$
$$59{,}357 = 53{,}392 + 5{,}965 \implies \mathbf{59{,}357 = 59{,}357} \quad [\textbf{PASS}]$$

### Identity 4: Ground Truth Population Totals
$$\text{Total Records} = \text{Total Attacks} + \text{Total Benign}$$
$$114{,}185 = 54{,}184 + 60{,}001 \implies \mathbf{114{,}185 = 114{,}185} \quad [\textbf{PASS}]$$

### Identity 5: Attack Influx Balance
$$\text{Total Attacks} = \text{Correctly Blocked Attacks} + \text{Attacks Allowed}$$
$$54{,}184 = 48{,}219 + 5{,}965 \implies \mathbf{54{,}184 = 54{,}184} \quad [\textbf{PASS}]$$

### Identity 6: Benign Influx Balance
$$\text{Total Benign} = \text{Benign Preserved} + \text{False Blocks}$$
$$60{,}001 = 53{,}392 + 6{,}609 \implies \mathbf{60{,}001 = 60{,}001} \quad [\textbf{PASS}]$$

---

## 4. Per-Class Attack Containment Breakdown

| Threat Category | Ground-Truth Count | Blocked (Contained) | Allowed (Missed) | Containment Rate | Primary Defense Mechanism |
|---|---|---|---|---|---|
| **`PORT_SCAN`** | 14,400 | 13,841 | 559 | **96.12%** | Rapid TCP port dispersion correlation + Host-level CIDR clamp |
| **`DDOS`** | 14,400 | 13,259 | 1,141 | **92.08%** | High-velocity volume burst correlation + Aggressive 300-step rate clamp |
| **`DOS`** | 24,000 | 20,090 | 3,910 | **83.71%** | State exhaustion anomaly detection + TCP teardown rate limit |
| **`BRUTE_FORCE`** | 1,384 | 1,029 | 355 | **74.35%** | Authentication failure clustering + Host IP drop |
| **`BENIGN`** | 60,001 | 6,609 (False Block) | 53,392 (Preserved) | **88.99% (Preserved)** | Window eviction gating prevents runaway false triggers |

---

## 5. False Block Root-Cause & Resolution Proof

During exploratory stress testing of early run baselines, false blocks were measured at 28,423 flows due to unbounded port tracking in `TemporalCorrelationAgent`:

- **The Defect:** Stale destination ports were accumulated in host sets across the entire lifetime of the process without deque eviction. Consequently, after observing benign web browsing spanning 5 distinct remote endpoints, the host was permanently flagged as an active `PORT_SCAN` attacker for the remainder of the 114k flows.
- **The Resolution:** Implemented exact window-bounded frequency tracking using `Counter[int]` with active decrement/removal during FIFO eviction, paired with a threat-class gate restricting port-scan heuristics to unclassified/suspicious flows.
- **The Measured Impact:**
  - False blocks decreased from **28,423 to 6,609** (a **76.7% reduction**).
  - Benign traffic preserved increased from **31,578 (52.6%) to 53,392 (88.99%)**.
  - Malicious attack containment remained robust at **48,219 (88.99%)**.

