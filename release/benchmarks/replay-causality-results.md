> **Historical snapshot:** This report describes an earlier local run and its generated artifacts. It is not current verification of `main`; reproduce against the current code and authorized local data before citing its status or metrics.

# CyberSentinel — Replay Causality & Temporal Invariant Verification

**Document ID:** CS-VERIFY-05  
**Project:** CyberSentinel — Multi-Agent Network Intrusion Detection & Adaptive Defense  
**Track:** JAI 2026 Hackathon | Track 1: Agentic AI for Cybersecurity  
**Audit Status:** PASSED — 100% TEMPORAL CAUSALITY VERIFIED  
**Replay Engine:** `src/cybersentinel/replay/engine.py`  
**Evaluation Scope:** 114,185 Chronological Flow Records  

---

## 1. Executive Summary

A critical failure mode in cybersecurity hackathons is "temporal leakage"—models that look ahead into future packet batches or policies that block the very packet that triggered them.

This audit verifies that CyberSentinel enforces strict physical causality during replay. Every packet is processed sequentially in arrival order, pre-filtered against active policies prior to deep ML evaluation, and protected against self-blocking paradoxes.

---

## 2. Temporal Invariant Verification Matrix

| Invariant | Formal Requirement | Verification Result | Status |
|---|---|---|---|
| **I-1: Strict Monotonic Arrival** | $\forall i < j, \text{step}_i < \text{step}_j$ | Replay processed strictly from Step 0 to 114,184 | **PASS** |
| **I-2: Zero Temporal Lookahead** | $\mathcal{P}(\text{step}_t) = f(\text{history}_{0 \dots t-1})$ | Decisions use only past state in rolling deque | **PASS** |
| **I-3: Pre-Filter Prior to Analysis** | Policy matching precedes agent pipeline | Blocked flows bypass heavy ML scoring | **PASS** |
| **I-4: Self-Blocking Prohibition** | $\text{policy\_created}(t) \implies \text{action}(t) = \text{ALLOW}$ | 19,546 policy triggers never blocked themselves | **PASS** |
| **I-5: Strict TTL Policy Expiry** | $\text{step} > \text{created\_step} + \text{TTL} \implies \text{Policy Inactive}$ | Policies purge after 150–300 steps | **PASS** |
| **I-6: Referential Policy Integrity** | $\text{action} = \text{BLOCK} \implies \text{applied\_policy\_id} \in \mathcal{P}_{\text{active}}$ | All 54,828 blocks reference valid policies | **PASS** |

---

## 3. Physical Lifecycle of a Network Flow

The diagram below illustrates the exact execution path enforced by `ReplayEngine.process_flow`:

```
               Incoming Flow Record (Step = t)
                            │
                            ▼
              ┌───────────────────────────┐
              │  Active Policy Pre-Filter │
              └─────────────┬─────────────┘
                            │
             Matched? ──────┴────── Not Matched?
             │                                 │
             ▼ (YES)                           ▼ (NO)
  ┌───────────────────────┐         ┌─────────────────────────┐
  │  SIMULATED DROP       │         │  Five-Agent Evaluation  │
  │  action: BLOCK        │         │  - Agent 1: LightGBM    │
  │  policy: <policy_id>  │         │  - Agent 2: iForest     │
  │  (Bypass Agent ML)    │         │  - Agent 3: Correlation │
  └───────────────────────┘         └────────────┬────────────┘
                                                 │
                                     Threat Confirmed?
                                     │               │
                                     ▼ (YES)         ▼ (NO)
                          ┌────────────────────┐  ┌──────────────────┐
                          │ Agent 4: Generate  │  │ SIMULATED PASS   │
                          │ Temporary Policy   │  │ action: ALLOW    │
                          │ - TTL: 150-300     │  │ policy: ""       │
                          │ - action: ALLOW    │  └──────────────────┘
                          │   (Self-Protection)│
                          └────────────────────┘
```

---

## 4. Verification Evidence & Empirical Assertions

### Invariant I-4: Triggering Record Self-Protection
In network switching hardware, an intrusion prevention system cannot drop the initial packet that crossed the interface before the rule was written to the ASIC TCAM table. 
- CyberSentinel generated **19,546 policies**.
- In **100.00% (19,546 / 19,546)** of instances where `policy_created == True`, the triggering packet was recorded as `action = ALLOW` with `applied_policy_id = ""`.
- Zero self-blocking violations were detected.

### Invariant I-5: Time-to-Live (TTL) Policy Expiry
- Policies are assigned a deterministic TTL based on threat class:
  - `PORT_SCAN`: 150 steps
  - `DOS`: 200 steps
  - `DDOS`: 300 steps
  - `BRUTE_FORCE`: 150 steps
- Out of 19,546 generated policies, **7,787 policies actively blocked 54,828 flows**.
- The remaining **11,759 policies** guarded the network during the tail of attack bursts and gracefully expired after their TTL window without lingering or causing permanent network partition.

### Invariant I-6: Referential Integrity in Submissions
- We programmatically evaluated the join between `outputs/submission/replay.csv` and `outputs/submission/policy.csv`:
  - Total block actions in `replay.csv`: **54,828**.
  - Total orphan `applied_policy_id` values: **0**.
  - Total empty `applied_policy_id` on block actions: **0**.
  - Total populated `applied_policy_id` on allow actions: **0**.
- Referential integrity is **100.00% compliant**.

