# CyberSentinel System Architecture

## Overview

CyberSentinel is an offline, five-agent network intrusion detection and adaptive defense framework built for JAI 2026 Hackathon Track 1. It evaluates CICIDS2017 network flow records across five benchmark classes using two independent detection agents, an evidence fusion matrix, a temporal correlation engine, and an adaptive policy manager.

```mermaid
flowchart TD
    subgraph Ingress ["1. Ingress & Pre-Filter"]
        A[Offline Flow Stream N] --> PF{Agent 5: Active Policy Pre-Filter}
        PF -->|Active Match| BLK[Action: BLOCK<br/>Applied Policy ID]
        PF -->|No Match| ALW[Action: ALLOW<br/>Forwarded for Analysis]
    end

    subgraph Detection ["2. Independent Detection (A1 + A2)"]
        ALW --> D1[Agent 1: Threat Detection<br/>Supervised Multiclass LightGBM<br/>Class + Confidence]
        ALW --> D2[Agent 2: Anomaly Detection<br/>Unsupervised Isolation Forest<br/>Score + Feature Evidence]
    end

    subgraph FusionAndCorrelation ["3. Correlation & Fusion (A3 + A4)"]
        D1 --> F3[Agent 3: Evidence Fusion<br/>Consensus Arbitration Matrix<br/>Status: AGREE / DISAGREE / INCOMPLETE]
        D2 --> F3
        ALW --> C4[Agent 4: Temporal Correlation<br/>150-Flow Sliding Window<br/>Multi-Stage Campaign Tracking]
        F3 --> C4
    end

    subgraph DefenseResponse ["4. Adaptive Defense (A5)"]
        C4 --> R5[Agent 5: Adaptive Policy Engine<br/>Generate Temporary SOURCE_IP Policies<br/>Finite Step TTL Expiration]
        R5 -.->|Activate for Later Flows > N| PF
    end

    subgraph Submission ["5. Competition Outputs"]
        D1 & D2 & F3 --> CSV1[(classification.csv<br/>All 114,185 Records)]
        R5 --> CSV2[(policy.csv<br/>Generated Policies)]
        PF & ALW --> CSV3[(replay.csv<br/>ALLOW / BLOCK Decisions)]
    end
```

## Five-Agent Responsibilities

1. **Agent 1 (Threat Detection Agent):**
   - Implements supervised five-class classification (`BENIGN`, `BRUTE_FORCE`, `DOS`, `DDOS`, `PORT_SCAN`).
   - Uses class-weighted LightGBM with robust imputation for missing, infinite, and out-of-distribution values.
   - Outputs predicted class and calibrated confidence score $[0.0, 1.0]$.

2. **Agent 2 (Anomaly Detection Agent):**
   - Independent baseline trained strictly on benign baseline network traffic.
   - Uses Isolation Forest with threshold calibration ($\approx 0.0332$).
   - Flags deviations without consuming Agent 1 outputs or labels.
   - Extracts feature-level evidence tags (e.g., `unusual_packet_rate`, `abnormal_flow_duration`).

3. **Agent 3 (Evidence Fusion Agent):**
   - Orchestrates deterministic consensus between Agent 1 and Agent 2.
   - Evaluates agreement (`AGREE`), disagreement (`DISAGREE`), and incomplete evidence (`INCOMPLETE`).
   - Routes conflicting or ambiguous predictions safely to fail-closed `REVIEW`.

4. **Agent 4 (Temporal Correlation Agent):**
   - Maintains a stateful 150-flow sliding window across arrival order.
   - Correlates isolated probes into multi-stage attack campaigns: distributed Port Scans, DDoS amplification bursts, and authentication sweeps.
   - Extracts target endpoints, member records, and threat group IDs.

5. **Agent 5 (Adaptive Defense Agent):**
   - Evaluates active policies before newly allowed flows are analyzed.
   - Generates temporary `SOURCE_IP` quarantine policies with explicit activation and expiration boundaries (`expires_after_record_id`).
   - Strictly enforces that the triggering flow is never self-blocked.
   - Never applies live firewall changes; all policies are simulated within the replay framework.

## Replay Engine & Causal Invariants

The chronological replay engine enforces strict causality guarantees:
- **Arrival-Order Processing:** Flows are evaluated strictly sequentially.
- **Pre-Filter First:** Only policies activated prior to record $N$ can drop flow $N$.
- **Universal Forensics:** Every flow, including those blocked by earlier policies, is classified in `classification.csv`.
- **Zero Label Leakage:** Ground-truth labels are never accessed during replay decision making.