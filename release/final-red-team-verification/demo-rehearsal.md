# CyberSentinel — Hackathon Live Demo Rehearsal & Presentation Script

**Document ID:** CS-VERIFY-09  
**Project:** CyberSentinel — Multi-Agent Network Intrusion Detection & Adaptive Defense  
**Track:** JAI 2026 Hackathon | Track 1: Agentic AI for Cybersecurity  
**Audit Status:** REHEARSED & READY — 5-MINUTE LIVE DEMONSTRATION RUNBOOK  
**Audience:** Technical Judges, Security Evaluators, AI Researchers  

---

## 1. Demo Structure & Timing Blueprint

This script is structured for a 5-minute live judging evaluation, showcasing technical depth, live WebGL interactivity, rigorous mathematics, and transparent engineering honesty.

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                       5-MINUTE PANEL PRESENTATION TIMELINE                  │
├─────────────┬─────────────────────────────────┬─────────────────────────────┤
│ Timestamp   │ Segment                         │ Primary Screen / Action     │
├─────────────┼─────────────────────────────────┼─────────────────────────────┤
│ 00:00-00:45 │ Hook & Architecture Overview    │ Slide / Console 01 Overview │
│ 00:45-01:45 │ WebGL 3D SOC & Spatial Topology │ Console 01 WebGL 3D Canvas  │
│ 01:45-02:45 │ Five-Agent Defense Pipeline     │ Consoles 03, 04, 05 & 06    │
│ 02:45-03:30 │ Live Scenario Trigger & Policy  │ Scenario Launcher & Replay  │
│ 03:30-04:15 │ Mathematical Proofs & Metrics   │ Console 09 Evaluation Suite │
│ 04:15-05:00 │ Submission Lockdown & Q&A       │ Console 10 Submission Hub   │
└─────────────┴─────────────────────────────────┴─────────────────────────────┘
```

---

## 2. Step-by-Step Presenter Script

### Minute 0:00 – 0:45: Hook & System Purpose
- **Action:** Open browser at `http://localhost:5173/`. Landing screen is `Console 01: Overview`.
- **Spoken Narrative:**
  > "Good morning judges. In modern cloud and enterprise perimeters, attacks evolve faster than static firewall rules can be manually authored. CyberSentinel is an autonomous, five-agent network intrusion detection and adaptive defense system. It doesn't just classify threats—it formulates temporary, simulated firewall policies to actively contain cascading attack bursts while preserving legitimate enterprise traffic. Over 114,185 evaluation flows, CyberSentinel achieved an 88.99% attack containment rate while maintaining 88.99% benign traffic availability with strict physical causality and zero lookahead."

### Minute 0:45 – 01:45: WebGL 3D Command Center Interactivity
- **Action:** Use mouse to rotate the 3D topology. Click on the `Threat Classifier` node. The Node Telemetry Drawer slides out from the right. Click `Reset View`. Click `2D View` toggle, then switch back to `3D View`.
- **Spoken Narrative:**
  > "Here in our SOC Command Center, we render a hardware-accelerated 3D WebGL topology built in Three.js. Each tier represents a vital layer of enterprise defense—from internet ingress and perimeter firewalls down to our five agent pods and internal databases. Clicking any node engages our raycasting engine, surfacing real-time packet throughput and health metrics. If an analyst operates on a lightweight terminal or remote tablet, a single click toggles instantly to an interactive 2D SVG topological schematic."

### Minute 01:45 – 02:45: The Five-Agent Pipeline in Action
- **Action:** Click `Threat Detection` in the sidebar, then `Zero-Day Anomalies`, then `Correlation Hub`, and finally `Policy Guardrails`.
- **Spoken Narrative:**
  > "Our architecture divides defense among five specialized agents:
  > - **Agent 1 (Classifier):** LightGBM model categorizing flows into 5 classes with sub-millisecond inference.
  > - **Agent 2 (Anomaly Detector):** Isolation Forest identifying zero-day mutations and stealthy volumetric drift.
  > - **Agent 3 (Temporal Correlation):** Sliding-window correlation that unmasks distributed port scans and multi-vector DDoS floods.
  > - **Agent 4 (Policy Engine):** Generates time-bounded, simulated firewall rules with adaptive TTLs.
  > - **Agent 5 (Reporter):** Generates automated incident narratives with SHAP feature explanations."

### Minute 02:45 – 03:30: Live Attack Scenario & Causality Verification
- **Action:** Return to `Overview` and click the `Launch DDoS Scenario` button. Point to the packet pulses turning crimson and the active policy table populating.
- **Spoken Narrative:**
  > "Let's trigger an incoming DDoS attack burst. Notice two critical invariants:
  > 1. **Zero Self-Blocking:** The packet that triggers policy creation is never blocked itself—adhering to real-world network physics.
  > 2. **Pre-Filtering:** As soon as the rule is active, subsequent attack packets are dropped at the pre-filter stage, saving expensive ML scoring."

### Minute 03:30 – 04:15: Mathematical Verification & Identity Proofs
- **Action:** Click `Evaluation Suite` in the sidebar. Scroll to the green mathematical conservation cards.
- **Spoken Narrative:**
  > "We hold our evaluation to absolute mathematical rigor. Across all 114,185 flows, every single packet is accounted for:
  > - 54,828 blocked + 59,357 allowed = exactly 114,185 total flows.
  > - 48,219 correctly blocked attacks + 6,609 false blocks = 54,828 blocked flows.
  > - In earlier prototypes, false blocks reached 28,000 due to unbounded state leakage. By auditing and fixing our sliding-window port tracking, we reduced false blocks by 76.7%."

### Minute 04:15 – 05:00: Submission Integrity & Mandatory Disclosure
- **Action:** Click `Submission Manager`. Highlight the three green checkmarks and SHA-256 hashes.
- **Spoken Narrative:**
  > "All three official submission files—`classification.csv`, `policy.csv`, and `replay.csv`—pass the organizer validation suite with zero errors. Furthermore, in the spirit of engineering transparency, we explicitly disclose that because the benchmark parquet omitted raw IP columns, CyberSentinel derives host identities via passive client TCP stack fingerprinting across 2,484 host clusters. Thank you, and we welcome your questions."

---

## 3. Disaster Recovery & Fallback Runbook

| Failure Mode | Trigger / Symptom | Recovery Action |
|---|---|---|
| **WebGL Context Lost** | GPU driver reset or browser tab suspended | Click the "2D View" toggle on the top right of the canvas. The system falls back to 2D SVG instantly. |
| **Backend API Disconnected** | Terminal window closed or process killed | Restart backend in terminal: `python -m uvicorn src.cybersentinel.server.app:app --port 8000`. Frontend reconnects automatically. |
| **Browser Freezes** | Out of memory on low-spec hardware | Refresh browser (`Ctrl+F5`). State is persistently restored from local storage and backend SQLite cache. |

