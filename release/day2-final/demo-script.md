# CyberSentinel — Hackathon Presentation & Live Demo Script

## JAI 2026 | Track 1: Agentic AI for Cybersecurity
**Duration:** 5 Minutes | **Format:** Live Technical Walkthrough & Architecture Defense

---

### [00:00 - 01:00] The Problem & The Multi-Agent Architecture
**Speaker:**
> *"Welcome, judges. In high-throughput enterprise networks, traditional signature IDS systems miss novel attacks, while monolithic ML classifiers generate unacceptable false alarm rates and lack explainability.*
>
> *For JAI 2026 Track 1, we built **CyberSentinel: Multi-Agent Network Intrusion Detection & Adaptive Defense**.*
>
> *Rather than relying on a single black-box model, CyberSentinel decomposes network defense into five autonomous, cooperating agents:*
> 1. * **Agent 1 (Threat Detection):** Calibrated multiclass Random Forest classifying 5 canonical threat categories with 99.99% accuracy.*
> 2. * **Agent 2 (Anomaly Detection):** Unsupervised Isolation Forest identifying zero-day outliers with under 1% benign FPR.*
> 3. * **Agent 3 (Evidence Fusion):** Tactical arbitrator uniting supervised classification and anomaly signals into deterministic ALLOW, BLOCK, or REVIEW decisions.*
> 4. * **Agent 4 (Temporal Correlation):** Pattern correlation engine linking isolated packet flows into multi-stage attack campaigns: Port Scans, DDoS amplification, and brute-force sweeps.*
> 5. * **Agent 5 (Adaptive Defense):** Dynamic policy manager that generates time-bounded, causal defense policies without live firewall disruption.*

---

### [01:00 - 02:30] WebGL Command Center & Live SOC Experience
*(Switch to browser screen showing the CyberSentinel SOC Command Center)*

**Speaker:**
> *"Here on the CyberSentinel Command Center, you see our hardware-accelerated 3D WebGL network topology.*
>
> *Our 5 agents are visualized as cooperating satellite nodes around the central network core. As traffic shifts from LOW to CRITICAL threat levels, the WebGL shader coordinates visual telemetry, particle velocity, and threat alerts in real time.*
>
> *Let's navigate through our operational tabs:*
> * **Overview:** Shows real-time aggregate defense telemetry, containment rate (33.4%), and throughput (>6,700 flows/sec).*
> * **Flow Analysis:** Provides SOC tier-1 analysts with granular flow inspection, feature importances, and Agent 2 anomaly calibration histograms.*
> * **Temporal Correlation:** Highlights correlated threat groups identified by Agent 4, showing how individual benign-looking port probes resolve into an active Port Scan campaign.*
> * **Adaptive Defense:** Displays the live policy lifecycle. Every temporary block rule has an explicit activation record ID and expiration tick, ensuring benign services are not permanently blackholed.*
> * **Replay & Submissions Studio:** Allows on-demand batch replay simulation and official three-file submission export.*
> * **Evidence History:** Connects to our offline SQLite storage database, logging every audit run for forensic compliance.*"

---

### [02:30 - 03:45] The Causal Replay Engine & Day 2 Invariants
*(Open Replay & Submissions Studio or terminal showing replay benchmark)*

**Speaker:**
> *"The hardest challenge in cybersecurity evaluation is temporal causality. Many hackathon projects cheat by looking ahead at future packets or blocking an attack using a rule triggered in that very same packet.*
>
> *CyberSentinel strictly enforces causal replay invariants:*
> 1. * **Pre-Filter Enforcement:** When flow $N$ arrives, only policies activated *prior* to $N$ ($< N$) can block it.*
> 2. * **Triggering Flow Protection:** The record that triggers a policy is never blocked by its own rule.*
> 3. * **Universal Classification:** Even if a flow is dropped at the firewall boundary by an active policy, CyberSentinel still computes and logs full threat predictions for forensic auditing.*
> 4. * **Throughput:** On the full 114,185 evaluation dataset, our vectorized replay engine completed all 114,185 flows in just **17.01 seconds**—exceeding 6,700 flows per second on standard hardware.*"

---

### [03:45 - 04:30] Submission CSV Verification & Results
*(Highlight `outputs/submission/` validation report)*

**Speaker:**
> *"We generated all three required submission files:*
> * `classification.csv`: 114,185 records with canonical classes, normalized anomaly scores, and evidence status.*
> * `policy.csv`: 85,749 deterministic time-bounded block policies.*
> * `replay.csv`: 114,185 records indicating exact simulation actions and valid policy cross-references.*
>
> *We developed an automated `SubmissionValidator` that verifies foreign key integrity, schema column headers, and mathematical bounds. The entire submission bundle passed with **0 errors** and status `READY_FOR_SUBMISSION`.*"

---

### [04:30 - 05:00] Summary & Q&A
**Speaker:**
> *"In summary, CyberSentinel is not a prototype or a conceptual slideshow. It is a tested, high-throughput, offline-safe, five-agent cybersecurity platform ready for production deployment.*
>
> *Thank you, and we welcome your questions!"*

