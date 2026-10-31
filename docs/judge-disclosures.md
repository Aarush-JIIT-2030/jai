# Judge-facing limitations and honest demo disclosures

This document is the short, defensible disclosure to use in the judge briefing. It distinguishes current implementation behavior from a possible synthetic-identity compatibility mode.

## 1. SOURCE_IP is not necessarily an observed address

The CICIDS2017 prepared feature matrix contains numeric flow features and labels, not native Layer-3 source/destination addresses. The current hardened branch only accepts literal observed IPv4/IPv6 addresses. It does not manufacture IP addresses from model features. When the organizer input has no observed source IP, Agent 4 endpoint correlation reports `not_ready` and Agent 5 does not create SOURCE_IP policies.

A legacy/alternate compatibility implementation can derive a pseudo-IP from TCP-stack fingerprint fields (for example, `Init_Win_bytes_forward`, `min_seg_size_forward`, and `Fwd Header Length`). If that mode is used, say plainly: **the SOURCE_IP value is synthetic, not an observed Layer-3 address; identical fingerprints can map to the same value, so distinct clients can collide and a resulting block can affect benign traffic.** Collision rates and false-block impact must be measured on the exact replay input. Do not imply this fallback is enabled in the current hardened branch.

This is an important organizer-contract question: the current validator requires policy scope to match a literal IP in the original input. A synthetic pseudo-IP needs explicit organizer acceptance and a matching validator contract.

## 2. Evaluation overlap

The dataset audit found 8,161 distinct feature vectors shared by training and evaluation, covering 9,795 evaluation rows (8.58% of the evaluation split). This overlap can make repeated-flow results optimistic. The official evaluation split is not modified to remove the overlap. Disclose the caveat alongside any metric.

## 3. Scores are not automatically probabilities

- **Agent 1:** the maximum `predict_proba` output is uncalibrated unless the optional scalar temperature-calibration workflow was run on a separate, labelled, held-out validation file. Do not call it a calibrated probability otherwise.
- **Agent 2:** Isolation Forest's decision-function-derived anomaly score is a raw score, not a probability of attack. Its threshold can optionally be selected on separate labelled validation data under a configured benign false-positive ceiling.

Report the exact model artifact and calibration provenance used for the run.

## 4. Fixed temporal and policy parameters

- Agent 4 has a 150-record sliding-window cap. When usable timestamps exist, it also applies the configured 300-second age window. These are fixed configuration parameters, not learned or adaptive window sizes.
- Agent 5's default policy duration is 150 replay positions, capped to the number of later records remaining in the current replay. This is a fixed rule, not an adaptive learned expiry model.

The replay is chronological and causal: a policy is created after its trigger and may affect only later records.

## 5. Dataset and operating scope

- Model and benchmark validation are based on CICIDS2017 only.
- The system is an offline flow-replay and simulated-defense platform. It does not inspect live sockets, capture packets, or alter operating-system firewalls.
- Generalization to other datasets, network environments, and live deployments is untested.

## 6. Reproducibility and submission status

The repository contains code and CI tests, but the organizer's hidden unlabeled replay input and final API contract are not part of the repository. A successful unit-test run is not proof of a full hidden replay or organizer submission. Generate the three CSVs from the exact organizer input, run the independent validator, preserve the run report and hashes, and verify the organizer API response before claiming submission completion.

## Suggested 20-second judge explanation

> “CyberSentinel is a causal, offline multi-agent replay system. We disclose that the CICIDS2017 feature-only data does not contain observed Layer-3 endpoints, so the hardened build fails closed rather than inventing source IPs. A fingerprint-derived pseudo-IP is only a compatibility option; it is synthetic and can collide. Our train/eval split also has 8.58% repeated feature-vector overlap. Agent 1 confidence is calibrated only when we run held-out temperature calibration; Agent 2 scores are raw anomaly scores, not probabilities. Our 150-record correlation cap and 150-position policy expiry are fixed parameters. Results are CICIDS2017-only and do not establish live-network or cross-dataset generalization.”