# Judge-facing limitations and honest demo disclosures

Use this disclosure before presenting any containment or correlation result.

## 1. SOURCE_IP is synthetic when native Layer-3 metadata is absent

The prepared CICIDS2017 feature matrix does not contain native source/destination Layer-3 addresses. The implementation prefers a valid observed source IP when one is present. When it is absent, it derives an IP-shaped `SOURCE_IP` identity from the TCP-stack fingerprint fields `Init_Win_bytes_forward`, `min_seg_size_forward`, and `Fwd Header Length` using a deterministic SHA-256 mapping into `10.x.y.z`.

**This is a synthetic identity, not an observed source address.** Identical TCP-stack fingerprints deliberately map to the same identity. The truncated 24-bit suffix can also collide across different fingerprints. NAT, proxies, virtualisation and common OS/network-stack defaults further weaken uniqueness. A policy collision can therefore block benign traffic from another client. Do not describe these values as packet-captured IPs or claim that the pseudo-identity is unique.

The replay metrics expose the number of rows using synthetic source identities. The validators recompute the same deterministic mapping when checking SOURCE_IP policy scopes. Destination IP is never synthesized; destination-based correlation requires an observed destination address.

## 2. Evaluation overlap

The dataset audit found 8,161 distinct feature vectors shared by training and evaluation, covering 9,795 evaluation rows (8.58% of the evaluation split). This overlap can make repeated-flow results optimistic. The official evaluation split is not modified to remove the overlap. Disclose the caveat alongside any metric.

## 3. Scores are not automatically probabilities

- **Agent 1:** the maximum `predict_proba` output is uncalibrated unless the optional scalar temperature-calibration workflow was run on a separate, labelled, held-out validation file. Do not call it a calibrated probability otherwise.
- **Agent 2:** the exported value is a bounded 0–1 anomaly index (higher means more anomalous), not a probability of attack. The operating threshold is applied to the underlying Isolation Forest decision function; it can optionally be selected on separate labelled validation data under a configured benign false-positive ceiling.

Report the exact model artifact and calibration provenance used for the run.

## 4. Fixed temporal and policy parameters

- Agent 4 has a 150-record sliding-window cap. When usable timestamps exist, it also applies the configured 300-second age window. These are fixed configuration parameters, not learned or adaptive window sizes.
- Agent 5's default policy duration is 150 replay positions, capped to the number of later records remaining in the current replay. This is a fixed rule, not an adaptive learned expiry model.

The replay is chronological and causal: a policy is created after its trigger and may affect only later records. A1/A2 classification and A3 fusion evidence are retained for every input row to satisfy the per-record classification output; an already-active policy controls the replay action before Agent 4 correlation and Agent 5 policy updates.

## 5. Dataset and operating scope

- Model and benchmark validation are based on CICIDS2017 only.
- The system is an offline flow-replay and simulated-defense platform. It does not inspect live sockets, capture packets, or alter operating-system firewalls.
- Generalization to other datasets, network environments, and live deployments is untested.

## 6. Reproducibility and submission status

The repository contains code and CI tests, but the organizer's hidden unlabeled replay input and final API contract are not part of the repository. A successful unit-test run is not proof of a full hidden replay or organizer submission. Generate the three CSVs from the exact organizer input, run the independent validator, preserve the run report and hashes, and verify the organizer API response before claiming submission completion.

## Suggested 20-second judge explanation

> “CyberSentinel is a causal, offline multi-agent replay system. CICIDS2017 does not include native Layer-3 endpoints in the prepared feature matrix, so when source IP is absent we derive a synthetic `SOURCE_IP` from three TCP-stack fingerprint fields. It is not an observed address: identical fingerprints map together and the 24-bit hash can collide, which can cause false blocks. Our train/eval split also has 8.58% repeated feature-vector overlap. Agent 1 confidence is calibrated only when we run held-out temperature calibration; Agent 2 exports a bounded anomaly index, not a probability. Our 150-record correlation cap and 150-position policy expiry are fixed parameters. Results are CICIDS2017-only and do not establish live-network or cross-dataset generalization.”