# CyberSentinel — Corrected Live Demonstration Runbook

**Status:** Presenter runbook aligned to the current application and official Day 2 requirements. Rehearse from a clean local startup before presenting.

## Before the panel

1. Confirm the organiser-provided evaluation dataset is installed at `data/processed/eval_prepared.parquet`.
2. Confirm both model artifacts exist and pass model loading.
3. Start the FastAPI backend and Vite frontend using the repository's documented commands.
4. Open Settings & Health and verify the API and model readiness.
5. Run the official replay once if the panel expects pre-generated CSVs. The Replay Studio now calls the backend; it does not animate fake progress.
6. Open Submission Studio and run the actual validator.
7. Keep the terminal visible for any command the panel asks to inspect.

## Five-minute demonstration

### 00:00–00:40 — Product overview

Open Overview. Explain that CyberSentinel is an offline network-flow replay and simulated-defense product. Rotate and inspect the Three.js topology. Explain that it is an interactive architecture schematic; do not describe it as live network telemetry.

### 00:40–01:20 — Five-agent architecture

Open Five-Agent Architecture and explain the official division:

- A1 supervised five-class threat detection.
- A2 independent anomaly detection.
- A3 evidence fusion.
- A4 temporal correlation.
- A5 temporary simulated defense policies.

Explain the input/output contract of each agent. Do not describe A1 confidence as calibrated; the current RandomForest implementation exposes maximum `predict_proba` output, which is not calibrated.

### 01:20–02:00 — A1/A2 evidence and A3 fusion

Open Flow Inspector and inspect a record or a clearly labelled test fixture. Then open Evidence Fusion. Change the A1 class/confidence and A2 score/flag and select **Run production fusion**. Explain that the result is returned by the Python `EvidenceFusionAgent`, not calculated by a duplicate frontend rule set.

### 02:00–02:45 — A4 temporal correlation

Open Replay Studio and run the actual official replay if the dataset and model artifacts are present. Then open Temporal Investigations and refresh. Show only groups returned by the latest replay. If no groups are available, explain that the console is empty because no replay group has been produced; do not use fabricated sample incidents.

### 02:45–03:35 — A5 adaptive defense and causality

Open Adaptive Defense. Inspect actual policy rows. Use the pre-filter tester with a scope value copied from an actual generated policy and test record positions before activation, during the active interval, and after expiry.

Explain:
- The policy is created after the triggering record.
- The triggering record remains ALLOW.
- Only later matching records can be BLOCKED while the policy is active.
- All policy actions are simulated; no operating-system firewall is changed.

### 03:35–04:30 — Replay metrics and trade-offs

Return to Replay Studio and show the returned replay metrics. Explain attack containment, block precision, benign preservation and false blocks using their correct denominators. If the evaluation dataset is unlabelled, label-based rates are unavailable; do not invent them.

### 04:30–05:00 — Submission files

Open Submission Studio. Run the current validator and download:
- `classification.csv`
- `policy.csv`
- `replay.csv`

Explain that local validation is not the same as a successful upload to the organiser API. Only claim upload success after receiving an actual organiser API response.

## Technical points judges may ask

**Why does classification include blocked records?** The official brief requires one five-class prediction per evaluation record, including flows later blocked during replay.

**Can the triggering record block itself?** No. A5 activates a policy after the triggering record; only later matching records can be blocked.

**Does the system use hidden labels?** No labels are used in prediction, fusion, correlation or policy creation. Labels, when present in a permitted labelled evaluation dataset, are used only for offline metric calculation.

**Are the IP values real?** The prepared evaluation parquet has no native Layer 3 source/destination IP fields. Any endpoint identity derived from flow features is synthetic/derived and collision-prone; disclose that limitation clearly.

**Does CyberSentinel modify the real firewall?** No. It is an offline replay with in-memory simulated policies.

## Recovery

- If models are unavailable, do not claim the agents are ready. Show the health diagnostics and explain the missing artifact.
- If the evaluation dataset is unavailable, do not claim a full replay was run. Use a clearly labelled small test fixture only to explain the code path.
- If the API is disconnected, restart the backend and refresh the UI.
- If WebGL is unsupported, use the 2D fallback.
- If the organiser API is not announced, show locally generated and validated CSVs only; do not claim submission.
