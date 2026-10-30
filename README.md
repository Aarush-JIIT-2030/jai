# CyberSentinel

**JAI 2026 · Track 1 — Agentic AI for Cybersecurity**

CyberSentinel is an offline network-flow intrusion-detection prototype. It analyses organiser-provided CICIDS2017-derived flow records using independent detection agents, fuses their evidence, and produces an explainable simulated policy decision.

> **Scope and safety:** This repository is for offline dataset analysis and traffic replay only. It does not sniff live traffic, attack networks, or install/change firewall rules. ALLOW/BLOCK/REVIEW are simulated recommendations, not real enforcement.

## Day 1 benchmark

The organiser's benchmark classes are:

- `BENIGN`
- `BRUTE_FORCE`
- `DOS`
- `DDOS`
- `PORT_SCAN`

Use the exact label mapping and train/validation files supplied by the organisers. Do not infer or invent mappings. Keep the official validation set unchanged.

## Architecture

1. **Threat Detection Agent** — supervised five-class classifier; returns predicted class and confidence.
2. **Anomaly Agent** — independent anomaly score and feature-level evidence. It must not use Agent 1's prediction as an input.
3. **Evidence Fusion Agent** — combines both outputs, records agreement/disagreement, gives a final class/evidence status, rationale, and simulated action.

The agents communicate through the contracts in `src/cybersentinel/contracts.py`. The end-to-end entry point will be `src/cybersentinel/pipeline.py`.

## Quick start

Python 3.10+ is recommended.

```bash
python -m venv .venv
# Windows: .venv\\Scripts\\activate
source .venv/bin/activate
pip install -r requirements.txt
```

Put organiser-provided files under `data/raw/` (this directory is git-ignored). Never commit the dataset unless the organisers explicitly permit redistribution.

Once implementation is in place:

```bash
python -m cybersentinel.cli --help
pytest
```

The CLI and tests are scaffolded; model training and official validation results must be implemented/run against the actual organiser data before reporting metrics.

## Team ownership

| Workstream | Suggested owner | Main paths |
|---|---|---|
| Data inspection and preprocessing | Teammate 1 | `src/cybersentinel/data/` |
| Supervised threat classifier | Teammate 2 | `src/cybersentinel/agents/threat_detection.py` |
| Independent anomaly detector | Teammate 3 | `src/cybersentinel/agents/anomaly_detection.py` |
| Fusion, orchestration, evaluation and submission | Team lead / integrator | `src/cybersentinel/agents/fusion.py`, `pipeline.py`, `evaluation/` |

See [CONTRIBUTING.md](CONTRIBUTING.md) for branch, interface, and PR rules.

## Metrics and reporting

Report measured accuracy, macro-F1, per-class precision/recall/F1, confusion matrix, data-cleaning decisions, split strategy, and any limitations. Macro-F1 matters because it gives each class equal weight. Never publish invented or unverified scores. Fit preprocessing only on training data; do not leak official validation information into training.

## Dataset and disclosure

The expected source is the organiser-provided CICIDS2017-derived dataset. The upstream CICIDS2017 dataset is described by the Canadian Institute for Cybersecurity: https://www.unb.ca/cic/datasets/ids-2017.html

Declare third-party libraries, datasets, AI assistance, and any reused generic boilerplate in the final documentation as required by the hackathon rulebook. No hosted AI API is required for this baseline.

## Current status

This is the team's initial engineering scaffold. No model performance is claimed until the organiser files are received, preprocessing/model code is implemented, and the official validation set is actually evaluated.
