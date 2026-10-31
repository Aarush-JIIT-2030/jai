# Synthetic five-agent judge demo

This runner creates a deterministic synthetic flow stream and exercises the real
CyberSentinel agents without modifying the supplied Agent 1 model.

## What runs

1. **Agent 1 — threat classifier:** loads `models/threat_detection/model.joblib`
   (or the path passed with `--threat-model`). Its own predictions determine
   which synthetic candidates are retained. No labels are passed to inference.
2. **Agent 2 — anomaly detector:** fits a temporary Isolation Forest on a
   generated synthetic BENIGN baseline. The artifact is written only under the
   demo output directory; the normal Agent 2 model is not overwritten.
3. **Agent 3 — evidence fusion:** uses the repository's `EvidenceFusionAgent`.
4. **Agent 4 — temporal correlation:** uses real observed synthetic source and
   destination IP addresses, timestamps, ports, and chronological flow order.
5. **Agent 5 — adaptive defense:** uses the real forward-only policy lifecycle.
   A trigger record is analyzed first; only later records can be blocked.

Agents 3–5 are deterministic response/correlation components, not separately
trained ML models. This follows the project's architecture: two learned
detectors plus three deterministic agents.

## Run

Install the project dependencies, ensure the trained Agent 1 artifact exists,
then from the repository root:

```bash
python -m pip install -e ".[dev,ml]"
python scripts/run_judge_demo.py
```

If Agent 1 is stored elsewhere:

```bash
python scripts/run_judge_demo.py --threat-model path/to/model.joblib
```

To increase candidate search effort:

```bash
python scripts/run_judge_demo.py --attempts-per-class 12000
```

## Output

The default output directory is `outputs/judge_demo/`:

- `synthetic_flows.csv` — generated input stream, no scenario label column.
- `five_agent_trace.csv` — per-record output from Agents 1–5 and replay action.
- `synthetic_policies.csv` — policies created during the replay.
- `agent2_synthetic_demo.joblib` — temporary demo-only Agent 2 artifact.
- `judge_demo_report.json` — seeds, model predictions, counts, and limitations.

## Important boundaries

- The runner never retrains, edits, or replaces Agent 1.
- The generated traffic is synthetic. It is suitable for a controlled demo,
  not as evidence of real-world detection accuracy or benchmark performance.
- Agent 2 is fitted on a synthetic benign baseline for this demonstration.
  Its demo scores must not be represented as official validation results.
- The runner exits rather than inventing attack predictions if Agent 1 does not
  classify generated candidates into attack classes with at least 0.70 confidence.
- All ALLOW/BLOCK values are offline replay decisions. No packets are captured,
  no live network is monitored, and no operating-system firewall is changed.
