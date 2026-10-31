#!/usr/bin/env python3
"""Run a reproducible synthetic judge demo through CyberSentinel's real five agents.

Agent 1 is loaded from the supplied trained artifact and is never modified.
Agent 2 is fitted to a clearly separate synthetic BENIGN baseline for this demo.
Agents 3-5 are the repository's real fusion, temporal-correlation, and
adaptive-defense implementations. All ALLOW/BLOCK decisions are offline only.
"""
from __future__ import annotations

import argparse
import json
import logging
from pathlib import Path
import sys

import numpy as np
import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from cybersentinel.agents.adaptive_defense import AdaptiveDefenseAgent
from cybersentinel.agents.anomaly_detection import AnomalyDetectionAgent
from cybersentinel.agents.correlation import TemporalCorrelationAgent
from cybersentinel.agents.fusion import EvidenceFusionAgent
from cybersentinel.agents.threat_detection import ThreatDetectionAgent
from cybersentinel.contracts import AnomalyDetectionResult, ThreatDetectionResult

LOG = logging.getLogger("judge_demo")
ATTACK_CLASSES = ("BRUTE_FORCE", "DOS", "DDOS", "PORT_SCAN")


def _base_value(column: str) -> float:
    key = column.casefold()
    if "port" in key:
        return 443.0
    if "duration" in key:
        return 120_000.0
    if "packets/s" in key:
        return 45.0
    if "bytes/s" in key:
        return 18_000.0
    if "packet" in key:
        return 8.0
    if "length" in key or "bytes" in key:
        return 500.0
    if "window" in key:
        return 64_240.0
    if "flag" in key:
        return 0.0
    if "iat" in key:
        return 10_000.0
    return 1.0


def make_benign_baseline(columns: list[str], rows: int = 1200, seed: int = 2026) -> pd.DataFrame:
    """Build deterministic, non-constant benign-like feature rows for demo A2."""
    rng = np.random.default_rng(seed)
    values: dict[str, np.ndarray] = {}
    for column in columns:
        center = _base_value(column)
        if "flag" in column.casefold():
            values[column] = rng.binomial(1, 0.015, rows).astype(float)
        else:
            values[column] = (center * rng.lognormal(mean=0.0, sigma=0.12, size=rows)).astype(float)
    return pd.DataFrame(values)


def mutate_candidate(base: dict[str, float], attack: str, rng: np.random.Generator) -> dict[str, float]:
    """Create candidate feature perturbations; Agent 1 decides the actual class."""
    row = dict(base)
    scale = float(rng.uniform(2.5, 18.0))
    for key in row:
        name = key.casefold()
        if attack in {"DOS", "DDOS"}:
            if "flow packets/s" in name:
                row[key] *= scale * 100
            elif "flow bytes/s" in name:
                row[key] *= scale * 120
            elif "total fwd packets" in name or "total backward packets" in name:
                row[key] *= scale * 30
            elif "syn flag count" in name:
                row[key] = max(row[key], scale * 4)
            elif "flow duration" in name:
                row[key] = max(1.0, row[key] / scale)
        elif attack == "PORT_SCAN":
            if "syn flag count" in name:
                row[key] = max(row[key], 2.0)
            elif "flow duration" in name:
                row[key] = max(1.0, row[key] / scale)
            elif "total fwd packets" in name:
                row[key] = max(1.0, row[key] / 2.0)
        elif attack == "BRUTE_FORCE":
            if "total fwd packets" in name or "total backward packets" in name:
                row[key] *= scale * 5
            elif "rst flag count" in name:
                row[key] = max(row[key], scale)
            elif "flow packets/s" in name:
                row[key] *= scale * 5
    # Avoid NaN/Inf and keep CICFlowMeter-like counts nonnegative.
    return {key: float(np.nan_to_num(value, nan=0.0, posinf=1e12, neginf=0.0))
            for key, value in row.items()}


def find_model_examples(
    threat_agent: ThreatDetectionAgent,
    columns: list[str],
    seed: int,
    attempts_per_class: int,
) -> tuple[dict[str, dict[str, float]], dict[str, float], dict[str, int]]:
    """Search synthetic candidates and retain only Agent-1's own predictions."""
    rng = np.random.default_rng(seed)
    examples: dict[str, dict[str, float]] = {}
    confidences: dict[str, float] = {}
    attempts: dict[str, int] = {}
    base = make_benign_baseline(columns, rows=1, seed=seed).iloc[0].to_dict()

    # BENIGN example is also accepted only when the loaded classifier says BENIGN.
    for attack in ("BENIGN",) + ATTACK_CLASSES:
        attempts[attack] = 0
        for index in range(attempts_per_class):
            attempts[attack] += 1
            if attack == "BENIGN":
                candidate = make_benign_baseline(columns, rows=1, seed=seed + index + 1).iloc[0].to_dict()
            else:
                candidate = mutate_candidate(base, attack, rng)
            prediction = threat_agent.predict(candidate)
            if prediction.status != "success" or prediction.predicted_class != attack:
                continue
            if prediction.confidence is None or prediction.confidence < 0.70:
                continue
            examples[attack] = candidate
            confidences[attack] = float(prediction.confidence)
            break
    return examples, confidences, attempts


def build_campaign_records(examples: dict[str, dict[str, float]], seed: int) -> pd.DataFrame:
    """Expand model-approved examples into chronological, endpoint-grounded campaigns."""
    rows: list[dict] = []
    seq = 0

    def append(flow: dict[str, float], label_for_scenario: str, src: str, dst: str, port: int):
        nonlocal seq
        seq += 1
        record = dict(flow)
        record.update({
            "record_id": f"JDG{seq:05d}", "seq": seq,
            "source_ip": src, "destination_ip": dst,
            "source_port": 40_000 + (seq % 20_000),
            "Destination Port": port, "protocol": 6,
            "Timestamp": pd.Timestamp("2026-10-31T10:00:00Z") + pd.Timedelta(seconds=seq * 2),
            "scenario_hint": label_for_scenario,
        })
        rows.append(record)

    benign = examples.get("BENIGN")
    if benign is not None:
        for i in range(12):
            append(benign, "BENIGN_CONTROL", f"192.0.2.{10 + i}", "198.51.100.10", 443)

    for attack in ATTACK_CLASSES:
        flow = examples.get(attack)
        if flow is None:
            continue
        if attack == "DDOS":
            # Eight distinct observed sources converge on one destination.
            for i in range(8):
                append(flow, attack, f"203.0.113.{10 + i}", "198.51.100.80", 80)
        elif attack == "PORT_SCAN":
            src = "192.0.2.90"
            for port in (21, 22, 23, 80, 443, 3389, 8080):
                append(flow, attack, src, "198.51.100.90", port)
        elif attack == "BRUTE_FORCE":
            src = "192.0.2.91"
            for _ in range(7):
                append(flow, attack, src, "198.51.100.91", 22)
        else:  # DOS
            src = "192.0.2.92"
            for _ in range(14):
                append(flow, attack, src, "198.51.100.92", 80)

    if not rows:
        raise RuntimeError("Agent 1 produced no usable synthetic examples.")
    return pd.DataFrame(rows)


def run_five_agents(frame: pd.DataFrame, threat: ThreatDetectionAgent, anomaly: AnomalyDetectionAgent) -> tuple[pd.DataFrame, pd.DataFrame]:
    fusion_agent = EvidenceFusionAgent()
    correlation_agent = TemporalCorrelationAgent(window_size=150, window_seconds=300)
    defense_agent = AdaptiveDefenseAgent(default_duration=8)
    trace: list[dict] = []

    for step, flow in enumerate(frame.to_dict(orient="records")):
        record_id = str(flow["record_id"])
        source_ip = str(flow["source_ip"])

        # Agent 5 checks only policies created by earlier records.
        pre_filter = defense_agent.evaluate_pre_filter(record_id, source_ip, step)

        # Agents 1 and 2 always score the supplied flow; no scenario_hint/label is passed.
        threat_result = threat.predict(flow)
        anomaly_result = anomaly.score(flow)

        # Agent 3 arbitrates the two independently produced results.
        fusion = fusion_agent.fuse(threat_result, anomaly_result)

        # Agent 4 observes the chronological endpoint stream, including records
        # that the simulated policy gate has already marked for blocking.
        correlation = correlation_agent.correlate(
            record_id, flow,
            threat_class=threat_result.predicted_class,
            confidence=threat_result.confidence,
        )

        policy_created = None
        if pre_filter is None:
            attack_detected = fusion.action == "BLOCK" or correlation.correlated
            defense = defense_agent.handle_post_analysis(
                record_id=record_id, source_ip=source_ip, current_step=step,
                attack_detected=attack_detected,
                attack_type=correlation.attack_type or threat_result.predicted_class,
                confidence=threat_result.confidence,
                duration=min(defense_agent.default_duration, max(1, len(frame) - step - 1)),
            )
            policy_created = defense.new_policy_created
            replay_action = "ALLOW"  # trigger record is analyzed before future policy activation
            applied_policy = "NONE"
        else:
            replay_action = "BLOCK"
            applied_policy = pre_filter.applied_policy_id or ""

        trace.append({
            "record_id": record_id,
            "agent1_class": threat_result.predicted_class or "",
            "agent1_confidence": round(float(threat_result.confidence or 0.0), 4),
            "agent2_anomaly_score": round(float(anomaly_result.anomaly_score or 0.0), 5),
            "agent2_is_anomaly": bool(anomaly_result.is_anomaly),
            "agent3_evidence_status": fusion.evidence_status,
            "agent3_recommendation": fusion.action,
            "agent4_correlated": bool(correlation.correlated),
            "agent4_attack_type": correlation.attack_type or "",
            "agent4_group_id": correlation.group_id or "",
            "agent5_policy_created": policy_created.policy_id if policy_created else "",
            "replay_action": replay_action,
            "applied_policy_id": applied_policy,
            "source_ip": source_ip,
            "destination_ip": str(flow["destination_ip"]),
            "destination_port": int(flow["Destination Port"]),
        })

    return pd.DataFrame(trace), pd.DataFrame([
        {
            "policy_id": p.policy_id,
            "activated_after_record_id": p.activated_after_record_id,
            "scope_type": p.scope_type,
            "scope_value": p.scope_value,
            "expires_after_step": p.expires_after_record_id,
            "policy_action": p.policy_action,
            "reason": p.reason,
        }
        for p in defense_agent.all_policies
    ])


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--threat-model", type=Path, default=Path("models/threat_detection/model.joblib"))
    parser.add_argument("--output-dir", type=Path, default=Path("outputs/judge_demo"))
    parser.add_argument("--seed", type=int, default=2026)
    parser.add_argument("--attempts-per-class", type=int, default=5000)
    args = parser.parse_args()

    if not args.threat_model.is_file():
        LOG.error("Agent 1 artifact not found: %s", args.threat_model)
        LOG.error("Copy your already-trained Agent 1 artifact to this path or pass --threat-model.")
        return 2

    threat = ThreatDetectionAgent.load(args.threat_model)
    columns = list(threat.model.feature_columns)
    if not columns:
        LOG.error("Agent 1 artifact has no feature schema.")
        return 2

    examples, confidence, attempts = find_model_examples(threat, columns, args.seed, args.attempts_per_class)
    if "BENIGN" not in examples:
        LOG.error("Could not find a high-confidence BENIGN synthetic example. Increase --attempts-per-class.")
        return 2
    attack_examples = sorted(set(examples) - {"BENIGN"})
    if not attack_examples:
        LOG.error("Agent 1 did not classify any generated candidate as an attack. No labels will be fabricated.")
        return 2

    # A2 is fitted only on the generated benign baseline; this demo artifact is
    # isolated from and does not overwrite the normal production Agent 2 artifact.
    benign_baseline = make_benign_baseline(columns, rows=1600, seed=args.seed)
    anomaly = AnomalyDetectionAgent().fit(benign_baseline)
    frame = build_campaign_records(examples, args.seed)
    trace, policies = run_five_agents(frame, threat, anomaly)

    args.output_dir.mkdir(parents=True, exist_ok=True)
    frame.drop(columns=["scenario_hint"]).to_csv(args.output_dir / "synthetic_flows.csv", index=False)
    trace.to_csv(args.output_dir / "five_agent_trace.csv", index=False)
    policies.to_csv(args.output_dir / "synthetic_policies.csv", index=False)
    anomaly.save(args.output_dir / "agent2_synthetic_demo.joblib")

    report = {
        "mode": "SYNTHETIC_JUDGE_DEMO",
        "seed": args.seed,
        "agent1_artifact": str(args.threat_model),
        "agent1_artifact_modified": False,
        "agent1_selected_classes": sorted(examples),
        "agent1_confidence": confidence,
        "candidate_attempts": attempts,
        "records": int(len(frame)),
        "agent1_predictions": trace["agent1_class"].value_counts().to_dict(),
        "agent2_anomaly_flags": int(trace["agent2_is_anomaly"].sum()),
        "agent3_recommendations": trace["agent3_recommendation"].value_counts().to_dict(),
        "agent4_correlated_records": int(trace["agent4_correlated"].sum()),
        "agent5_policies_created": int(len(policies)),
        "replay_blocks": int((trace["replay_action"] == "BLOCK").sum()),
        "note": "Synthetic records and a synthetic-only Agent 2 artifact. Agent 1 is the supplied trained model. Agent 3-5 are the repository's real deterministic agents. All actions are offline simulation; no live traffic/firewall controls.",
    }
    (args.output_dir / "judge_demo_report.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps(report, indent=2))
    if trace["agent4_correlated"].sum() == 0:
        LOG.warning("Agent 4 ran but no campaign crossed its configured correlation threshold.")
    if len(policies) == 0:
        LOG.warning("Agent 5 ran but no policy was created; inspect Agent 1/2 outputs before the presentation.")
    return 0


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    raise SystemExit(main())
