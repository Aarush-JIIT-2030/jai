# CyberSentinel — Submission Contract (Corrected Against Official Day 2 Brief)

**Status:** Corrected documentation. A fresh local run of the current branch is still required before declaring submission-ready.

## Source of truth

The Day 2 briefing requires three CSVs and explicitly specifies the following record-level contracts. The official brief's per-record clarification takes precedence over the compact/partially obscured table layout.

## 1. classification.csv

Exact required columns, in order:

`record_id,predicted_class,anomaly_score,evidence_status`

Requirements:

- Exactly one prediction for every organiser-provided evaluation record ID.
- Five-class taxonomy only: `BENIGN`, `BRUTE_FORCE`, `DOS`, `DDOS`, `PORT_SCAN`.
- Predictions must be generated from permitted flow features.
- Include predictions for records that are later blocked by an active policy.
- Do not submit actual/ground-truth labels.
- Anomaly score and evidence status must reflect the implemented Agent 2 / Agent 3 outputs.

## 2. policies.csv

Exact required columns, in order:

`policy_id,activated_after_record_id,scope_type,scope_value,expires_after_record_id`

Requirements:

- Use organiser-provided record IDs.
- `scope_type` must be one of `SOURCE_IP`, `DESTINATION_IP`, or `SRC_DST_PAIR`, and `scope_value` must contain the matching literal observed endpoint(s). A policy row represents a simulated BLOCK rule; the action is recorded in `replay.csv`.
- A policy is activated only after its triggering record.
- Expiry must follow the implementation's documented record-boundary convention.
- Only literal observed endpoint metadata is eligible for a policy scope. Missing or invalid endpoint values fail closed; feature-derived fingerprints are never treated as IP addresses.

## 3. replay.csv

The briefing's explicit per-record clarification requires:

`record_id,action,active_policy_id`

Requirements:

- Every evaluation record exactly once.
- `action` must be `ALLOW` or `BLOCK`.
- `BLOCK` must reference a valid policy that was activated earlier and is still active for that record.
- `ALLOW` must have an empty `active_policy_id`.
- A policy cannot block the record that triggered its creation.

## 4. Required validation

The independent validator must check:

- Exact header names and order.
- Exact organiser record-ID coverage and uniqueness.
- Five-class taxonomy.
- Numeric anomaly-score validity and evidence-status validity.
- Unique policy IDs and valid policy scope/action.
- Activation and expiry order.
- Referential integrity from replay to policy.
- Active-policy matching at each BLOCK record.
- No self-blocking.
- No policy lookahead or hidden-label use.
- No duplicate or missing replay/classification records.

A local validator result is not proof that the organiser API accepted the files. Do not claim upload success until the organiser endpoint returns an actual successful response.

## 5. Historical report correction

An earlier version of this dossier described a different schema (`flow_id`, `predicted_label`, `confidence`, `is_anomaly`; and alternate policy/replay columns). Those columns do **not** match the Day 2 briefing and must not be used for the official submission.

The current generator in `src/cybersentinel/replay/engine.py` writes the four-column classification schema, five-column policies schema, and three-column replay schema above. Re-run `python scripts/generate_submissions.py` and the current validator after any replay/model changes.
