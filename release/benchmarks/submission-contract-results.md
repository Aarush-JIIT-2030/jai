# CyberSentinel — Official Level 2 Submission Contract

**Source of truth:** the organizer-provided CSV templates supplied with the hidden replay set. The files are header-only templates; the replay generator must populate them without changing their exact columns or order.

## 1. classification.csv

Exact columns:

`record_id,predicted_class,anomaly_score,evidence_status`

- Exactly one row for every hidden input record, in the same order.
- predicted_class must be one of BENIGN, BRUTE_FORCE, DOS, DDOS, PORT_SCAN.
- anomaly_score must be finite and within [0,1]; higher means more anomalous. It is a bounded index, not a probability.
- evidence_status must be AGREE, DISAGREE, or INCOMPLETE.
- Do not include hidden ground-truth labels.

## 2. policies.csv

Exact columns:

`policy_id,activated_after_record_id,scope_type,scope_value,expires_after_record_id`

- policy_id is unique.
- scope_type is SOURCE_IP, DESTINATION_IP, or SRC_DST_PAIR.
- scope_value must match literal observed endpoint metadata from the blocked row.
- A policy becomes active on the record after activated_after_record_id and remains active through expires_after_record_id, inclusive.
- A policy row represents a simulated BLOCK rule; there is no policy_action column in the organizer template.

## 3. replay.csv

Exact columns:

`record_id,action,active_policy_id`

- Every input record exactly once, in original seq order.
- action is ALLOW or BLOCK.
- ALLOW must have an empty active_policy_id.
- BLOCK must reference a known policy that is active at that record and whose scope matches the observed endpoint(s).
- A policy cannot block its own triggering record.

## 4. Validation and submission status

The independent validator checks exact headers, exact record coverage/order, five-class predictions, finite [0,1] anomaly scores, evidence states, unique policy IDs, supported observed endpoint scopes, activation-exclusive/expiry-inclusive windows, and replay-to-policy references.

A local validator pass does not prove organizer acceptance. Only an actual successful organizer response or receipt establishes acceptance. The supplied materials do not include API credentials or an upload receipt.
