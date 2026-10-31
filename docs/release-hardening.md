# Release hardening notes

## Causal replay invariants

- The organizer-provided row order is authoritative; record IDs are identifiers, not arithmetic counters.
- A policy is created after its triggering record. It can affect only a later row.
- Policy lifetime is tracked internally by replay position and exported as the organizer record ID at the expiry position.
- Policy lookup occurs before the fusion decision for each row.
- Classification is emitted for every row independently of the replay action.
- Agent 4 uses only literal observed source and destination IP addresses. Invalid destination values are ignored, invalid destination ports are normalized to 0, and TCP fingerprints are never converted into endpoints.
- Agent 5 accepts only literal IPv4/IPv6 source addresses for SOURCE_IP scope.
- Missing/invalid model evidence is not replaced with benign or normal defaults; fusion returns INCOMPLETE/REVIEW.

## Validation

Run:

```bash
python scripts/validate_submissions.py --input PATH_TO_ORGANIZER_INPUT --output-dir submissions/
```

The independent validator verifies record coverage and ordering, exact official headers, five-class predictions, allowed evidence states, finite anomaly scores, unique policy IDs, literal IP scopes, policy activation/expiry ordering, causal BLOCK references, and matching observed source IP.

The API's bundle validator checks exact record ordering, policy lifecycle boundaries, and (when validating against the installed evaluation frame) that every BLOCK policy scope matches the observed source IP for that record. The independent CLI validator performs the same source-IP-to-record check against the original input file.

## Explicit limitations

- If organizer hidden records do not include native source IPs, endpoint correlation and SOURCE_IP policy generation are intentionally unavailable for those records. Do not replace missing IPs with synthetic identities.
- The official hidden input, organizer API endpoint/schema and credentials must be supplied by the organizers before final full replay and submission can be verified.
- Repository CI validates code and frontend build only. It is not a substitute for evaluation on the official hidden records.
