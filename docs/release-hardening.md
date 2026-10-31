# Release hardening notes

## Causal replay invariants

- The organizer-provided row order is authoritative; record IDs are identifiers, not arithmetic counters.
- A policy is created after its triggering record. It can affect only a later row.
- Policy lifetime is tracked internally by replay position and exported as the organizer record ID at the expiry position.
- Policy lookup occurs before the fusion decision for each row.
- Classification is emitted for every row independently of the replay action.
- Agent 4 prefers literal observed source and destination IP addresses. Destination IP is never synthesized. If source IP is absent, the current fallback derives an IP-shaped synthetic source identity from the finite TCP-stack fingerprint tuple (`Init_Win_bytes_forward`, `min_seg_size_forward`, `Fwd Header Length`); identical tuples map together and the truncated 24-bit hash can collide. This identity is not an observed address.
- Agent 5 accepts syntactically valid IPv4/IPv6 source identities for simulated scope. A valid IP string can be synthetic; do not present scope validation as proof of packet-observed provenance.
- Invalid destination values are ignored, invalid destination ports are normalized to 0, and incomplete fingerprints leave the source identity unresolved (no source policy can be created).
- Missing/invalid model evidence is not replaced with benign or normal defaults; fusion returns INCOMPLETE/REVIEW.

## Validation

Run:

```bash
python scripts/validate_submissions.py --input PATH_TO_ORGANIZER_INPUT --output-dir submissions/
```

The independent validator verifies record coverage and ordering, exact official headers, five-class predictions, allowed evidence states, finite anomaly scores, unique policy IDs, IP-formatted scopes, policy activation/expiry ordering, causal BLOCK references, and scope consistency against the original input row. For `SOURCE_IP`, it recomputes the same deterministic fallback identity when native source IP is absent; therefore a syntactically valid scope is not necessarily an observed address.

The API bundle validator and independent CLI validator both compare every BLOCK policy to the identity derived from its original input row. Destination scopes still require literal observed destination IP metadata.

## Explicit limitations

- When native source IP is absent but all three fingerprint fields are finite, the implementation uses a deterministic synthetic identity. It can collide and can create false blocks; it is not a substitute for a captured IP. If the fingerprint is incomplete, source correlation/policy creation is unavailable.
- The official hidden input, organizer API endpoint/schema and credentials must be supplied by the organizers before final full replay and submission can be verified.
- Repository CI validates code and frontend build only. It is not a substitute for evaluation on the official hidden records.
