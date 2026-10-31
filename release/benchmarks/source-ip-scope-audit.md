# CyberSentinel — Source Identity and Endpoint Scope Audit

## Input-source precedence

- When a replay row contains a parseable native `source_ip`, that observed address is used.
- When native source IP is absent or malformed, the current fallback derives a deterministic IP-shaped `SOURCE_IP` identity from the TCP-stack fingerprint fields `Init_Win_bytes_forward`, `min_seg_size_forward`, and `Fwd Header Length`.
- The fallback is a **synthetic identity, not an observed address**. Identical fingerprint tuples deliberately map to the same identity. The SHA-256 digest is truncated to a 24-bit suffix, so different tuples can collide. Common TCP-stack defaults, NAT, proxies, and virtualisation further weaken any host-identity interpretation. A collision can group unrelated clients or cause a benign flow to be blocked by a simulated policy.
- If any required fingerprint field is missing, non-numeric, or non-finite, the fallback is unavailable and no source-scoped policy can be created for that row.
- Destination IP is never synthesized. Destination-based correlation and `SRC_DST_PAIR` scopes require a parseable literal destination IP from the input.

## Challenge input versus feature-only dataset

The supplied 200-row hidden replay input inspected for this challenge contains native `source_ip` and `destination_ip` fields alongside `record_id`, `seq`, protocol, ports, `day`, and `time_offset`. For those rows, the observed source address takes precedence and the synthetic fallback count should be zero if every source field is valid.

The CICIDS2017 training/evaluation feature partitions do not contain native Layer-3 endpoints. If those feature-only rows are replayed directly, the synthetic fingerprint fallback is used wherever the three fingerprint fields are complete. This is a different input mode from the organizer endpoint-enriched hidden replay.

## Policy and validator semantics

- `SOURCE_IP` scope values are IP-formatted identity tokens. They may be observed addresses or the disclosed synthetic fallback.
- `DESTINATION_IP` scope values must be literal observed destination addresses.
- `SRC_DST_PAIR` combines the input-derived source identity with a literal observed destination address.
- Both validators recompute the same source identity from the original row and verify that each BLOCK references a known policy active strictly after activation and through expiry, inclusive. A syntactically valid `10.x.y.z` value does not prove it was observed.
- Replay metrics distinguish missing native source addresses, rows that actually received a synthetic identity, and rows for which no source identity could be derived.

## Remaining evaluation boundary

The hidden replay is unlabelled, so false-block rates and attack containment cannot be measured from the hidden replay itself. All ALLOW/BLOCK outcomes are simulated offline decisions; no live firewall is changed and no packet capture is performed.