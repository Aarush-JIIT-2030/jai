# CyberSentinel — SOURCE_IP Scope & Synthetic Identity Disclosure

**Current release status:** The replay engine prefers a valid native source IP. When none is present, it derives a deterministic synthetic source identity from TCP-stack fingerprint fields and uses that identity for Agent 4 source grouping and Agent 5 simulated SOURCE_IP policies.

## 1. Why a synthetic identity is used

The prepared CICIDS2017 feature matrix contains numeric flow features and a label, but no native Layer-3 source/destination IP columns. The Day 2 policy interface expects a `SOURCE_IP` scope. To preserve source-level grouping and forward policy behavior on feature-only rows, the implementation derives a deterministic pseudo-IPv4 identity when a valid source IP is absent.

## 2. Derivation

Derivation order:
1. If a valid native source IP field is present, normalize and use that observed address.
2. Otherwise require all three TCP-stack fingerprint fields: `Init_Win_bytes_forward`, `min_seg_size_forward`, and `Fwd Header Length`.
3. Convert finite numeric values to stable normalized strings, join them in a fixed field order, and hash the tuple with SHA-256.
4. Render the first three digest bytes as a private-address-shaped value in `10.x.y.z`.
5. If any required fingerprint field is missing or non-finite, return no source identity and fail closed for source correlation/policy creation.

The replay and both validators call the same `TemporalCorrelationAgent.derive_source_identity()` helper so policy creation and validation use the same mapping.

## 3. Critical limitations

- The derived value is **synthetic, not an observed Layer-3 address**. It is not obtained from packet capture, a socket, or an endpoint inventory.
- Identical TCP-stack fingerprints intentionally produce the same identity. Two distinct clients with the same tuple are indistinguishable to this fallback.
- Only 24 hash bits are rendered into the pseudo-IPv4 suffix, so different fingerprints can also collide by chance.
- NAT, proxies, virtualisation and common OS/network-stack defaults reduce fingerprint uniqueness.
- A SOURCE_IP policy collision can block benign traffic from another client sharing the synthetic identity. Report false-block and benign-preservation metrics; do not present containment without this caveat.
- Destination IP is never synthesized. Destination-convergence correlation requires a literal observed destination IP.

## 4. Scored interface and validator behavior

The official policy file uses `scope_type=SOURCE_IP` and `policy_action=BLOCK`. When the source is synthetic, `scope_value` contains the deterministic pseudo-IP described above. The independent validator recomputes the same identity from the original row's TCP-stack fields; it does not claim that the value is observed.

Replay metrics include `synthetic_source_identity_rows` and `source_identity_mode` so the run report identifies synthetic usage. Preserve those metrics with the output bundle.

## 5. Required checks before final submission

Regenerate the three official CSVs from the exact hidden replay input and measure:
- count of rows with observed versus synthetic source identities,
- number of unique synthetic identities and identical-fingerprint groups,
- distinct fingerprint tuples that collide after 24-bit truncation,
- policy creation and expiry invariants,
- attack containment and benign preservation,
- false blocks attributable to identical-fingerprint and hash collisions,
- exact official CSV/API validation.

Never describe a synthetic SOURCE_IP as an observed endpoint. Do not reuse collision counts or false-block attribution from a different fingerprint mapping or replay input.