# CyberSentinel — SOURCE_IP Scope & Derived Identity Disclosure (Corrected)

**Status:** Corrected against the current replay and correlation source. Final cluster counts and false-block attribution must be regenerated after this identity change.

## 1. Dataset limitation

The prepared evaluation parquet is documented as containing 71 numeric flow features and one label column. The current source code does not rely on native `source_ip` or `destination_ip` fields being present.

The Day 2 scored interface requires `scope_type=SOURCE_IP`. Where the input dataset contains no native source IP, CyberSentinel must disclose that its policy scope value is a derived identifier, not an observed Layer 3 address.

## 2. Current source identity derivation

The current implementation is in:

- `src/cybersentinel/agents/correlation.py` — `TemporalCorrelationAgent.derive_source_identity()`
- `src/cybersentinel/replay/engine.py` — calls the same helper for flows without a native source IP.

Derivation order:

1. If a non-empty native source IP field exists, use it.
2. Otherwise require the TCP-stack feature tuple:
   - `Init_Win_bytes_forward`
   - `min_seg_size_forward`
   - `Fwd Header Length`
3. Hash the normalized tuple with SHA-256 and render the first three digest bytes as a private-address-shaped value in `10.x.y.z`.
4. If the required fingerprint fields are absent, return no source identity. A5 must not create a broad policy for an empty identity.

This value is a **synthetic TCP-stack-derived identity**, not a native or observed IP address. It is stable for identical fingerprint tuples, including across records and replay runs.

## 3. Important corrections to earlier reports

Earlier versions of this dossier described a different arithmetic formula and asserted exact counts of 2,484 clusters, 254 collision clusters and 5,812 false blocks attributed to collisions. Those figures are not supported by the current derivation and must not be repeated as current measurements without rerunning the exact current implementation against the actual evaluation dataset.

The earlier implementation also had a weak fallback that hashed destination port, flow duration and forward-packet count into a small address range. That could make a per-flow pattern look like a stable host identity. The current implementation removes that fallback and fails closed when a complete TCP fingerprint is unavailable.

The previous replay implementation assigned synthetic addresses by encounter-order mapping, while the standalone correlation helper used a different fallback. The current replay and correlation paths now call the same identity derivation helper.

## 4. Collision and operational risks

- Two devices with identical TCP-stack fingerprint values map to the same derived identity.
- Different identities can theoretically collide in the finite 24-bit rendered address space.
- NAT, proxies, virtualisation and shared OS/network-stack defaults can reduce identity uniqueness.
- A policy on a derived identity can therefore block benign records from another client sharing that fingerprint.
- No destination IP is inferred when the dataset lacks one. DDoS destination-convergence correlation is not asserted without an observed destination identity.

These limitations must be included in the judge explanation.

## 5. Scored interface and organiser clarification

The policy CSV continues to use the required schema values:

- `scope_type=SOURCE_IP`
- `policy_action=BLOCK`

The `scope_value` is a synthetic fingerprint-derived identity when no native source IP exists. Do not describe it as a real source IP.

If the organiser interprets `SOURCE_IP` as requiring a literal observed source address, the prepared dataset alone cannot satisfy that semantic requirement. Seek an organiser clarification rather than inventing or misrepresenting an address.

## 6. Required rerun before final submission

Because identity derivation changed, regenerate the three CSVs with the current code and rerun:

- unique derived identity count,
- fingerprint collision profile,
- policies created,
- attack containment,
- benign preservation,
- false blocks,
- policy match and expiry invariants,
- full official CSV validation.

Do not reuse old CSV hashes or the earlier collision attribution as evidence for the current implementation.
