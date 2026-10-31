# CyberSentinel — SOURCE_IP Scope & Derived Identity Disclosure

**Current release status:** The hardened branch accepts only literal, observed IPv4/IPv6 source addresses for Agent 4 endpoint correlation and Agent 5 SOURCE_IP policies. It does not synthesize a source IP from TCP-stack fingerprints.

## 1. CICIDS2017 endpoint limitation

The prepared CICIDS2017 feature matrix is documented as 71 numeric flow features plus a label. It does not provide native Layer-3 source/destination IP columns. Therefore the feature-only training/evaluation files cannot establish real source or destination endpoints.

When no valid native source IP is present:
- Agent 4 returns `not_ready` for endpoint correlation and does not create endpoint groups.
- Agent 5 refuses to create a SOURCE_IP policy.
- Replay still classifies every row and records its simulated ALLOW/BLOCK decision, but it cannot claim endpoint-based containment for rows without observed source IP metadata.

This is a deliberate fail-closed behavior in the current hardened branch.

## 2. Synthetic identity caveat (legacy / compatibility builds)

A prior/alternate identity approach derives a private-address-shaped pseudo-IP from TCP-stack fingerprint fields such as `Init_Win_bytes_forward`, `min_seg_size_forward`, and `Fwd Header Length`. **That value is synthetic, not a native or observed IP address.** Identical TCP-stack fingerprints produce the same identity, so distinct clients can collide; NAT, proxies, virtualisation and common OS/network-stack defaults further weaken uniqueness. A collision can cause a policy to affect benign traffic from another client.

If a competition-compatible build enables this fallback, disclose all of the following before the demo:
1. `SOURCE_IP` is a synthetic fingerprint-derived identity when native IP metadata is absent.
2. It is not a packet-captured or observed IP address.
3. Identical fingerprints can collide and cause false correlation or false blocking.
4. The collision profile and false-block rate must be measured on the exact replay input; historical counts from earlier derivations are not current evidence.

Do not silently switch between observed and synthetic identity modes. Label the mode in run metadata and judge-facing output.

## 3. Scored interface implications

The policy contract may require `scope_type=SOURCE_IP` and `policy_action=BLOCK`. A feature-only dataset with no native source IP cannot satisfy the semantic meaning of an observed SOURCE_IP scope using this current branch. Ask the organizer whether a fingerprint-derived pseudo-IP is acceptable before changing the hardened fail-closed behavior.

The independent submission validator checks that SOURCE_IP scope values match literal IP fields in the original replay input. A synthetic identity will not pass that observed-endpoint validation unless the organizer explicitly changes the contract and the validator is updated to validate the deterministic fingerprint mapping instead.

## 4. Required checks for any identity-mode change

Before submission, regenerate all three CSVs and rerun:
- identity-mode declaration and unique identity count,
- identical-fingerprint collision profile,
- policy creation and expiry invariants,
- attack containment and benign preservation,
- false blocks attributable to identity collisions,
- exact official CSV/API validation.

Never reuse historical collision counts, policy counts, CSV hashes, or false-block attribution after changing identity derivation.