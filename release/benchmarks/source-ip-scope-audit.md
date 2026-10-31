# CyberSentinel — Observed Endpoint Scope Audit

**Current release rule:** Agent 4 and Agent 5 use only literal endpoint values present in the replay input. Missing or invalid endpoints remain unknown. The system never fabricates an IP address from flow fingerprints.

## Organizer hidden input

The supplied 200-row hidden replay input contains native source_ip and destination_ip fields, alongside record_id, seq, protocol, ports, day, and time_offset. These observed endpoints are available to correlation and policy replay.

The CICIDS2017 training/evaluation feature partitions are feature matrices and do not supply native Layer-3 endpoints. That does not justify manufacturing endpoints for the hidden replay. Model training and endpoint-aware hidden replay remain separate concerns.

## Scope rules

- SOURCE_IP: a normalized literal IP from the current row's source_ip field.
- DESTINATION_IP: a normalized literal IP from the current row's destination_ip field.
- SRC_DST_PAIR: the normalized literal source and destination joined as source|destination.
- If a required endpoint is absent, malformed, or non-literal, the corresponding scope cannot be created or matched.
- TCP fingerprint fields such as Init_Win_bytes_forward, min_seg_size_forward, and Fwd Header Length are never converted into IP addresses.

## Validation

Both validators recompute policy scope matches from the original input row and the policy scope type. A BLOCK must reference a known policy that is active after its activation record and through its expiry record, inclusive. The scope must match the observed endpoint(s) for the blocked record.

## Limitations

- If an organizer replay input omits native endpoints, endpoint correlation and endpoint-scoped policy generation are intentionally unavailable for those records.
- No pseudo-IP, hash-derived identity, or fingerprint-derived endpoint is permitted in the official submission.
- The hidden input is unlabelled, so false-block rates and attack containment cannot be measured from the hidden replay itself.

Do not describe a missing endpoint as a synthetic or observed IP. Do not claim live firewall enforcement; all ALLOW/BLOCK outcomes are simulated offline replay actions.
