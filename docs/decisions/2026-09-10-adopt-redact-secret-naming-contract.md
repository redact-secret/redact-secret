---
decision_id: decision-adopt-redact-secret-naming-contract
status: accepted
scope: workspace
title: Adopt the Redact Secret naming contract
decided_at: 2026-09-10
full_record: https://github.com/redact-secret/redact-secret/blob/180335698aba54f71e3e994f1a90da6752f06396/docs/decisions/2026-09-10-adopt-redact-secret-naming-contract.md
spec: distribution
---
# Adopt the Redact Secret naming contract

Summarized in place 2026-09-22 by
[#600](https://github.com/redact-secret/redact-secret/issues/600) (DS6d
disposition grade). The `full_record` link above is the complete pre-summary
text: the scope-boundary reasoning, PEP 503 notes, 2026-09-10
registry-availability evidence, alternatives, and both former
`Current application` appendices. The current rules live in
[`docs/specs/distribution.md`](../specs/distribution.md).

## Decision

Replace the `secret-scan` public identity with `Redact Secret` across every
registry, import, binary, and internal metadata namespace: product
`Redact Secret`; repository `redact-secret/redact-secret` (was
`omiologic/secret-scan`); npm `@redact-secret/core`, `@redact-secret/wasm`,
and `@redact-secret/node-<platform>` (were `@omiologic/secret-scan*`); crates
`redact-secret` and `redact-secret-cli`, Rust import `redact_secret`, CLI
binary `redact-secret` (were `secret-scan*`); PyPI `redact-secret`, Python
import `redact_secret` (were `omiologic-secret-scan` and `secret_scan`). The
behavioral description, "Deterministic secret detection and redaction," is
unchanged. Exported error names (`SecretScanError`, `SecretScanErrorCode`)
and the `crates/secret-scan-*` directory paths are deliberately out of scope.

## Consequences

`scripts/check-legacy-identifiers.py` is a permanent `npm run ci` gate
against the old identity outside a per-path, rationale-bearing historical
allowlist, and `scripts/verify-release-governance.py` rechecks registry-name
availability before release-candidate sign-off. Accepted ADRs written under
the old names are allowlisted, not rewritten. The decision authorized no
version, tag, publication, or repository transfer; #157 later completed the
transfer.
