---
owner: #1263
reviewed_source: 2816897f96c405c3eb8c87a0c70eba5df273c121
status: retained
retire_on: after-release:0.1.0-beta.14
candidate_version: 0.1.0-beta.14
review_scope: public-api-and-compatibility
disposition: accepted-with-limitations
limitations: SecretScanErrorCode::ALL grows from 22 to 23 elements so a caller that spells its array type must update; the support matrix is not refreshed for the eight new detectors; this review is evidence and not release approval
previous_review_record: https://github.com/redact-secret/redact-secret/blob/2816897f96c405c3eb8c87a0c70eba5df273c121/docs/audits/beta12-candidate-public-contract-review.md
previous_review_sha256: 590e9c4c055370961244311b479e6db656eebb6794381be25d6f4bd7af12b9fd
---

# Beta.14 candidate public-contract review

[Documentation home](../README.md) · [Audit archive](README.md)

This is the one retained review of the version being prepared
(`decision-retire-historical-audit-bodies-before-release-qualification`). The
artifact inventory selects it because its front matter binds it to
`candidate_version: 0.1.0-beta.14`; a review bound to any other version cannot
stand in for it. After publication its conclusions move into
`docs/releases/0.1.0-beta.14/` and this body is retired.

- Candidate: `0.1.0-beta.14` (PEP 440 `0.1.0b14`), prepared by PR #1245.
- Previous published source: `v0.1.0-beta.13`,
  `66b492bdff5e6751fc6b5409266916346ed7c723`.
- Reviewed source: `2816897f96c405c3eb8c87a0c70eba5df273c121` (`main`). The
  qualified commit is a descendant of it; the inventory fails if it is not.
- Reviewed on: 2026-10-06. Scope: public API and compatibility only. The
  changelog is hashed beside it in the inventory; benchmarks, performance and
  support status are other evidence.
- The beta.12 review, cited as history only: its complete text is at the
  permalink and SHA-256 in the front matter. It was written for another
  version and satisfies nothing here.

## Verdict

**Additive in every binding and the CLI.** Nothing was removed, renamed or
re-signed: the Rust root exports, the JavaScript and Python exports, the CLI
arguments, the error codes and the finding `type` values of beta.13 are all
still present with the same meaning. No `Changed` entry exists in the
`0.1.0-beta.14` changelog section, consistent with that. One additive change
has a source-compatibility edge, recorded as a limitation below.

## Surface by surface

Verified against `v0.1.0-beta.13..HEAD`, not copied from the PR description.

| Surface | beta.13 | beta.14 | Class |
| --- | --- | --- | --- |
| Rust crate root (`core-public-api` in `Cargo.toml`, `tests/public_api.rs`) | 54 names | 72 names, none removed | Additive |
| Core error codes (`SecretScanErrorCode`) | 22 | 23: `INVALID_ACTION_POLICY` | Additive; see ALL note |
| JavaScript values (`@redact-secret/core`, `/common`) | no `status`, `compareActionPolicies`, `defaultPolicy` | those three plus the `actionPolicy` option and 17 new exported types; error code union gains `INVALID_ACTION_POLICY` | Additive |
| Python `__all__` | 44 names | 55 names, none removed | Additive |
| CLI arguments | `--json`, `--redact`, `--ruleset`, `--pii`, `--print-pii-activation`, `--` | adds `--action-policy <path>` and `--compare-action-policy <path>` | Additive |
| Finding types and detectors (`docs/coverage/detector-inventory.json`) | 141 types, 110 detectors | 157 types, 118 detectors; none removed or renamed | Additive, behavior (new findings) |

### Rust

Eighteen names were added: `ActionPolicy`, `ActionPolicyError`,
`ActionPolicyErrorClass`, `MAX_ACTION_POLICY_BYTES`, `load_action_policy`,
`ActionComparison`, `ActionCounts`, `ActionDecision`, `ComparedFinding`,
`ComparedPolicy`, `ComparedSide`, `DecisionBasis`, `DetectionIdentity`,
`MAX_COMPARED_POLICIES`, `PolicyBinding`, `compare_action_policies`,
`compare_action_policies_with_limits` and `BuiltInRegistry`. No dependency was
added to the core (`sha256` is an internal module).

`SecretScanErrorCode` is `#[non_exhaustive]`, so the new `InvalidActionPolicy`
variant cannot break a `match`. Its `ALL` constant is typed
`[Self; 23]` instead of `[Self; 22]`. Code that indexes or iterates `ALL` is
unaffected; code that writes the array type or destructures it by length stops
compiling. That is the one compatibility edge in this release. It is classed
additive because the documented contract is that the code set grows and
callers handle an unknown code (`docs/reference/api-contract.md`), and the
length is not a documented guarantee.

### JavaScript, WebAssembly and the Node addon

`status()`, `compareActionPolicies()` and `defaultPolicy` are new exports of
the root and `./common` entries; `actionPolicy` is a new optional field of
`ScanOptions` and `IncrementalSanitizerOptions`. The `exports` map and
subpaths are unchanged. The `SecretScanErrorCode` union gains `INVALID_ACTION_POLICY`, so a
TypeScript `switch` that is exhaustive over the union with a `never` check
needs a new case; this is the same growth contract as the Rust code set. The
WebAssembly callback path now reports `INVALID_POLICY_ACTION` for a callback
that returns an invalid action, matching Node and the incremental adapter
(it reported `POLICY_FAILURE`): an error-code refinement within the existing
failure class, called out here because a caller that matched the old code
would see the more precise one. The Node addon adds `#[napi]` functions for
the same features and removes none.

### Python

Eleven names were added to `__all__`: `ActionComparison`, `ActionCounts`,
`ActionDecision`, `ComparedFinding`, `ComparedPolicy`, `ComparedSide`,
`CoreStatus`, `DetectionIdentity`, `InvalidActionPolicyError`,
`compare_action_policies` and `status`. `action_policy=` is a new keyword of
the whole-input and incremental-session entry points, mutually exclusive with
`policy`.

### CLI

`--action-policy <path>` applies a declarative policy to check and redact
modes. `--compare-action-policy <path>` (one to three times, one file path,
not standard input, not `--redact`) is a read-only preview. No existing
argument, report field or exit code changed; compare mode defines exit 0 (all
agree), 1 (some action differs) and 2 (failure), using the existing 0/1/2
meanings.

### Behavior, not API

Eight detectors were added (`buildkite-token`, `fly-token`, `mapbox-token`,
`pydantic-logfire-token`, `sourcegraph-token`, `square-token`,
`unkey-root-key`, `xata-api-key`), and `generic-token`, `bearer-token` and
`connection-string` changed within their documented classes (changelog
`Fixed`). These change what is reported and redacted, not the API. The
WebAssembly artifacts grow by the comparison and the core's SHA-256 (about
7.0% brotli for `full`, accepted and recorded in the changelog). The support
matrix is not refreshed for this version.

## Disposition

Accepted with limitations. The public API change since `0.1.0-beta.13` is
additive in every binding and the CLI: no export, error code, argument, range
unit, finding type or callback contract was removed, renamed or re-signed.
The limitations are the `SecretScanErrorCode::ALL` array-length change, the
unrefreshed support matrix for the eight new detectors, and the narrower
scope of this review (public API and compatibility). This review is evidence
for the release approval request. It does not approve, publish or tag
anything: the approved version, the exact qualified source SHA and explicit
user approval remain separate, and any tree change after qualification needs
a new qualification.
