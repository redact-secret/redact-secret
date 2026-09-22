---
decision_id: decision-adopt-redact-secret-naming-contract
status: accepted
scope: workspace
title: Adopt the Redact Secret naming contract
decided_at: 2026-09-10
---
# Adopt the Redact Secret naming contract

## Current application — 2026-09-19 (#442)

The naming matrix below gains one row: `@redact-secret/adapter*` (npm) and
`redact-secret-adapters` (PyPI), for the host-integration packages
`decision-graduate-adapters-to-a-separate-repository` graduates into the
separate `redact-secret/redact-secret-adapters` repository. That repository
owns its own naming and release authority; this contract only records the
identity it uses, the same way this document already records identities for
surfaces this repository does not itself publish (the six
`@redact-secret/node-<platform>` packages).

**Three meanings of "adapter" now coexist in this project, and this
contract disambiguates them so a future reader does not conflate them:**
*stream adapters* (`packages/javascript/src/adapters/`, the `Transform`/
`TransformStream` wrappers inside `@redact-secret/core` described in
[`ARCHITECTURE.md`](../../ARCHITECTURE.md)'s "Incremental and streaming
behavior"), *host adapters* (the CLI and the language bindings themselves —
"the CLI is a host adapter over the same core," per `README.md` and
`ARCHITECTURE.md`'s "Command-line host behavior" section), and these new
*host-integration packages* (`@redact-secret/adapter*` / `redact-secret-
adapters`, published from the separate adapters repository). None of the
three is renamed by this update; the disambiguation exists because the third
meaning is new as of this decision.

## Current application — 2026-09-11 (#144)

The accepted naming matrix below is implemented. The canonical repository is
now `redact-secret/redact-secret`; #157 completed the transfer, and current
manifest repository/homepage/bugs URLs use it. Metadata uses
`[workspace.metadata.redact-secret]`. The transfer-pending scope boundary and
registry observations below describe the decision-time state, not the current
candidate. `SecretScanError`/`SecretScanErrorCode` and internal crate-directory
paths remain unchanged as decided.

The original body is retained as historical rationale. The current artifact
mapping is recorded in the [first-release decision's current application](2026-09-10-ship-first-release-artifact-set.md#current-application--2026-09-12-181-182).
The candidate changelog is current product documentation and is no longer on
the historical-name allowlist. No version or release operation is authorized
by this update.


## Decision

Replace the `secret-scan` public identity with `Redact Secret` across every
registry, import, binary, and internal metadata namespace, following exactly
this naming matrix:

| Surface | Old identity | New identity |
| --- | --- | --- |
| Product | `secret-scan` | `Redact Secret` |
| GitHub repository | `omiologic/secret-scan` | `redact-secret/redact-secret` |
| npm facade | `@omiologic/secret-scan` | `@redact-secret/core` |
| npm WebAssembly package | `@omiologic/secret-scan-wasm` | `@redact-secret/wasm` |
| npm native packages | `@omiologic/secret-scan-<platform>` | `@redact-secret/node-<platform>` |
| Rust core crate | `secret-scan` | `redact-secret` |
| Rust CLI crate | `secret-scan-cli` | `redact-secret-cli` |
| Rust library import | `secret_scan` | `redact_secret` |
| CLI binary | `secret-scan` | `redact-secret` |
| PyPI distribution | `omiologic-secret-scan` | `redact-secret` |
| Python import | `secret_scan` | `redact_secret` |
| npm host-integration packages (separate `redact-secret-adapters` repository) | — (new as of 2026-09-19, #442) | `@redact-secret/adapter*` |
| PyPI host-integration distribution (separate `redact-secret-adapters` repository) | — (new as of 2026-09-19, #442) | `redact-secret-adapters` |

The product's behavioral description does not change: this remains
"Deterministic secret detection and redaction." Renaming the product name does
not narrow, widen, or otherwise touch that contract.

### Explicit scope boundaries

Three surfaces this contract deliberately does **not** touch, so a future
contributor does not reopen them as oversights:

- **Exported error type/class names are unchanged.** `SecretScanError` and
  `SecretScanErrorCode` (pinned in `[workspace.metadata.secret-scan]
  core-public-api`, mirrored by the Python exception hierarchy, the JS
  `SecretScanError` class, and the WASM error name) stay as they are. This
  contract renames package, import, and binary identity — not exported type
  names, which are a larger, independently-breaking consumer-facing surface.
  A future decision may rename them, but this one does not.
- **`crates/secret-scan-core/` and `crates/secret-scan-cli/` directory names
  are unchanged.** Cargo resolves a crate by the name declared in its
  manifest, not by the directory that contains it. Directory paths here are
  internal build-tooling infrastructure, not public runtime identity, and are
  out of scope for this rename.
- **`repository`/`homepage`/`bugs` URLs in manifests keep pointing at
  `github.com/omiologic/secret-scan` for now.** The GitHub repository transfer
  to `redact-secret/redact-secret` is a separately authorized action (tracked
  by issue #157) that has not happened yet. Pointing manifest URLs at the new
  path before the transfer would publish a dead link. These URLs move as part
  of #157's own follow-up, not this contract.

### PEP 503 normalization

PyPI normalizes project names per PEP 503: runs of `-`, `_`, and `.` collapse
to a single `-` and the result is lowercased. `redact-secret`, `redact_secret`,
and `redact.secret` therefore all resolve to the same PyPI project identity.
The Python distribution name (`redact-secret`) and the Python import name
(`redact_secret`) are two different strings by design — the former is a PyPI
identity, the latter a module path — but neither is a distinct *alias* PyPI
would treat as a second project; only `redact-secret`, `redact_secret`, and
`redact.secret` are the same normalized alias set.

### Registry-availability evidence

Checked on 2026-09-10, against each registry's public read-only API, using the
same 404-means-no-public-project convention this workspace's release scripts
already use (see `scripts/check-rust-workspace.py`,
`scripts/check-python-package.py`):

- **crates.io**: `redact-secret` and `redact-secret-cli` both return 404 —
  no public project exists under either name today.
- **npm**: `@redact-secret/core` and `@redact-secret/wasm` both return 404 on
  the public registry; issue #151 additionally records that the `@redact-secret`
  npm organization itself is already owned by the project operator.
- **PyPI**: `redact-secret` and its PEP 503 normalized alias `redact_secret`
  both return 404 — no public project exists under either spelling.
- **GitHub**: `redact-secret/redact-secret` returns 200 — an empty placeholder
  repository the project operator already owns, per issue #151's evidence.
  This placeholder secures the target path; it is not the canonical source
  repository, and #157 owns the actual transfer.

A 404 above is evidence that no public project exists under that name today.
It is not evidence of a *reservation* — nothing in this decision or its
implementation creates a placeholder package on npm, crates.io, or PyPI to
hold a name. `scripts/verify-release-governance.py` rechecks this same
evidence immediately before release-candidate sign-off (issue #153), using
the identical 404 semantics.

### Allowlist mechanism for historical references

Implementing this contract (issue #152) does not mechanically rewrite every
occurrence of the old identity. Historical ADRs, closed audits, and the
prepared Python-repository redirect notice describe what was true when they
were written, and rewriting them would misrepresent history rather than
correct it. `scripts/check-legacy-identifiers.py` (issue #153) enforces this
distinction: it scans the whole repository for the old identity and fails
unless the hit is on its `LEGACY_IDENTIFIER_ALLOWLIST`, keyed by exact path
with a mandatory, non-empty, per-entry rationale. Only reviewed historical ADR,
audit, migration, and redirect documents are allowlisted; anything else — a
manifest, a source import, a workflow, current documentation — must use the
new identity or the check fails.

## Rationale

A single accepted matrix, decided once before implementation begins, is what
lets `scripts/check-legacy-identifiers.py` distinguish "this old-name
occurrence is a deliberate historical record" from "this old-name occurrence
is a missed rename" — without one, every future old-name grep hit would need
re-litigating case by case. Recording registry availability with a date
attached (rather than as a permanent claim) matches how this workspace already
documents crate/PyPI availability in `docs/rust-workspace.md`'s "Registry
names" section, and lets a later recheck (issue #153's registry preflight)
detect drift between this decision and reality at sign-off time.

## Alternatives considered

- Renaming `SecretScanError`/`SecretScanErrorCode` in the same pass was
  considered and rejected for this decision: it is a materially larger
  breaking change for existing consumers (`catch`/`except`/`instanceof`
  clauses) than a package or import rename, and bundling it here would make
  the two changes' compatibility consequences indistinguishable. It can be
  proposed as its own decision later.
- Renaming the `crates/secret-scan-core/`/`crates/secret-scan-cli/` directories
  to match the new crate names was considered and rejected: Cargo does not
  resolve crates by directory path, so the rename would touch every path
  literal in scripts and workflows for no change in public identity.
- Updating manifest `repository`/`homepage`/`bugs` URLs immediately, ahead of
  the actual GitHub transfer, was considered and rejected: it would point
  published-looking metadata at a URL that returns 404 for anyone who follows
  it before issue #157 completes the transfer.

## Consequences

- `scripts/check-rust-workspace.py`, `scripts/check-python-package.py`, and
  `scripts/check-artifact-matrix.py` read their expected identity from
  `[workspace.metadata.secret-scan]` (renamed to
  `[workspace.metadata.redact-secret]` as part of applying this contract) —
  implementation changes that table and every script/workflow/document that
  currently hardcodes the old identity, in the order recorded in this
  session's implementation plan.
- `scripts/check-legacy-identifiers.py` becomes a permanent, always-on `npm run
  ci` gate against reintroducing the old identity outside its allowlist.
- `scripts/verify-release-governance.py` gains a registry-name preflight that
  rechecks this decision's availability evidence — across npm, crates.io,
  PyPI (including its normalized aliases), and GitHub — immediately before a
  future release candidate's sign-off, so any conflict found later blocks
  readiness rather than silently reusing 2026-09-10's evidence.
- This decision amends no consequence of `decision-release-bindings-in-lockstep`
  or `decision-ship-first-release-artifact-set`: one product, one shared
  version, one tag, and the commitment to ship all four artifacts together
  remain exactly as those decisions recorded them. It changes only the literal
  identity strings those decisions and their implementations use. Their body
  text, having described what was decided on 2026-09-09 and 2026-09-10 under
  the names then in force, is not rewritten; it becomes a
  `LEGACY_IDENTIFIER_ALLOWLIST` entry in issue #153's declaration check.
- This decision does not select a version, create a release branch or tag,
  publish to any registry, create a GitHub release, deploy, archive, transfer
  the repository, or dispatch a workflow. Existing release authority
  (`AGENTS.md`, "Release authority") remains in force, and issue #157 alone
  owns the GitHub repository transfer this decision merely prepares for.
