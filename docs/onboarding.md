# Developer onboarding and local validation

[Documentation home](README.md) · [Contribution guide](../CONTRIBUTION.md)

Read [architecture](../ARCHITECTURE.md), [conventions](../CONVENTIONS.md),
[decisions](decisions/DECISIONS.md), and [workspace policy](rust-workspace.md)
before changing behavior. Use unmistakably synthetic or revoked examples only.
Findings, errors, snapshots, and diagnostics must not copy matched values.

## Run the repository checks

From the root, with a supported Node version and Rust 1.88 or newer:

```bash
npm ci
npm run ci
npm run rust:check
cargo fmt --all --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
```

`npm run ci` checks declarations, release guards, conformance schema, JavaScript
types, and wrapper tests. It does not run the full native platform matrix or
substitute for the real artifact qualifiers. [Qualification](qualification.md)
and [Python packaging](python-packaging.md) give those commands and inputs.

Detector, redaction, overlap, or policy changes need deterministic regressions.
Prefer the shared [conformance corpus](../conformance/README.md) for behavior
that all runtimes must preserve. Explain false-positive and false-negative
tradeoffs. Keep host I/O in adapters and the Rust core side-effect free.

## Documentation

User-facing guides live under `docs/` and start at [the documentation home](README.md).
Use ordinary Markdown, descriptive headings, relative links, and synthetic
examples. Keep current behavior distinguishable from historical audits and
future work. Describe only capabilities that the shipping runtime can execute.

Existing audit and decision URLs are preserved for traceability.

## Release boundary

Review changes to the public API and [changelog](../CHANGELOG.md).
Local green tests are not cross-platform qualification or registry verification.
Release approval, version selection, tagging, publication, and deployment follow
[the repository's release authority](../AGENTS.md); editing or reviewing the
repository does not itself authorize them.
