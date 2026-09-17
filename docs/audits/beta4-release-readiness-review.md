# Beta.4 release readiness review

Reviewed on 2026-09-17 against `7bc2b0a720f5f280c54053f3e0c9091db269fb05`,
with the readiness fixes committed alongside this report. Release tracking:
[#362](https://github.com/redact-secret/redact-secret/issues/362).

## Decision

Do not publish yet. The pino example can reconstruct a contextual credential
through interpolation after its arguments have been scanned independently.
[#361](https://github.com/redact-secret/redact-secret/issues/361) records the
minimal synthetic reproduction and the required actual-pino consumer tests.
The core correctly redacts the joined input; the integration's scan boundary
needs repair.

## Fixed in this review

- Tracing, logging, and MCP JavaScript walkers now preserve `__proto__` as an
  own data property instead of invoking the inherited setter. Tests verify
  redaction, JSON round trips, input preservation, and the output prototype,
  including enumerable Error properties.
- The Python logging filter sanitizes cached exception text when `exc_info`
  is absent. It also handles a depth-limit marker without indexing it as a
  dictionary or raising a secondary exception.
- Python tracing, MCP, and logging example tests now run through
  `npm run examples:test`, and therefore through `npm run ci`.
- Incorrect logging explanations about cached exception text and propagated
  records were replaced with concise descriptions. The release runbook now
  links release status instead of presenting beta.1/beta.2 as the current state.

## Scope and evidence

The review focused on beta.3-to-current changes, the built-in registry and
collision pipeline, public export drift, new integration examples, and release
checks. The core's priority ordering and disjoint-span acceptance remain
unchanged. The Rust crate-root exports, JavaScript source API, and Python
package declarations have no diff against the beta.3 tag. New finding types
and their policies still require a candidate compatibility review.

Local checks after the fixes:

- `npm run ci`: passed, including 117 JavaScript package tests, 91 assessment
  contract/adapter tests, and repository policy/release checks.
- `npm run examples:test`: 63 JavaScript and 56 Python tests passed.
- `cargo test --workspace --locked`: 839 tests passed across 20 suites,
  including detector, overlap, conformance, incremental and binding tests.
- `npm run rust:check`, `cargo fmt --all --check`, and
  `cargo clippy --workspace --all-targets --locked -- -D warnings`: passed.
- `npm run sast:scan`: passed the existing baseline (40 findings, 18 scan
  errors, zero unresolved). The acknowledged scan errors remain coverage
  limitations; this does not mean the scanner reported zero findings.
- `RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --locked`: passed.

The first CI attempt timed out after 30 seconds while its Rust adapter test
invoked Cargo during concurrent workspace compilation. After builds completed,
the unchanged assessment test and the full CI run passed. This is not a
performance assessment result; no large performance workload was run.

These checks do not establish exact-RC cross-platform qualification, actual SDK
consumer coverage, or an exhaustive absence of defects. Before release, resolve
#361, review and integrate these fixes, freeze the approved RC revision, then
collect its full qualification, rehearsal, SAST, API and changelog evidence.
Historical successful workflow runs do not qualify this modified revision.

No version, tag, package publication, workflow dispatch or release approval was
performed by this review.
