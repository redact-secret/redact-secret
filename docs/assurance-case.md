# Security assurance case

This document argues why Redact Secret's security requirements are met. It
connects the [threat model](specs/threat-model.md), the trust boundaries, the
secure design principles the code follows, and the common implementation
weaknesses it counters, each with the evidence a reviewer can check.
[SECURITY.md](../SECURITY.md) states the security model users can rely on;
where this document and SECURITY.md differ, SECURITY.md governs.

## Claim

Given text the caller does not control, the core returns findings and
redacted text such that **no supported credential's plaintext is exposed by
the library itself** — not in findings, errors, diagnostics, or logs — and
processing is **bounded, deterministic, and free of side effects**, so the
library can sit on an authoritative server boundary.

The claim is limited to supported credential formats and to the core and its
bindings. What the library does not protect against is listed in the threat
model's
[Does not protect against](specs/threat-model.md#does-not-protect-against-documented-not-findings)
and [Residual risks](specs/threat-model.md#residual-risks-accepted) sections.

## Threat model and trust boundaries

[`docs/specs/threat-model.md`](specs/threat-model.md) names the assets
(plaintext secrets in input, the sanitized output, findings), the attackers
considered (anyone who controls the scanned text, a malicious or careless
extension author, a compromised dependency or build), and the data flow.

There are two trust boundaries
([ARCHITECTURE.md](../ARCHITECTURE.md#security-boundaries)):

1. **Untrusted text → core.** All input is untrusted. Everything downstream
   of the core (logs, storage, model context) receives only sanitized text
   and plaintext-free findings.
2. **Client → server.** Client-side scanning is preventive UX only; the
   server-side scan is the authoritative enforcement point and must run even
   when a client already scanned.

Custom detectors, policies, and formatters are trusted in-process code, and
findings passed directly to `redact` are trusted caller assertions
([SECURITY.md](../SECURITY.md#extension-and-caller-trust)).

## Secure design principles

| Principle (Saltzer and Schroeder) | How it is applied | Evidence |
| --- | --- | --- |
| Economy of mechanism | One Rust core implements detection, overlap resolution, policy, and redaction; JavaScript, Python, WebAssembly, and the CLI call it instead of reimplementing it. The core has one runtime dependency (`unicode-normalization`). | [ARCHITECTURE.md § System topology](../ARCHITECTURE.md#system-topology), `crates/secret-scan-core/Cargo.toml` |
| Fail-safe defaults | Limit, extension, and input failures fail closed and input-free; unknown or over-limit input is rejected, not passed through. Whole-input operations are bounded by default (64 MiB, 50,000 findings). | [ADR: bound whole-input operations by default](decisions/2026-09-19-bound-whole-input-operations-by-default.md), [API contract](reference/api-contract.md) |
| Complete mediation | Every runtime surface goes through the same canonical pipeline; placeholders are checked against every finding's range, including `warn` and `allow` findings. | [ARCHITECTURE.md § Canonical processing pipeline](../ARCHITECTURE.md#canonical-processing-pipeline), [SECURITY.md](../SECURITY.md#extension-and-caller-trust) |
| Open design | All detectors, rules, and evidence are public; security does not depend on hiding how detection works. | [`docs/specs/`](specs/), [conformance corpus](../conformance/README.md) |
| Separation of privilege | Detection is separate from policy enforcement; a detector proposes, policy decides the action. | [ARCHITECTURE.md § Detection and policy separation](../ARCHITECTURE.md#detection-and-policy-separation) |
| Least privilege | The core performs no network, filesystem, environment, or telemetry access. CI and release jobs get no default token permissions and only the write scopes an allowlist names. | [SECURITY.md § Security model](../SECURITY.md#security-model), `scripts/check-artifact-matrix.py` (`WRITE_SCOPE_ALLOWLIST`) |
| Least common mechanism | No shared mutable or global state between scans; incremental sanitizers own their bounded buffers. | [ARCHITECTURE.md § Incremental and streaming behavior](../ARCHITECTURE.md#incremental-and-streaming-behavior) |
| Psychological acceptability | Safe defaults need no configuration; five-minute quick starts; placeholders keep redacted text readable. | [Quick start](quickstart.md), [safe integration guide](guides/safe-integration.md) |

## Common weaknesses countered

| Weakness | Countermeasure | Evidence |
| --- | --- | --- |
| Exposure of sensitive information in output, logs, or errors (CWE-200, CWE-209, CWE-532) | Findings and errors carry classifications and ranges only, never matched text; placeholders that could reproduce a secret are rejected. | Core error and finding types (`crates/secret-scan-core/src/error.rs`, `types.rs`); conformance tests asserting plaintext-free errors |
| Uncontrolled resource consumption, including regular-expression denial of service (CWE-400, CWE-770, CWE-1333) | The core matches with hand-written, linear-time scanners and no backtracking regex engine, so its ReDoS surface is zero by construction; overlap resolution is `O(n log n)`; input size, finding count, retained plaintext, and token lengths are bounded and fail closed. | [Ruleset contract ADR](decisions/2026-09-19-define-declarative-detector-ruleset-contract.md), [`docs/specs/engine.md`](specs/engine.md), `crates/secret-scan-core/src/limits.rs`, `tests/adversarial_bounds.rs`, `tests/whole_input_limits.rs` |
| Memory-safety errors (CWE-119, CWE-416) | The core is safe Rust with `#![forbid(unsafe_code)]`; the workspace denies `unsafe_code`. | `crates/secret-scan-core/src/lib.rs`, `Cargo.toml` `[workspace.lints]` |
| Integer overflow and range errors across encodings (CWE-190, CWE-131) | Ranges are translated between UTF-8, UTF-16, and code points by one tested path; Clippy denies panicking shortcuts (`unwrap`, `expect`, `panic`). | [ARCHITECTURE.md § Runtime surfaces and range units](../ARCHITECTURE.md#runtime-surfaces-and-range-units), `tests/unicode_conversion_corpus.rs` |
| Detection bypass by obfuscation (invisible characters, normalization) | Input is NFC-normalized and invisible characters are handled before matching, with ranges mapped back to the original input. | `crates/secret-scan-core/src/normalize.rs`, `tests/invisible_normalization.rs` |
| Nondeterminism that hides divergence between runtimes | Every binding runs the same conformance corpus; CI compares shadow evaluations byte for byte across Linux, macOS, Windows, and wasm32. | [ARCHITECTURE.md § Cross-language conformance](../ARCHITECTURE.md#cross-language-conformance), `shadow-determinism` CI job |
| Supply-chain compromise (CWE-1357, CWE-829) | Actions pinned to commit SHAs; `npm ci --ignore-scripts`; `cargo deny`; Dependabot; Scorecard; pinned, signature-verified OpenGrep SAST; release artifacts qualified and digest-checked before publication; npm provenance and PyPI attestations. | [SECURITY.md § CI supply-chain review](../SECURITY.md#ci-supply-chain-review), [CI supply-chain review](https://github.com/redact-secret/redact-secret/blob/2816897f96c405c3eb8c87a0c70eba5df273c121/docs/audits/ci-release-automation-supply-chain-review.md), [qualification](qualification.md) |

## Verification

The claim is checked continuously, not only at review time:

- deterministic unit, integration, and cross-runtime conformance tests on
  every pull request, with Rust line coverage held at or above 80%
  ([rust-workspace.md](rust-workspace.md));
- a fixed-seed invariant fuzz test in the core (`redact.rs`) and adversarial
  bound tests;
- static analysis (OpenGrep SAST, Clippy with warnings denied) and OpenSSF
  Scorecard;
- the [vulnerability reporting process](../SECURITY.md#how-reports-are-handled),
  with a regression test for every confirmed defect
  ([synthetic regression convention](../conventions/synthetic-secret-regressions.md)).
