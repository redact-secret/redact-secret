# Changelog

This file records the released product contract and notable changes. Release
evidence is linked from each published version.

## Unreleased

- Assessment tooling now includes a CLI binary runner, self-test command, and
  first checked-in correctness/performance baseline with explicit process
  startup, process-inclusive processing, and whole-process RSS measurements.
- Assessment tooling now evaluates an installed Python package through both
  whole-input and incremental APIs, normalizes code-point ranges to canonical
  UTF-8 byte spans, and records the first correctness, timing, Python-allocation,
  and whole-process RSS baseline with explicit sampling limits.
- Assessment tooling now includes a Rust library runner, self-test command,
  and first checked-in correctness/performance baseline for the `rust-core`
  surface.
- Node.js and browser packages now expose working bounded incremental
  sanitization plus Node `Transform` and Web `TransformStream` adapters.
  Candidate qualification installs packed packages outside the checkout,
  exercises those public APIs on Node.js 20, 22, and 24 and in Chromium,
  Firefox, and WebKit, and records revision- and digest-bound results.

## 0.1.0-beta.1 — 2026-09-11

[Publication evidence](docs/releases/0.1.0-beta.1/README.md).

### Product and packages

- Redact Secret provides deterministic secret detection and redaction through
  one side-effect-free Rust core, shared by JavaScript, Python, Rust, and CLI
  consumers. The canonical `conformance/` corpus defines cross-language behavior.
- The first release artifact set comprises the `redact-secret` Rust library,
  `redact-secret-cli` crate and `redact-secret` binary, the `redact-secret` PyPI
  distribution (import `redact_secret`), and the `@redact-secret/core` npm
  package with `@redact-secret/wasm` and six `@redact-secret/node-<platform>`
  runtime dependencies. All share one version and source revision.
- The TypeScript detector implementation has been removed. JavaScript exposes
  policy and placeholder formatter callbacks over safe metadata; it does not
  restore the retired custom-detector API. Rust retains its native detector
  traits and registry; custom detector callbacks do not cross language bindings.

### Public behavior and support

- Whole-input scan, redaction, and combined operations return finding metadata
  without matched values. Ranges refer to the original input: UTF-8 bytes in
  Rust and CLI, UTF-16 code units in JavaScript, Unicode code points in Python.
- Default policy blocks private keys, redacts known credential structures and
  other high-confidence findings, and warns on other findings. Redaction
  replaces `redact` and `block` spans; `warn` and `allow` preserve text. Hosts
  enforce `block`. Caller-supplied overlapping redaction ranges are rejected.
- Built-in coverage includes private keys, provider token families,
  authorization/JWT credentials, contextual assignments, credential-bearing
  connection URLs, and OTP shared-secret URIs. See the
  [detection reference](docs/reference/detection.md) for supported formats and
  precision/recall limits. Entropy alone is not a detection signal sufficient
  to classify arbitrary text.
- Rust, Python, and CLI standard input support bounded incremental sanitization.
  JavaScript session and stream factories fail with `INCREMENTAL_UNAVAILABLE`
  on both current artifacts; exported adapter contracts do not imply support.
- JavaScript is ESM with explicit `await initialize()`. Node.js 20, 22, and 24
  support glibc Linux, macOS, and Windows on x64 and arm64. npm and CLI ship six
  non-musl targets. The two additional musl addons are qualified only, with no
  npm publication path. Browsers require ES2022 and WebAssembly; qualification
  covers Chromium, Firefox, and WebKit.
- Python provides typed CPython 3.10+ abi3 wheels for eight targets: manylinux,
  musllinux, macOS, and Windows on x64 and arm64. Source builds require Rust;
  the workspace MSRV is 1.88. See the [qualification matrix](docs/qualification.md).
- CLI check mode reports safe metadata with exit codes 0 (clean), 1 (findings),
  and 2 (failure); redaction returns 0 or 2. Text source labels escape control
  characters and backslashes, and JSON preserves source identity.

### Security and release evidence

- The core has no runtime I/O, environment lookup, telemetry, or secret storage.
  Errors use fixed, input-free codes and messages; callback errors and unsafe
  placeholders fail closed. Client scanning is preventive UX; server scanning
  is authoritative. Hosts must bound whole-input resources and Python chunks.
- Version lockstep includes the private root manifest, every Cargo member,
  JavaScript facade, and all native/Wasm manifests. The legacy-identifier gate
  rejects unintended old identities, including in this changelog.
- The pinned OpenGrep engine and vendored rules are verified against the reviewed
  baseline. The CI gate fails on unresolved findings or unacknowledged scan
  errors independently of best-effort SARIF upload. A baseline pass is not a
  claim of zero findings or complete parser coverage.
- Qualification, package-content checks, and clean packed-package consumer
  tests precede publication. The release graph verifies all seven npm runtime
  dependencies before publishing the facade and records durable manifests for
  successful and failed runs. Reconciliation requires separate authorization.
- This first beta consolidates the unpublished development history; the former
  dated entry was not a published release. All packages were published from
  the original qualified RC source; recovery verified existing content before
  skipping it, and all seven registry-install lanes passed.
