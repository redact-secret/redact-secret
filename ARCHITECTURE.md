# Architecture

## Overview

Redact Secret is a deterministic, cross-language text-inspection product for
detecting and redacting credentials before untrusted content crosses a trust
boundary. One Rust core is the canonical implementation of built-in detection,
candidate normalization and overlap resolution, policy evaluation, redaction,
and bounded incremental sanitization.

JavaScript, Python, Rust, and CLI consumers use runtime-specific surfaces over
that core. Bindings translate host values, callbacks, errors, and string ranges;
they do not reimplement detector behavior.

The core is side-effect free. It performs no runtime network or filesystem
access, environment lookup, telemetry, secret storage, model invocation, or UI
work. These constraints make the same behavior suitable for browsers, Node.js,
Python applications, Rust applications, CLIs, serverless runtimes, MCP systems,
and agent/tool gateways.

## Migration state

This document describes the accepted target architecture. Migration progress
was tracked by [issue #3](https://github.com/redact-secret/redact-secret/issues/3)
and its sub-issues rather than duplicated here.

The migration is complete:

- `crates/secret-scan-core` and the top-level `conformance/` corpus are the
  canonical source of behavior;
- `packages/javascript` is the published JavaScript package (`@redact-secret/core`)
  over the Node and WebAssembly bindings; and
- the repository-root TypeScript detector core that previously served as the
  behavioral oracle has been removed (`RB-2`, issue #72).

Git preserves the retired implementation's history. The repository does not
maintain a second detector implementation.

## Security boundaries

The main architectural distinction is between intentional credential storage
and conversational or textual context.

```text
Intentional credential path

User -> Credential Manager -> Secret Vault -> Provider Gateway -> Provider
```

```text
Untrusted text path

User / Tool / MCP / Log
          |
          v
    Redact Secret
          |
          v
     Sanitized Text
          |
          v
Conversation / Context / Storage / Model
```

A credential vault may contain secrets. Conversation history, model context,
knowledge stores, logs, telemetry, and diagnostics must not.

Client-side scanning is preventive UX: it can warn or redact before plaintext
leaves a device. Server-side scanning is the authoritative enforcement boundary
and must run even when a client also scans. This protects direct API clients,
older or modified clients, CLIs, SDKs, MCP integrations, and agents.

Applications must not log raw request or tool bodies before scanning. Findings,
errors, callbacks, fixtures, snapshots, and diagnostics must not expose matched
plaintext.

## System topology

```text
JavaScript                      Python          Rust          CLI
   |                               |              |             |
   +-> Node: N-API addon           +-> PyO3       |             |
   |      bindings/node                binding    |             |
   |                               bindings/python             |
   +-> Browser: wasm-bindgen                      |             |
          bindings/wasm                           |             |
   |                               |              |             |
   +-------------------------------+--------------+-------------+
                                   |
                                   v
                         crates/secret-scan-core
                                   |
             detection -> overlap -> policy -> redaction
                                   |
                                   v
                      safe text + safe metadata

                  conformance/ is the shared contract
```

The binding and package layout is:

| Path | Responsibility | Public artifact |
| --- | --- | --- |
| `crates/secret-scan-core` | Canonical detector, policy, redaction, and incremental behavior | crates.io library crate |
| `crates/secret-scan-cli` | Process arguments, files, standard streams, output, and exit codes | `redact-secret` binary |
| `bindings/node` | N-API conversion between Node.js and the Rust core | Eight `@redact-secret/node-<platform>` packages (glibc and musl Linux, macOS, Windows) |
| `bindings/wasm` | `wasm-bindgen` conversion between browsers and the Rust core | `@redact-secret/wasm` (root `full`, `./common`) |
| `bindings/python` | PyO3 extension and Python-facing package surface | PyPI `redact-secret`, imported as `redact_secret` |
| `packages/javascript` | One typed API with runtime-specific loading | `@redact-secret/core` |
| `conformance` | Language-neutral behavioral fixtures and schema | Repository contract, not a package |
| `assessment` | Language-neutral evaluation protocol: assessment corpus, workload profiles, result contract | Repository protocol, not a package, not a release gate |
| [`redact-secret/redact-secret-adapters`](https://github.com/redact-secret/redact-secret-adapters) (separate repository) | Host-integration packages (pino, Python `logging`, OpenTelemetry `SpanProcessor`) built against this repository's public core API only | `@redact-secret/adapter*` (npm), PyPI `redact-secret-adapters` |

Host integrations live in that separate repository, not here, so a host-SDK
release never re-qualifies this repository's own release matrix
(`decision-graduate-adapters-to-a-separate-repository`). MCP is deliberately
excluded from that repository: `examples/mcp-redact/` wraps the incremental
sanitizer, a stateful surface materially wider than the four-item core
contract (`initialize()`, `scanAndRedact()`'s result shape, `finding.action`,
`findings` as an array) that repository's adapters depend on, and it is not
protected by any declared host version range. It stays an example in this
repository.

Detailed workspace dependency, lint, unsafe-code, MSRV, public-API,
package-content, and registry-name policies live in
[docs/rust-workspace.md](./docs/rust-workspace.md). The CPython distribution's
identity, abi3 contract, wheel matrix, and artifact qualification live in
[docs/python-packaging.md](./docs/python-packaging.md).

## Canonical processing pipeline

```text
UTF-8 input
    |
    v
Invisible-character removal into a scan copy
    |
    v
Built-in Rust detector registry
    |
    v
Candidate validation and normalization
    |
    v
Deterministic priority and overlap resolution
    |
    v
Detected findings with stable IDs and source ranges
    |
    v
Policy evaluation over safe metadata
    |
    v
One-pass redaction
    |
    v
Sanitized text + findings without matched values
```

The core removes zero-rendering and format code points
(`Default_Ignorable_Code_Point ∪ Cf`, derived from a pinned UCD version) into
a scan copy before detection, and translates every reported range back into
the original input. It does not case-fold, apply NFKC, decode, or unescape;
none of those change source coordinates in a way this step's range
translation covers, and each remains a deliberate exclusion (see below). See
[Normalize invisible characters before
detection](./docs/decisions/2026-09-19-normalize-invisible-characters-before-detection.md)
for the derived set, its v1 exclusions, the span translation rule, and its
incremental-sanitization consequence, and [Defer encoded-input decoding out
of scope, with
reasoning](./docs/decisions/2026-09-20-defer-encoded-input-decoding.md) for
why base64/percent/backslash decoding specifically stays out of scope.
Detectors are unchanged and inspect the scan copy; they cannot tell
normalization occurred.

Candidate validation rejects malformed, empty, out-of-bounds, or invalid UTF-8
boundary ranges. It runs against the scan copy the candidate was detected in;
the range is then translated into the original input and re-checked there, so
ranking, overlap resolution, finding numbering, and redaction operate on
original coordinates only. Candidates are then ranked by resolved-action
severity, specificity, confidence, span width, detector registration order,
and detector emission order. Overlap resolution selects the pairwise-disjoint
subset of candidates that maximizes total evidence weight — the classical
`O(n log n)` weighted-interval-scheduling dynamic program, not a greedy walk
— so two or more mutually disjoint candidates that an overlapping single
candidate would have discarded can now be kept together when their combined
weight is higher
(`decision-select-optimal-disjoint-candidates-by-total-evidence-weight`).
Each candidate's weight reuses exactly the same ranking keys above, summed
across a selection and compared in the same dominance order; resolved-action
severity, specificity, and confidence are scaled so that no combination of
weaker candidates can outweigh one stronger one, preserving today's "never
displace a stricter one" rule for any single overlap while still letting
several candidates that tie on every stronger key out-total one candidate
that does not. Final findings are ordered by their original-input position
and assigned stable one-based IDs.

Specific provider or structural evidence outranks broad contextual evidence.
This favors precision and bounded redaction. The tradeoff is explicit: strict
prefixes, length bounds, lexical grammars, and supported-format allowlists can
miss truncated, new, malformed, or unsupported credential variants. Entropy is
only a supporting signal and never sufficient by itself for aggressive
classification.

Resolved-action severity is checked first and overrides that specificity
ordering: a candidate that would resolve to a weaker action (by the crate's
fixed default classification, `Block > Redact > Warn > Allow`) can never
displace an overlapping candidate that would resolve to a stricter one, even
when the displaced candidate has higher specificity
(`decision-resolve-overlap-precedence-by-resolved-action-severity`). A
handful of `Provider`-specificity types (`twilio_auth_token`,
`twilio_api_key_secret`, `datadog_api_key`, `datadog_application_key`,
`new_relic_license_key`) are deliberately confidence-gated rather than
always-redact, each per its own documented `decision-freeze-*` grammar
record; this key is what keeps that deliberate choice from silently
weakening overlap resolution when one of them overlaps a lower-specificity
candidate that would redact.

## Detection and policy separation

Detection answers what a range appears to be. Policy independently chooses one
of `redact`, `block`, `warn`, or `allow` from immutable finding metadata.
Policy callbacks never receive the input or matched value.

Overlap resolution's resolved-action severity key (above) consults this same
default classification directly, on a candidate's already-known type and
confidence — never the caller's active policy. `run_detector_pipeline` runs
before a `Policy` is chosen and returns before one is ever invoked, and a
policy's context (finding index, whole-session finding count) does not exist
until overlap resolution has already finished. So which candidate wins an
overlap is identical under every policy for the same input; a custom, stricter,
or weaker consumer policy changes only the enforcement action applied to the
winning candidate, never which candidate is selected.

The default policy blocks private-key material, redacts known provider,
authorization, connection, and other high-confidence credentials, and warns on
other medium- or low-confidence findings. A consumer may enforce a stricter
server policy without changing detector behavior.

The redactor replaces `redact` and `block` ranges in one ordered pass. `warn`
and `allow` ranges remain unchanged. Default placeholders are stable,
non-recoverable labels such as `<SECRET_1>`. A custom formatter receives safe
metadata and a placeholder index only. The core rejects empty, oversized, or
unsafe placeholders with fixed, input-free errors.

Findings supplied directly to a redaction API are trusted caller assertions.
The core validates their metadata, bounds, ordering, overlap, and placeholder
safety, but does not rerun detection or authenticate the classification.

## Runtime surfaces and range units

The Rust core uses UTF-8 byte offsets. Each binding converts ranges without
changing the selected span:

| Surface | Public range unit | Runtime contract |
| --- | --- | --- |
| Rust crate | UTF-8 bytes | Calls the core directly |
| Node.js | UTF-16 code units | Loads the N-API addon |
| Browser JavaScript | UTF-16 code units | Loads the WebAssembly module |
| Python | Unicode code points | Loads the CPython abi3 extension |
| CLI | UTF-8 bytes internally | Presents host input/output and exit behavior |

The JavaScript package exposes one API across Node.js and browsers. Consumers
call `await initialize()` before synchronous scan, redaction, incremental, or
adapter operations. Node initialization may be a fast no-op, but it remains in
the shared contract so application code is runtime-independent and loading
failures are observable.

Node-only and browser-only loading code stays behind package export boundaries.
The browser graph must not resolve Node built-ins, and Node consumers are not
forced through browser-oriented WebAssembly glue.

Python uses PyO3 and maturin. Supported wheels target CPython 3.10+ through the
abi3 contract on qualified manylinux, musllinux, macOS, and Windows targets in
both x64 and arm64; source installs require Rust when no wheel applies. Every
wheel is built and smoke-tested on the architecture it targets, and installed
with no index, no dependency, and no source fallback, so a passing install is
itself the evidence that no Rust toolchain was needed. Rust consumers use the library crate
directly. The CLI is a host adapter over the same core, never another detector.

## Incremental and streaming behavior

Incremental sanitization is part of the Rust core. Independently scanning chunks
is unsafe because a credential may cross any chunk boundary.

An incremental session:

- requires explicit total-input, retained-plaintext, token, and multiline
  limits;
- retains every still-open lexical construct until it is safe to emit, reaches
  a closing boundary, or fails at a declared limit;
- evaluates policy exactly once after a finding becomes final;
- preserves absolute ranges, deterministic ordering, IDs, actions, and
  placeholder numbering; and
- drops retained plaintext on abort, lifecycle misuse, callback failure, or
  limit failure without attaching it to an error.

For accepted input within the declared limits, concatenated incremental output
and findings must equal a whole-input scan over the same logical string,
regardless of chunk partitioning.

The Node artifact and the browser (WebAssembly) artifact both build a real
session, wrapping the same core `IncrementalSanitizer` the Python binding
does. Rust, Python, CLI standard input, and both JavaScript artifacts expose
working incremental sanitization.

Byte-stream adapters own one fatal, stateful UTF-8 decoder so a multibyte scalar
may cross chunks without becoming a detection boundary. Node adapters integrate
with `Transform`; browser adapters integrate with `TransformStream`. Bindings
handle host backpressure, cancellation, destruction, and decoding, while the
Rust core owns scan semantics and retained-plaintext safety.

## Command-line host behavior

The CLI is a host adapter, never another detector. It owns process arguments,
standard streams, files, and exit codes; the core owns every detection, policy,
and redaction decision, so the CLI and the bindings agree on the same input.

Two modes:

- **check** (the default) scans standard input, or every path given, and
  reports safe file identity and finding metadata. Reports carry a source
  identity, finding id, type, detector, confidence, action, and UTF-8 byte
  range. They never carry matched plaintext, in either the line format or the
  JSON format, and no renderer has the input available to resolve a range.
- **redact** (`--redact`) sanitizes standard input, or exactly one path, and
  writes the result to standard output. The input is never modified in place
  and no path is opened for writing.

Check exit codes are the enforcement contract a pre-commit hook or CI job
branches on: `0` when nothing was found, `1` when anything was, and `2` for a
usage, decoding, or processing failure. A failure outranks a finding, so a run
that could not read or decode part of its input never reports success. Input
that is not valid UTF-8 fails closed rather than being scanned in part.
Redaction reports `0` or `2` only, because a finding is its purpose rather than
its failure; enforcement on a finding belongs to check mode.

Standard input uses the incremental session described above, under explicit
limits the CLI declares and `--help` prints; a path is read whole under the same
total-input bound. Both paths are the canonical core. The session's construct
limits bound the streamed path alone, and the core applies the token limit to
every unresolved logical line, so those limits are sized for the long lines a
pipeline carries rather than for credential length — otherwise the two paths
would disagree about ordinary input. Redaction emits each closed unit as it
streams, so a failure part way through leaves a sanitized but incomplete prefix
on standard output; the exit code, not the output's presence, is the signal.
Every CLI failure —
a partial read, a decoding failure, a limit failure, a closed downstream pipe,
or an abort — leaves the session holding no retained plaintext, and every
diagnostic uses a fixed code and an input-free message on the same terms as
[Error and telemetry constraints](#error-and-telemetry-constraints). A rejected
command line names the rule it broke, never the argument text that broke it.

## Cross-language conformance

The top-level [`conformance/`](./conformance/README.md) corpus is the single
executable behavioral contract. Canonical fixture ranges use UTF-8 byte offsets.
Binding runners convert them to native range units and verify that the converted
span has the same meaning.

The corpus covers:

- positive, negative, malformed, contextual, and regression cases;
- detector metadata and exclusions;
- overlap precedence, policy, and redaction;
- Unicode boundaries and offset conversion;
- incremental partition equivalence and adversarial limits; and
- fixed, input-free diagnostics.

Fixtures contain only unmistakably synthetic or revoked inputs, and expected
metadata never copies a matched value. Generated grammar mutations are
deterministic and record their provenance. A schema change is a cross-language
contract change.

Release qualification requires the Rust core and every supported surface to run
the applicable shared contract in one repository CI graph. Binding-local smoke,
lifecycle, callback, packaging, and host-integration tests supplement the shared
corpus; they do not replace or fork it.

## Cross-language evaluation

The top-level [`assessment/`](./assessment/README.md) directory defines the
cross-language evaluation protocol
(`decision-define-cross-language-evaluation-protocol`): a synthetic assessment
corpus, named workload profiles, and a common result contract every surface
reports through. It is distinct from `conformance/` and is never a release
gate — it measures accuracy and performance, not pass/fail behavioral
conformance.

The protocol covers:

- reviewed accuracy fixtures across logs, code, chat, and negative text,
  including Unicode and astral-boundary cases, each with UTF-8 byte ranges
  and a policy-aware outcome;
- workload profiles that separate accuracy measurement (small, whole-input,
  never chunked) from scale measurement (larger, with a declared chunk
  profile and target finding density), each reproduced deterministically
  from its own fields rather than committed as generated data; and
- a common result contract covering accuracy, initialization, processing,
  throughput, repetition, and memory metrics, with full reproducibility
  provenance (commit, artifact identity, corpus version and hash, OS, CPU,
  runtime, and exact command).

The five per-surface runners are implemented under `scripts/assessment-*.mjs`
and `crates/secret-scan-core/examples/assessment_adapter.rs`; they execute
accuracy and performance profiles, emit conforming results, and can be
aggregated by `npm run assessment:all`. See
[assessment/README.md](./assessment/README.md) for the runner boundaries,
committed evidence, and why assessment remains non-gating readiness
evidence rather than release authorization.

## Public API and extension boundary

Every public surface returns sanitized text and finding metadata equivalent to:

```text
id, type, detector, confidence, action, start, end
```

It never returns a matched value. Callers may use offsets against plaintext only
while that plaintext remains inside their own trusted process boundary.

The first stable Rust-core extension surface supports custom policy and
placeholder formatter callbacks. These callbacks receive normalized safe
metadata. Custom detector callbacks across bindings are intentionally excluded
because they would expose plaintext across the FFI boundary and could restore divergent
detector behavior. The retired TypeScript oracle's custom-detector and
registry APIs were legacy migration surfaces, not part of the accepted first
stable cross-language contract. Rust consumers retain the native `Detector`
traits and `DetectorRegistry` listed in the core public API; that native
extension is not a JavaScript or Python callback surface.

Excluding a *callback* is not the same as excluding all extension:
`decision-define-declarative-detector-ruleset-contract` fixes the contract
for a caller-supplied **declarative ruleset** — data the core parses and
matches itself through the existing `pattern.rs` engine, never host code
run per candidate — as the accepted path for JavaScript, Python, and the
CLI. See that decision for the matching vocabulary, cost bounds, ordering
cap, and implementation status.

Extensions are trusted in-process code, not a sandbox. Fixed library errors can
sanitize an exception crossing a callback boundary, but cannot prevent trusted
application code from capturing plaintext through closures or global state.

## Detector profiles

The built-in detectors are split into two internal packs. `common` holds the
structural and contextual detectors (a PEM/OpenSSH private key, an RFC 7519
JWT, an `otpauth://` URI, a credential-bearing connection URI, an HTTP
`Bearer` header, and a contextual assignment), and `provider` holds every
issuer-specific one. Two profiles are built from them: `full` (every
built-in, the default and compatibility baseline on every surface) and
`common` (an opt-in, smaller profile for preventive browser and small-process
use). A smaller profile gets its size from link-time reachability of its own
registry constructor, not from Cargo features on the core. Each profile keeps
the canonical order as a subsequence, and no detector id behaves differently
between profiles. Python and the CLI stay `full` only. The contract is
accepted in
[Define the detector profile and pack contract](./docs/decisions/2026-09-18-define-detector-profile-and-pack-contract.md).

**Entry point per surface.**

- **Rust core.** `DetectorRegistry::with_common_built_in` and
  `IncrementalSanitizer::with_common_built_in` build the `common` profile
  alongside the unchanged `full` constructors (`with_built_in`), both
  reporting their identity through `profile()`. A profile constructor rejects
  a custom detector that reuses any `full` built-in id, including a
  `provider` id `common` does not itself register.
  `DetectorRegistry::register` applies no profile's reserved-id rule, so
  extending a registry through it clears `profile()` to `None`.
- **WebAssembly (`bindings/wasm`).** One default-on Cargo feature, `full`.
  The default build (`npm run wasm:build`) links the `full` registry
  constructors; `npm run wasm:build:common` builds
  `--no-default-features`, linking only the `common` ones. Each artifact
  reports its profile through its own `profile()` export. Measured savings
  and build evidence are in
  [the #381 record](./docs/audits/evidence/381/README.md).
- **Node addon (`bindings/node`).** One compiled addon serves both
  profiles: it exports `profile()` plus a `common` counterpart to every
  registry-backed export (`initializeCommon`/`scanCommon`/
  `scanAndRedactCommon`/`createIncrementalSanitizerCommon`/`profileCommon`).
  `redact()` is unchanged and shared — it never touches the registry. There
  is no second native binary.
- **`@redact-secret/core`.** The root export stays `full`; a `./common`
  subpath mirrors its full public API and reports `PROFILE` as `"common"`
  (the root reports `"full"`). `initialize()` on either entry point rejects
  with `INITIALIZATION_FAILED` if the artifact it loaded reports a different
  profile than the entry point that loaded it — the same detail-free
  rejection an unusable or version-mismatched artifact already gets.
- **`@redact-secret/wasm`.** The published package carries two built
  artifacts under one identity: the unchanged root (`full`) glue and
  `.wasm`, and a `common` subpath shipping the `common` build's own glue and
  `.wasm` beside them.

**Stream subpaths.** `@redact-secret/core/web-stream` and `/node-stream`'s
convenience `createWebStreamSanitizer`/`createNodeStreamSanitizer` always
open a session against `full`; unchanged, since they are the pre-existing
`full` entry points. `@redact-secret/core/common/web-stream` and
`/common/node-stream` are the `common` counterparts: same factories, same
`WebStreamSanitizer`/`NodeStreamSanitizer` classes, opened against `common`
instead. Resolving a `common` subpath from a browser bundle never reaches
`full`'s runtime module or the root `@redact-secret/wasm` artifact specifier
(issue #416). The classes themselves are also profile-agnostic — they wrap
whichever session they are given — so a consumer can still construct one
directly with a session from `@redact-secret/core/common`'s own
`createIncrementalSanitizer`.

**Mismatch check.** CI builds, qualifies, and packages both WASM artifacts
and both Node profiles on every run, and the release workflow instantiates
the downloaded root `@redact-secret/wasm` artifact and asks it — rather than
trusting the download's artifact name — that `profile() === "full"` before
publishing, refusing to publish a `common` or otherwise non-`full` build
under the `full`/default package identity.

Evidence and the named-pack recommendation are in
[the #382 record](./docs/audits/evidence/382/README.md); user-facing usage is
in the [detection reference](./docs/reference/detection.md#detector-profiles),
[API concepts](./docs/reference/api-contract.md#detector-profiles), and the
[JavaScript](./docs/guides/javascript.md#detector-profiles) and
[Rust](./docs/guides/rust.md#detector-profiles) guides. Publishing a released
version with these exports still requires the explicit release approval
`AGENTS.md` describes.

## Error and telemetry constraints

Public errors use stable codes and fixed, input-free messages. Binding layers
map core failures into idiomatic host exceptions without attaching the original
input, matched substring, callback exception, or secret-bearing cause.

The core and bindings emit no telemetry. Applications may record safe aggregate
events such as a finding type and count, but never plaintext values or raw input
fragments.

## Build and dependency constraints

The Rust core may use `std` and only explicitly allowlisted dependencies. Its
normal and build dependency graph excludes runtime networking, filesystem and
environment access, telemetry, secret storage, and UI behavior, and its sources
name none of those facilities either. It declares no Cargo features, no
optional or target-specific dependencies, and nothing binding-specific, so
every dependent gets the one shape the test suite exercises. Unsafe code is
forbidden in the core and CLI. Any binding-local unsafe code must be scoped to a
real FFI boundary and documented according to workspace policy.

The core's published surface is pinned by name in
`[workspace.metadata.redact-secret] core-public-api`, and the files its package
may carry are pinned by `core-package-globs`; `npm run rust:check` fails when
either drifts. The built-in detector registry and the incremental retention
tuning are private, so both can change without breaking a dependent.

Core algorithms must be deterministic, avoid catastrophic regular-expression
behavior, avoid unnecessary full-input copies, resolve overlaps in
`O(n log n)` time after prioritization, and reconstruct redacted output in one
pass after findings are finalized. Whole-input APIs default to a declared
`WholeInputLimits` bound — 64 MiB of input, 50,000 findings — and fail closed
with a fixed error rather than truncating when either is exceeded; a caller
may widen the bound explicitly (`scan_with_limits`/`redact_with_limits`/
`scan_and_redact_with_limits` in Rust, an equivalent `limits` option in every
binding) (`decision-bound-whole-input-operations-by-default`). This is a
library-level default, not a substitute for host-side bounding: authoritative
hosts must still enforce transport, decoded input, sanitized output,
concurrency, and memory limits.

## Versioning, qualification, and release

The Rust crate, npm package, Python package, and CLI are one product with one
SemVer version and one `v{version}` Git tag. Binding-specific fixes still advance
the shared version and qualify every required artifact from the same commit.

A release candidate must pass the shared conformance contract plus all
surface-specific build, test, type, package-content, platform, and smoke checks
without publishing. The release process records the source commit, conformance
revision, version, required artifacts, and observed registry state. Publication
is not transactional; only an explicitly authorized reconcile operation may
complete a partially published matching version without rebuilding artifacts
that already succeeded.

The `Artifact qualification` workflow is that candidate run. From one revision it
calls the Rust and CPython workflows and additionally builds the N-API addon,
the browser WebAssembly artifact, and the CLI binary for every declared target,
smoke-testing each on the architecture it targets, exercising the browser
artifact in Chromium, Firefox, and WebKit, and recording an artifact inventory
— source commit, product version, conformance-corpus digests, per-artifact
SHA-256, and the file-by-file contents of each publishable package — that
states `"published": false`. Packed JavaScript candidates are also installed
outside the checkout and their public incremental and stream APIs are exercised
on every declared Node.js major and browser engine; each row records its runtime,
commands, results, source revision, and package SHA-256 identities. The supported
target, engine, and Node.js lists
live once in `[workspace.metadata.redact-secret]`, and a declaration check binds
every manifest, script, and workflow matrix to them so a supported platform
cannot be added or dropped in one file alone. That check also enforces
least-privilege workflow permissions and commit-pinned third-party actions.
See [docs/qualification.md](./docs/qualification.md), which also records the
one remaining deliberate asymmetry: the CLI still ships no musl variant,
while npm now ships musl N-API addons alongside glibc
(`decision-publish-musl-node-addons`). A Node host with no usable addon at
all falls back to the WebAssembly artifact browsers use
(`decision-add-node-wasm-fallback`).

Release readiness does not authorize selecting a version, tagging, publishing,
deploying, or archiving another repository. Those actions require the separate
release approval defined by repository governance.

## Deliberate exclusions

The first stable architecture does not include:

- a Go binding or stable C ABI;
- a pure-Python, TypeScript, or Go detector fallback;
- runtime provider lookups or network-assisted validation;
- credential storage, credential management, or secret rotation;
- UI components, server-framework integration, or model/tool invocation; or
- PII detection, prompt-injection analysis, organization data policy, or other
  broader context-safety functions.

Those capabilities may wrap or follow Redact Secret, but they must not weaken
the deterministic core or create another authoritative detector implementation.

The invisible-character normalization step above deliberately excludes, each
tracked by its own future issue:

- confusable and homoglyph skeleton matching (UTS #39);
- whitespace folding (`U+00A0`, `U+2000..U+200A`, `U+3000`);
- decoding the Unicode Tags block back to ASCII (`U+E0020..E007F`), as
  opposed to removing it; and
- base64, percent-encoding, or backslash-escape decoding.

See [Normalize invisible characters before
detection](./docs/decisions/2026-09-19-normalize-invisible-characters-before-detection.md)
for why each is out of scope for v1.

## Decision sources

The accepted records governing this architecture are:

- [Adopt a Rust-core monorepo](./docs/decisions/2026-09-09-adopt-rust-core-monorepo.md)
- [Define runtime bindings](./docs/decisions/2026-09-09-define-runtime-bindings.md)
- [Govern cross-language conformance](./docs/decisions/2026-09-09-govern-cross-language-conformance.md)
- [Release bindings in lockstep](./docs/decisions/2026-09-09-release-bindings-in-lockstep.md)
- [Ship the first release's full artifact set](./docs/decisions/2026-09-10-ship-first-release-artifact-set.md)
- [Define the cross-language evaluation protocol](./docs/decisions/2026-09-12-define-cross-language-evaluation-protocol.md)
- [Measure JavaScript performance externally](./docs/decisions/2026-09-12-measure-javascript-performance-externally.md)
- [Define the detector profile and pack contract](./docs/decisions/2026-09-18-define-detector-profile-and-pack-contract.md)
- [Normalize invisible characters before detection](./docs/decisions/2026-09-19-normalize-invisible-characters-before-detection.md)
- [Graduate logging and tracing adapters to a separate repository](./docs/decisions/2026-09-19-graduate-adapters-to-a-separate-repository.md)
