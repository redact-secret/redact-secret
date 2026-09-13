# Public contract and cross-runtime conformance review

[Documentation home](../README.md) · [Audit archive](README.md)

- Issue: [#199](https://github.com/redact-secret/redact-secret/issues/199).
- Reviewed on: 2026-09-13, macOS arm64.
- Reviewed implementation revision: `5607de8973ddb83f9b61f840f67eb8534d5cea0d`.
- Machine-readable evidence: [verification summary](evidence/199/verification-summary.json).
- Status: **PUBLIC CONTRACT VERIFIED; FULL RC QUALIFICATION PENDING.**

This review establishes the version-independent public behavior contract and
checks every current product surface against the canonical behavior applicable
to that host. It is release-readiness evidence, not release approval. The
current macOS arm64 artifacts were built from the reviewed revision and tested
directly. The last full platform rehearsal remains evidence only for its older
revision; issue [#203](https://github.com/redact-secret/redact-secret/issues/203)
owns the required same-revision release-candidate matrix.

No matched value, fixture input, or credential-shaped string appears in this
document or its JSON evidence. Detector identifiers, range units, error codes,
file hashes, fixture counts, and artifact identities are safe metadata.

## Contract summary

All bindings delegate built-in detection, overlap resolution, default policy,
redaction, and incremental retention to `crates/secret-scan-core`. Bindings
translate ranges, callbacks, lifecycle, and fixed errors; the CLI additionally
owns process, file, stream, report, and exit-code behavior. No second detector
implementation is part of the supported contract.

| Surface | Whole input | Incremental / stream | Public range unit | Policy / formatter |
| --- | --- | --- | --- | --- |
| Rust crate | `scan`, `redact`, `scan_and_redact` | `IncrementalSanitizer` | UTF-8 bytes into original input | Custom policy and formatter; native custom detector registry |
| Python package | `scan`, `redact`, `scan_and_redact` | String-chunk `IncrementalSanitizer` | Unicode code points into original input | Custom policy and formatter; no custom detector callback |
| Node package | `scan`, `redact`, `scanAndRedact` | Incremental session and byte `Transform` | UTF-16 code units into original input | Custom policy and formatter; no custom detector callback |
| Browser package / Wasm | Same JavaScript root API | Incremental session and byte-to-string `TransformStream` | UTF-16 code units into original input | Custom policy and formatter; no custom detector callback |
| CLI | Check and redact modes | Standard input is incremental; file input is whole | UTF-8 bytes in reports | Built-in policy and formatter only |

The range always addresses the original input, never the sanitized output.
JavaScript's four incremental limit fields retain their `CodeUnits` names for
compatibility but are enforced as UTF-8 byte ceilings by the Rust core. Python
names those limits as bytes. Rust and CLI limits are bytes.

`block` is a policy result, not automatic process termination in the library
APIs. Applications must enforce it before downstream use. CLI check mode exits
`1` for any finding and `2` for a usage, decoding, or processing failure;
redact mode exits `0` after successful sanitization even when a finding's
action is `block`, and `2` on failure.

## Canonical conformance ownership

The committed corpus is the language-neutral contract. Its expectations use
UTF-8 byte offsets and never carry matched text. At the reviewed revision it
contains 399 synchronous fixtures (297 supported and 102 intentionally
unsupported), 16 incremental fixtures, 11 incremental lifecycle scenarios, 6
Unicode conversion fixtures, and 15 incremental/stream error codes.

| Contract area | Canonical evidence | Runtime assertion |
| --- | --- | --- |
| Detector results, exclusions, overlap, confidence, ranges | `synchronous-corpus.json` | Rust, installed Python, real Node addon, real browser Wasm/package, and real CLI artifact all passed every evaluated fixture |
| UTF-8 native ranges | Synchronous and Unicode conversion corpora | Rust and CLI assert byte offsets directly |
| UTF-16 native ranges | Synchronous and Unicode conversion corpora | Node and Wasm convert independently and verify the selected JavaScript slice |
| Python native ranges | Synchronous and Unicode conversion corpora | Installed Python converts independently to code-point offsets |
| Whole-input redaction and policy | Synchronous corpus plus public-API suites | All surfaces assert default actions and redaction; callback surfaces add custom-policy and formatter cases |
| Incremental equivalence | `incremental-corpus.json` | Rust and installed Python run the complete corpus across generated partitions; Node and browser artifact qualification exercise representative cross-boundary and byte-partition cases over the same core session |
| Lifecycle, limits, cleanup, safe failures | Lifecycle and error-code corpora plus binding-local suites | Rust, Python, Node, Wasm, Node `Transform`, Web `TransformStream`, and CLI terminal paths are covered according to their host API |

The last two rows deliberately distinguish semantic ownership from adapter
coverage. The Rust core and Python runner execute the complete canonical
incremental corpus. JavaScript qualification proves that the real Node and Wasm
artifacts open that core session and that host range conversion, decoding,
backpressure, cancellation, abort, callback failure, and cleanup work, but it
does not replay all 16 incremental fixtures through every installed JavaScript
artifact. This is an evidence-depth gap, not an unsupported product behavior;
the full release-candidate artifact inventory remains owned by #203, and
[#224](https://github.com/redact-secret/redact-secret/issues/224) owns the
missing full-corpus JavaScript replay.

## Fixed safe errors

Core errors are a stable code and fixed message without a payload. Python and
both Rust-backed JavaScript bindings map them without attaching the original
input, matched substring, placeholder, callback exception, or secret-bearing
cause. JavaScript adds fixed host errors for initialization, unpaired UTF-16
surrogates, invalid stream chunks, and malformed UTF-8. The CLI uses fixed
failure codes/messages and never gives its report renderer input bytes with
which to resolve a finding range.

The 15-entry `error-codes.json` registry is intentionally scoped to the shared
incremental and stream vocabulary; it is not a claim that initialization,
synchronous argument validation, or CLI host failures have identical codes in
all languages. Binding-local tests own those idiomatic host errors.

Failure handling is fail-closed at the host boundary: an invalid input or
terminal incremental failure cannot continue accepting data, and retained
plaintext is discarded. A streaming CLI redaction failure may already have
written a sanitized prefix; callers must use the nonzero exit code and must not
treat that prefix as complete input.

## Actual-artifact evidence

The following artifacts were built from the reviewed implementation revision,
not mocked or resolved from registry packages:

| Artifact | Host verification |
| --- | --- |
| Node N-API addon | Node 22 on macOS arm64; addon smoke/lifecycle suite, all 399 evaluated synchronous fixtures, package root API, and Node stream adapter passed |
| Browser Wasm and package | Locally built release Wasm; Chromium, Firefox, and WebKit each passed 27 artifact/package checks, including the synchronous corpus and real Web stream behavior |
| Python abi3 wheel | macOS arm64 `cp310-abi3` wheel installed with no index, dependencies, or source fallback; CPython 3.14 smoke and 601 tests passed |
| CLI binary | Release macOS arm64 executable; identity, exit codes, all evaluated synchronous fixtures, and redaction passed |
| Rust crate/workspace | `cargo test` passed 472 tests in 20 suites; `cargo clippy` reported no issues |

Exact artifact and corpus SHA-256 identities are in the verification summary.
Generated build products are ignored local outputs and are not committed.

The [#174 full matrix rehearsal](release-qualification-follow-up.md) passed all
41 jobs and recorded 43 artifact files across the declared Node, browser,
Python, Rust, and CLI matrices at revision
`9f02fc401525381a6b02b5dd514a68df9a4f9531`. It remains valid historical
evidence, but it is not current-revision or release-candidate evidence: the
synchronous corpus hash has changed since that run. No cross-platform result
has been borrowed from it for the current-host table above.

## Supported and unsupported scope

Supported streaming is bounded incremental sanitization in Rust, Python, both
JavaScript artifacts, Node `Transform`, browser `TransformStream`, and CLI
standard input. The CLI file path remains a bounded whole-input operation.
There is no promise that independently scanning arbitrary chunks is safe.

The following scope is intentionally unsupported or excluded from the first
stable contract:

- JavaScript and Python custom detector callbacks; Rust's native detector
  extension remains available in-process.
- A custom detector in an incremental session, because it declares no
  retention bound, and whole-input count-dependent policy in an incremental
  session, because the final finding count is not yet known.
- CLI policy/formatter customization and a Python byte-stream adapter. These
  surfaces expose the host contracts documented above, not every adapter form
  available in another language.
- Node package installation on musl/Alpine. Musl addons are qualified, but npm
  publishes platform packages only for the six declared non-musl targets.
- Runtime provider lookup, network validation, complete DLP coverage, a Go
  binding, a stable C ABI, and pure-language detector fallbacks.
- Unbounded whole-input safety. Authoritative hosts must bound transport,
  decoded input, finding count, sanitized output, concurrency, and memory.

These exclusions do not weaken the server-authority rule: browser scanning is
preventive UX, while server-side scanning remains authoritative.

## Follow-up ownership

The review found no defect in detector, redaction, overlap, range conversion,
policy, formatter, or supported streaming behavior. It did find the JavaScript
incremental evidence-depth gap described above and created one bounded
follow-up. Existing release-readiness issues own the other evidence and
delivery boundaries:

| Issue | Ownership after this review |
| --- | --- |
| [#180](https://github.com/redact-secret/redact-secret/issues/180) | Detection-assurance parent remains open although #185–#191 are closed; its closeout is administrative and #200 consumes its evidence |
| [#200](https://github.com/redact-secret/redact-secret/issues/200) | Publish honest detection reliability, false-positive/false-negative results, and limitations from repeatable RC assessment |
| [#201](https://github.com/redact-secret/redact-secret/issues/201) | Set performance/resource thresholds before evaluating the formal RC |
| [#202](https://github.com/redact-secret/redact-secret/issues/202) | Execute safe integration examples, including host enforcement and failure containment |
| [#203](https://github.com/redact-secret/redact-secret/issues/203) | Produce the full same-revision RC artifact inventory and installed-consumer qualification |
| [#204](https://github.com/redact-secret/redact-secret/issues/204) | Complete public documentation and choose its delivery platform later |
| [#224](https://github.com/redact-secret/redact-secret/issues/224) | Replay every canonical incremental fixture through real installed Node and browser artifacts across their applicable partitions |

No existing issue was closed, edited, or commented on by this review. Issue
#224 is the only GitHub write it performed.

## Verification performed

All commands completed successfully on the reviewed revision:

```bash
npm run ci
cargo test
cargo clippy
npm --prefix bindings/node ci
npm --prefix bindings/node run build
npm run js:build
npm run addon:qualify -- --target aarch64-apple-darwin
npm run wasm:build
npm run browser:qualify
uvx maturin build --release -m bindings/python/Cargo.toml -o dist
python3 scripts/qualify-python-wheel.py --conformance \
  dist/redact_secret-0.1.0b1-cp310-abi3-macosx_11_0_arm64.whl
cargo build --release --locked -p redact-secret-cli
npm run cli:qualify -- --binary target/release/redact-secret
```

After this evidence document was added, `npm run decisions:validate`, the full
repository gates, Markdown link checks, `git diff --check`, and the required
WIP commit checks were run again as recorded in the final handoff.

## Authority boundary

This review did not select or change a version, create an RC branch or tag,
publish a package, deploy, dispatch a workflow, alter repository settings, or
approve a release. Public registry installation is impossible before an
approved publication and remains part of #203's post-publication evidence.
