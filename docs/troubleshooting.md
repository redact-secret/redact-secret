# Troubleshooting

[Documentation home](README.md)

## Install and setup

Check [supported runtimes](getting-started.md#supported-runtimes) first: an
unsupported runtime explains most setup failures.

| Symptom | What to check |
| --- | --- |
| `cargo install redact-secret-cli` fails with ``could not find `redact-secret-cli` in registry `crates-io` with version `*` `` | Every release is a beta, and Cargo does not pick a prerelease unless you name it: add `--version <version>`, as in the [quickstart](quickstart.md#command-line) |
| `redact-secret: command not found` after `cargo install` | Cargo installs into `~/.cargo/bin` (or `$CARGO_HOME/bin`); put it on `PATH` |
| `npm install @redact-secret/core` gives an older beta than the newest | A bare install resolves the `latest` tag, which a maintainer moves by hand after publishing. Use `@redact-secret/core@beta` or an exact version |
| pip reports no matching distribution with `--only-binary=:all:` | No wheel exists for this platform or Python version; see the [wheel matrix](python-packaging.md). Without that flag pip would start a source build, which needs a Rust toolchain |
| `cargo install` or `cargo build` fails to compile | The workspace needs Rust 1.88 or newer (`rustc --version`) |
| Which version am I running? | JavaScript: `VERSION` exported by `@redact-secret/core`. Python: `redact_secret.VERSION`. Rust: `redact_secret::VERSION`. CLI: `redact-secret --version`. Quote it when you [report a problem](guides/reporting-detection-issues.md) |

## Errors

| Symptom / code | What to check |
| --- | --- |
| `NOT_INITIALIZED` in JavaScript | Await `initialize()` before synchronous work |
| `INITIALIZATION_FAILED` on Node | Supported Node major and target, installed optional addon, matching package versions, and an addon whose profile matches the entry point (`@redact-secret/core` or `/common`); a missing or unloadable addon falls back to `@redact-secret/wasm` instead, so check that it is installed and matches the package version too |
| `ImportError: redact-secret could not load its native extension` in Python | No wheel for this platform or Python build, or an incomplete install; reinstall with `--only-binary=:all:` on a platform in the [wheel matrix](python-packaging.md) |
| Node runs on WebAssembly, not the addon | `artifact()` returns `"wasm"` after `initialize()`: the host has no matching `@redact-secret/node-<platform>` package, its optional-dependency install failed, or the addon could not load |
| `INITIALIZATION_FAILED` in browser | Browser import conditions, Wasm asset URL, HTTP response, MIME type, and an artifact whose version and profile match the entry point (`@redact-secret/core` or `/common`) |
| `INITIALIZATION_FAILED` in browser only when `pii` is set | The PII build is a second, lazily loaded asset (`redact_secret_wasm_pii_bg.wasm`, or `redact_secret_wasm_common_pii_bg.wasm` for `/common`) fetched only when the first `initialize()` passes a non-empty `pii` selection. Confirm the bundler emitted it, it is served with `application/wasm`, and its version and profile match the entry point; a page without `pii` never requests it. See [browser loading](guides/javascript.md#browser-loading) |
| `PII_SELECTOR_INVALID` | A `pii` selector is malformed (for example uppercase `PII`); use `pii`, `pii:global`, `pii:us` or `pii:family:<jurisdiction>:<family>` in lowercase |
| `PII_SELECTOR_UNSUPPORTED` | The selector is well formed but its jurisdiction or family is not supported (for example `pii:kr`) |
| `PII_SELECTOR_UNAVAILABLE` | The loaded artifact has no PII runtime or the family is unavailable. Through `@redact-secret/core` this should not occur for a supported selector; if you import `@redact-secret/wasm` directly, use `@redact-secret/wasm/pii` or `@redact-secret/wasm/common/pii` |
| `UNPAIRED_SURROGATE` | JavaScript text contains an invalid standalone UTF-16 surrogate; correct input handling before scanning |
| `INVALID_FINDINGS` | Findings belong to the same original text, have valid native-unit bounds, and do not overlap |
| `INVALID_PLACEHOLDER` | Formatter output is non-empty, no more than 256 UTF-8 bytes, and does not reproduce a replaced value |
| `POLICY_FAILURE` / `PLACEHOLDER_FAILURE` | Trusted callback raised; use synthetic input to debug the callback |
| `INVALID_POLICY_ACTION` | Policy must return `redact`, `block`, `warn`, or `allow` |
| `INVALID_LIMITS` | Positive explicit session limits and sufficient retained buffer for an incremental session; a positive `maxInputBytes`/`maxFindings` for whole-input `scan`/`redact`/`scanAndRedact` |
| `INPUT_LIMIT_EXCEEDED` | An incremental session's total accepted input, or a whole-input `scan`/`redact`/`scanAndRedact` call's input, exceeded its byte limit (64 MiB by default for whole-input) |
| `FINDING_LIMIT_EXCEEDED` | A whole-input `scan`/`redact`/`scanAndRedact` call's accepted finding count exceeded its limit (50,000 by default); raise it via the `limits` option or chunk the input through the incremental API |
| `BUFFER_LIMIT_EXCEEDED`, `TOKEN_LIMIT_EXCEEDED`, `MULTILINE_LIMIT_EXCEEDED` | Incremental session input exceeded a declared bound; long ordinary lines also count |
| `INVALID_STATE` | The session already finalized, aborted, or failed; create a new session for new input |
| CLI exit 2 | Read the fixed stderr diagnostic; output may be incomplete |

Initialization errors intentionally hide underlying loader diagnostics. Inspect
installation and asset availability without attaching input or raw callback
exceptions to logs. Retry initialization only after correcting its cause.

## Unexpected detection or output

`block` does not throw automatically: the redactor replaces its span and your
host decides whether to reject the operation. `warn` and `allow` preserve text.
Offsets index the original input, not the sanitized result. Different runtimes
use [different coordinate units](reference/api-contract.md).

A missed credential may be outside the supported grammar. File and stdin CLI
paths have different construct limits. See [coverage](reference/detection.md)
and [streaming](guides/streaming.md) before treating these as inconsistencies.

Report a minimal synthetic or revoked reproducer with runtime/version and safe
expected metadata, following the [reporting guide](guides/reporting-detection-issues.md).
Use the [private security process](../SECURITY.md) for vulnerabilities. Never
paste an active secret into a public issue.
