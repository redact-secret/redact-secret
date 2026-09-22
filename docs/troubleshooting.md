# Troubleshooting

[Documentation home](README.md)

| Symptom / code | What to check |
| --- | --- |
| `NOT_INITIALIZED` in JavaScript | Await `initialize()` before synchronous work |
| `INITIALIZATION_FAILED` on Node | Supported Node major and target, installed optional addon, matching package versions, and an addon whose profile matches the entry point (`@redact-secret/core` or `/common`); a missing or unloadable addon falls back to `@redact-secret/wasm` instead, so check that it is installed and matches the package version too |
| `ImportError: redact-secret could not load its native extension` in Python | No wheel for this platform or Python build, or an incomplete install; reinstall with `--only-binary=:all:` on a platform in the [wheel matrix](python-packaging.md) |
| Node runs on WebAssembly, not the addon | `artifact()` returns `"wasm"` after `initialize()`: the host has no matching `@redact-secret/node-<platform>` package, its optional-dependency install failed, or the addon could not load |
| `INITIALIZATION_FAILED` in browser | Browser import conditions, Wasm asset URL, HTTP response, MIME type, and an artifact whose version and profile match the entry point (`@redact-secret/core` or `/common`) |
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
expected metadata. Use the [private security process](../SECURITY.md) for
vulnerabilities. Never paste an active secret into a public issue.
