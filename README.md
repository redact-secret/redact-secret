# Redact Secret

Deterministic secret detection and redaction for runtime data and AI context.

Your application handles text it does not fully control: user input, pasted
configuration, error messages, HTTP bodies, and tool results. Before that text
leaves the request and lands somewhere that keeps or repeats it, pass it
through Redact Secret. It finds supported credential formats and returns the
text with those credentials replaced, plus findings that describe what was
found and where without ever including the secret itself. It runs in your
process. It makes no network calls and sends no telemetry, and the same input
always gives the same result.

## What it is for

Scan text at the runtime boundary, just before it reaches one of these
destinations:

- **Logs**: log messages, structured fields, and error text
  ([logging example](examples/logging-redaction/)).
- **Persistence**: databases, caches, search indexes, and conversation
  history.
- **Telemetry**: traces, spans, and LLM observability records
  ([tracing example](examples/tracing-masking/)).
- **Tool output**: results returned by tools, agents, and MCP servers
  ([MCP example](examples/mcp-redact/)).
- **Model context**: prompts, retrieved documents, and anything else added to
  a model's context window.

One side-effect-free Rust core owns built-in detection, overlap resolution,
policy, redaction, and bounded incremental sanitization. JavaScript (Node.js
and browsers), Python, Rust, and a command-line tool all use that core
instead of reimplementing it.

## Where scanning belongs

> Client-side scanning is preventive UX. Server-side scanning is the
> authoritative enforcement boundary.

Scanning in a browser or desktop client catches a pasted credential before it
leaves the device. That is useful, but clients can be modified or skipped, so
it is never enforcement. The server scans again, independently, before
logging, storage, context construction, or model and tool invocation, and
that server scan is the one your security decisions rely on. Redact Secret
reports a `block` action, but your application is what rejects the request.
See [browser and server boundaries](#browser-and-server-boundaries) and
[policy and safe integration](docs/guides/safe-integration.md).

## What it does not replace

- **It is not a DLP platform.** It finds credentials, not personal data, and
  it has no policy console, quarantine, or hosted service.
- **It does not detect every secret.** Detection is limited to supported
  formats and deliberately favors precision. Truncated, new, or unsupported
  credential formats can be missed, and an empty finding list does not prove
  the text is secret-free.
- **It does not replace repository and history scanners.** Tools that scan Git
  history, pull requests, and registries for leaked credentials (for example
  Gitleaks, TruffleHog, or GitHub secret scanning) do a different job and are
  complementary. Redact Secret works on live data at runtime. Its CLI can
  check files and staged diffs, but it does not walk commit history.
- **It does not verify, rotate, or revoke credentials.** It never contacts a
  provider, so it cannot tell whether a detected credential is active. If a
  secret has leaked, rotate it.

## Supported formats and limitations

Which credential families are supported, and how strong the evidence is for
each, is published in the generated [support matrix](docs/support-matrix.md).
That matrix is built from evaluation evidence, not written by hand. The
[detection and limits reference](docs/reference/detection.md) explains what
can be missed and why. Published versions and their artifacts are listed in
[release status](docs/releases/status.md).

## Install and first example

Public beta packages exist for npm, PyPI, crates.io, and the CLI. The exact
install command for the current published version of each is in
[getting started](docs/getting-started.md#install-a-published-release).
Select a version explicitly rather than relying on an unqualified install.

```ts
import { initialize, scanAndRedact } from "@redact-secret/core";

await initialize();

const result = scanAndRedact("API_KEY=SYNTHETIC_REVOKED_CONTEXT_VALUE");
console.log(result.text);
// API_KEY=<SECRET_1>
```

```python
import redact_secret

result = redact_secret.scan_and_redact("API_KEY=SYNTHETIC_REVOKED_CONTEXT_VALUE")
print(result.text)
# API_KEY=<SECRET_1>
```

```bash
printf '%s\n' 'API_KEY=SYNTHETIC_REVOKED_CONTEXT_VALUE' | redact-secret --redact
# API_KEY=<SECRET_1>
```

Then continue with the [JavaScript](docs/guides/javascript.md),
[Python](docs/guides/python.md), [Rust](docs/guides/rust.md), or
[CLI](docs/guides/cli.md) guide, or the [documentation home](docs/README.md).
To build this checkout instead, see the
[source setup](docs/getting-started.md#build-this-checkout). The executable
behavior contract that every surface passes lives in
[conformance](conformance/README.md).

## Integrations

Pino, Python `logging`, and OpenTelemetry `SpanProcessor` integrations are
being graduated to a separate repository,
[`redact-secret-adapters`](https://github.com/redact-secret/redact-secret-adapters),
as `@redact-secret/adapter-pino`, `@redact-secret/adapter-otel`, and the PyPI
`redact-secret-adapters` distribution; none of those packages is published
yet — see
[`docs/decisions/2026-09-19-graduate-adapters-to-a-separate-repository.md`](./docs/decisions/2026-09-19-graduate-adapters-to-a-separate-repository.md)
for why, including why this repository's own release matrix is unaffected.
Model context (MCP) and LangChain remain application use cases with no
dedicated package: [`examples/mcp-redact/`](examples/mcp-redact/) is a
tested, example-only integration — see its README for its stated support
level — and no LangChain integration exists in this repository at all.

## Architecture at a glance

```text
JavaScript       Python        Rust          CLI
    |               |            |             |
 N-API / wasm     PyO3           |             |
    |               |            |             |
    +---------------+------------+-------------+
                    |
                    v
          deterministic Rust core
                    |
       detect -> resolve -> policy -> redact
                    |
                    v
          safe text + safe metadata

       conformance/ is the shared contract
```

The core performs no runtime network or filesystem access, environment lookup,
telemetry, secret storage, model invocation, or UI work. Bindings translate
host callbacks, errors, and string ranges while preserving the selected spans.

| Surface | Binding | Public range unit |
| --- | --- | --- |
| JavaScript on Node.js | N-API | UTF-16 code units |
| JavaScript in browsers | `wasm-bindgen` WebAssembly | UTF-16 code units |
| Python | PyO3 | Unicode code points |
| Rust | Direct library crate | UTF-8 bytes |
| CLI | Direct core integration | UTF-8 bytes internally |

See [ARCHITECTURE.md](./ARCHITECTURE.md) for processing, trust boundaries,
incremental safety, package ownership, conformance, and release design. See
[docs/rust-workspace.md](./docs/rust-workspace.md) for workspace dependency,
lint, unsafe-code, MSRV, public-API, package-content, and registry-name
policies, and [docs/python-packaging.md](./docs/python-packaging.md) for the
CPython distribution, its abi3 wheel matrix, and how each artifact is
qualified.

## JavaScript quick start

The JavaScript package presents one typed API across Node.js and
modern browsers. Its explicit initialization contract makes native or
WebAssembly loading failures observable without making every scan asynchronous.

On Node.js, `@redact-secret/core` installs a prebuilt N-API addon for
glibc and musl Linux, macOS, and Windows (x64 and arm64 each: eight platform
packages, `engines.node` `20.x || 22.x || 24.x`) as an optional dependency.
On a host with no matching addon at all — an unsupported platform or
architecture, a matching optional dependency that failed to install, or a
corrupt addon — `initialize()` falls back to the same WebAssembly artifact
browsers use instead of failing outright. Call `artifact()` after
`initialize()` to see which one actually loaded: `"addon"` or `"wasm"`. Bun
and Deno get this fallback for free. **Cloudflare Workers is a verified,
supported runtime**: it resolves its own `workerd` package condition to a
loader that instantiates the WebAssembly artifact from a bundler-compiled
`WebAssembly.Module` instead of the generated glue's `import.meta.url`-based
`fetch`, which does not work under a real `workerd` sandbox
(`decision-verify-edge-runtimes`). **Vercel Edge is not yet supported**: it
resolves the plain browser entry point, whose `fetch`-based initialization
fails there for a related but distinct reason, verified against Vercel's own
reference Edge Runtime engine; see
[docs/qualification.md](./docs/qualification.md) for the verified root cause
and why the Cloudflare Workers fix does not carry over. See that document
also for the full target matrix, exactly which failures engage the Node
fallback, and how CI keeps both from drifting.

```ts
import { artifact, initialize, scanAndRedact } from "@redact-secret/core";

await initialize();
console.log(artifact()); // "addon" on a supported host, "wasm" on the fallback
```

All examples use unmistakably synthetic, revoked values. Findings contain
classification, action, and original-input offsets, never the matched plaintext
value. For the [first example](#install-and-first-example) above:

```ts
result.findings[0];
// {
//   id: "finding-1",
//   type: "contextual_secret",
//   detector: "generic-token",
//   confidence: "high",
//   action: "redact",
//   start: 8,
//   end: 39
// }
```

JavaScript offsets are half-open UTF-16 code-unit ranges into the original
input, even when the sanitized output has a different length.

## Core operations

Every supported language surface provides equivalent whole-input behavior:

- `scan` runs the built-in Rust detectors, resolves overlaps, evaluates policy,
  and returns immutable findings;
- `redact` validates caller-supplied findings and replaces `redact` and `block`
  ranges while leaving `warn` and `allow` ranges unchanged; and
- `scanAndRedact` performs both operations once and returns sanitized text with
  the corresponding findings.

Default placeholders are `<SECRET_1>`, `<SECRET_2>`, and so on. A custom
formatter receives only safe finding metadata and a one-based placeholder
index. Empty, oversized, or unsafe placeholders fail with a fixed, input-free
error.

Detection and enforcement remain separate. A policy receives immutable
metadata without plaintext and chooses `redact`, `block`, `warn`, or `allow`.
The default policy is:

| Detection | Default action |
| --- | --- |
| Private-key material | `block` |
| Known provider, bearer/JWT, authorization, or connection credential | `redact` |
| Other high-confidence secret | `redact` |
| Other medium- or low-confidence secret | `warn` |

The first stable cross-language extension surface includes custom policy and
placeholder formatter callbacks. Custom detector callbacks are excluded: all
built-in detectors run in Rust, and bindings must not create another detector
implementation. A caller with an internal credential format is not left
without a path: `decision-define-declarative-detector-ruleset-contract`
fixes the contract for a caller-supplied **declarative ruleset** — data the
core parses and matches itself, never a callback — and issues #495 and #484
implement it for the Rust core, JavaScript (Node and browser WebAssembly),
Python, and the CLI. See [Declarative rulesets](#declarative-rulesets) below.

## Declarative rulesets

An organization with an internal credential format — an in-house service
token, a partner API key, a legacy prefix — can declare it without writing
code. A ruleset is UTF-8 text, at most 64 KiB, matched by the same
linear-time, ReDoS-free engine every built-in detector already runs through
(`crates/secret-scan-core/src/detectors/pattern.rs`): no regex, no new
matching vocabulary.

```text
ruleset-revision: 1
detector: acme-internal-token
specificity: contextual
prefix: "ACME_"
alphabet: alnum-dash
run: at-least 20
validator: none
```

The first line is always `ruleset-revision: 1`. Every following `detector:
<id>` line starts a block of exactly five fields:

| Field | Values |
| --- | --- |
| `specificity` | `entropy` or `contextual` only — `structural`, `provider`, and `private-key` are reserved to built-in detectors and rejected |
| `prefix` | a double-quoted literal, 3–64 bytes, matched byte-exact and case-sensitive (no escape sequences) |
| `alphabet` | one of `alnum`, `alnum-dash`, `alnum-dash-dot`, `upper-alnum`, `digit`, `lower-hex`, `base64-body` |
| `run` | `exact <n>` or `at-least <n>`, `1 ≤ n ≤ 4096` |
| `validator` | `none`, or `trailing-lower-hex` (the matched run's final `n` alphabet bytes — `n` from the block's own `run` count — must be lowercase hex) |

A ruleset detector's matching semantics are exactly a built-in prefixed
detector's:

- **Case-sensitive, byte-exact prefix matching.** No case folding, no NFKC,
  no decoding, no unescaping.
- **Matching runs on the normalized scan copy; reported ranges use original
  input coordinates.** Every detector matches after invisible and format
  code points are stripped
  (`decision-normalize-invisible-characters-before-detection`); every
  reported range is translated back to the caller's original text before it
  becomes a public result. A ruleset detector is not a special case.
- **Boundary behavior is fixed, not caller-configurable.** A match that is a
  truncated slice of a longer run of the same alphabet is rejected, not
  truncated — a ruleset has no way to loosen or tighten this.

Every ruleset candidate carries `Confidence::Medium`, fixed regardless of the
ruleset's own content, and registers after every built-in detector. Combined
with the specificity restriction above, a ruleset can add detections but can
never silently outrank a built-in's resolved finding. A caller with a loaded
ruleset still sees `Full`/`Common` from `DetectorRegistry::profile()`;
ruleset presence is a separate fact the caller already has from the number
of detectors `load_ruleset` returned.

### Names section

A ruleset can also add to `generic-token`'s contextual-assignment name
vocabulary, without a `detector:` block at all:

```text
ruleset-revision: 1
names: ambiguous
name: corp_token
```

`names: ambiguous` is the only claimable bucket in this revision — a caller
can add an in-house assignment keyword (`corp_token`) to the same **ambiguous**
bucket `auth`/`credential`/`signing_key` already belong to, kept at that
bucket's higher entropy bar and always `Confidence::Medium`; a ruleset cannot
add to the high-signal bucket (`api_key`, `password`, …) in this revision.
Every `name:` value is normalized the same way a scanned input's captured
assignment name already is, so `CorpToken`, `corp-token`, and `corp_token` are
the same addition. A name that normalizes to an existing built-in name is a
silent no-op — a ruleset can never remove, override, or re-bucket a built-in
name. A names-only ruleset (no `detector:` blocks) is valid; a names section
registers its own separate detector rather than changing `generic-token`
itself, so it inherits the same containment property as a value-section
ruleset detector.

A malformed ruleset is rejected as a whole — never partially loaded — with
the fixed `INVALID_RULESET` code and one of a closed set of rejection
classes (`RulesetErrorClass`: `RULESET_TOO_LARGE`, `UNKNOWN_REVISION`,
`UNKNOWN_FIELD`, `UNSUPPORTED_CONSTRUCT`, `UNKNOWN_ALPHABET`,
`UNKNOWN_VALIDATOR`, `SPECIFICITY_NOT_CLAIMABLE`, `MISSING_FIELD`,
`PREFIX_TOO_SHORT`, `PREFIX_TOO_LONG`, `RUN_LENGTH_OUT_OF_BOUNDS`,
`TOO_MANY_DETECTORS`, `DUPLICATE_DETECTOR_ID`, `RESERVED_DETECTOR_ID`,
`EMPTY_RULESET`, `NAME_BUCKET_NOT_CLAIMABLE`, `NAME_TOO_LONG`,
`TOO_MANY_NAMES`) — never a byte from the rejected ruleset.

Per surface:

- **Rust:** `redact_secret::load_ruleset(bytes) -> Result<Vec<Box<dyn Detector>>, RulesetError>`,
  registered the same way a native custom detector is:
  `DetectorRegistry::with_built_in(detectors)`.
- **JavaScript (Node and browser WebAssembly):** a `ruleset` option on `scan`/
  `scanAndRedact`, taking a `Uint8Array` or a UTF-8 `string`.
- **Python:** a `ruleset` keyword argument on `scan`/`scan_and_redact`, taking
  `bytes`, `bytearray`, or `str`.
- **CLI:** `--ruleset <path>`, requiring an explicit file source — standard
  input's streaming session accepts no custom detector, ruleset or
  otherwise, because none declares the retention bound a streaming session
  must enforce.

Deliberately out of scope for this revision: `AND`/`OR`/`NOT`, nesting,
rule-to-rule reference, context keyword/companion fields, caller-set
confidence or entropy threshold, regex or any pattern beyond the alphabets
above, and migrating built-in detectors onto this format. See
`decision-define-declarative-detector-ruleset-contract` for the full
rationale.

## Incremental sanitization

Independently scanning chunks is unsafe because a credential can cross any
chunk boundary. The bounded incremental API retains unresolved plaintext until
a detector window closes, finalization supplies the end-of-input boundary, or a
declared limit fails.

**Current support:** Rust, Python, CLI standard input, and both JavaScript
artifacts (Node and browser WebAssembly) support incremental sanitization.
See [streaming](./docs/guides/streaming.md).

Python limits count UTF-8 bytes, while findings carry absolute Unicode code
point offsets into the joined input:

```python
import redact_secret

limits = redact_secret.IncrementalLimits(
    max_input_bytes=1_000_000,
    max_buffered_bytes=32_896,
    max_token_bytes=8_192,
    max_multiline_bytes=32_768,
)

with redact_secret.IncrementalSanitizer(limits) as session:
    first = session.append("api_key=SYNTHETIC_REVOKED_")
    second = session.append("INCREMENTAL_VALUE\nordinary text")
    final = session.finalize()

safe_text = first.text + second.text + final.text
# api_key=<SECRET_1>\nordinary text
```

Leaving the `with` block aborts a session that was not finalized, so whatever it
still retained is discarded.

Every session requires explicit total-input, retained-plaintext, token, and
multiline limits. Abort, lifecycle misuse, callback failure, and limit failure
drop retained plaintext and return only fixed, input-free errors. For accepted
input, concatenated incremental results must equal one whole-input operation
regardless of chunk partitioning.

Byte-stream adapters use one fatal, stateful UTF-8 decoder so multibyte
characters may safely cross chunks. Host adapters own backpressure,
cancellation, and destruction; the Rust core owns scan semantics and retained
plaintext safety.

## Detection coverage

<!-- support-matrix:start -->
**Support status** (34 providers, 79 credential families; stable: 3, provisional: 58, pending: 2, unsupported: 16) -- generated from evaluation evidence, never hand-written. `provisional` means useful but evidence-incomplete, not "almost stable"; unsupported families are listed with their reason. See the full [support matrix](docs/support-matrix.md).
<!-- support-matrix:end -->

The support-status line above and the linked matrix are the only place
per-family support is stated; this README does not repeat provider lists or
counts. Built-in Rust detection covers these kinds of structure — the
[detection reference](docs/reference/detection.md) names the provider formats
behind each:

- PEM-style private-key blocks;
- provider-issued API keys and tokens with a recognizable format;
- JWTs and bearer, Basic, and Token authorization credentials;
- contextual credential assignments, such as an `api_key` or `password`
  setting;
- credential-bearing database and message-broker connection URLs; and
- `otpauth://` URIs carrying a shared secret.

Entropy is only a supporting signal. Random-looking text is not classified
without structural or contextual evidence, and the generic name `token` alone
is deliberately ignored.

Strict prefixes, supported URI schemes, minimum lengths, bounded values, and
placeholder exclusions favor precision. The tradeoff is that truncated, short,
new, or unsupported credential formats can be missed. The core never performs
runtime provider lookups, and Redact Secret is not a complete DLP system.

Whole-input `scan`, `redact`, and `scan_and_redact` default to a 64 MiB input
bound and a 50,000 finding-count bound
(`decision-bound-whole-input-operations-by-default`). Exceeding either fails
closed with a fixed `INPUT_LIMIT_EXCEEDED`/`FINDING_LIMIT_EXCEEDED` error
rather than a truncated result; a caller that genuinely needs a wider bound
raises it explicitly (`scan_with_limits` and its siblings in Rust, a `limits`
option in every binding). This is a library-level backstop, not a substitute
for host-side bounding: authoritative servers must still bound transport
bytes, decoded input, sanitized output, concurrency, and memory before
downstream use.

## Browser and server boundaries

Scan in the browser before constructing a request body so preventive UX can
keep a high-confidence credential on the device:

```ts
const result = scanAndRedact(userInput);
showSecretWarning(result.findings);

await fetch("/api/conversation", {
  method: "POST",
  body: JSON.stringify({ content: result.text }),
});
```

Scan again on the server before logging, persistence, context construction, or
model and tool invocation:

```ts
const result = scanAndRedact(request.content, { policy: serverPolicy });

if (result.findings.some((finding) => finding.action === "block")) {
  throw new Error("Blocked sensitive input");
}

await conversationStore.save(result.text);
return modelGateway.respond({ input: result.text });
```

Never log raw request or tool bodies before authoritative scanning.

## Opt-in detector profiles

Everything above uses `full`, the default on every surface: every officially
supported built-in detector, and the compatibility baseline. Keep the
authoritative server boundary above on `full`.

For size- or latency-sensitive **preventive** consumers — browser UX and
small agent or tool processes — `common` is a smaller, opt-in built-in
detector set: only the structural and contextual detectors (a PEM/OpenSSH
private key, an RFC 7519 JWT, an `otpauth://` URI, a credential-bearing
connection URI, an HTTP `Bearer` header, and a contextual assignment), not
any one issuer's token format. Switch by changing the import, or the Rust
constructor:

```ts
import { initialize, scanAndRedact } from "@redact-secret/core/common";
```

```rust
let registry = DetectorRegistry::with_common_built_in(std::iter::empty())?;
```

`common`'s false-negative tradeoff: a bare provider token (for example a raw
GitHub or AWS credential, with no surrounding `Bearer` header or contextual
assignment) is not detected at all, and a provider token that *is* caught by
a `common` detector's context is reported under that detector's type and
confidence instead of the provider-specific one — for example `warn` where
`full` would `redact`. It adds no false positive: it only drops candidates
`full` would have reported. Measured against `full` over the whole canonical
corpus, `common` saves about 16% transfer size and processes 3–6× faster in
the browser, with zero new false positives and identical findings wherever
no provider detector would have competed
([evidence](./docs/audits/evidence/382/README.md)).

`@redact-secret/core/web-stream` and `@redact-secret/core/node-stream`'s
convenience `createWebStreamSanitizer`/`createNodeStreamSanitizer` always
open a `full` session. For a `common` byte stream, use the same factories
from `@redact-secret/core/common/web-stream`/`@redact-secret/core/common/node-stream`
instead — resolving one of those two subpaths never reaches the `full`
runtime or the root `@redact-secret/wasm` artifact in a browser bundle. The
`WebStreamSanitizer`/`NodeStreamSanitizer` classes are profile-agnostic and
shared across both pairs of subpaths, so constructing one directly with a
session from `@redact-secret/core/common`'s own `createIncrementalSanitizer`
still works too. See the
[streaming guide](./docs/guides/streaming.md#streaming-under-the-common-profile).

Python and the CLI stay `full` only — the CLI is a pre-commit/CI enforcement
tool, where a smaller profile would only weaken enforcement.

## Mask secrets in traces

Wire the same detection into LLM tracing SDKs so prompts, tool calls, and
spans never carry a secret into observability storage. See
[`examples/tracing-masking/`](examples/tracing-masking/) for the masking
callback, an OpenTelemetry `SpanProcessor`, and their tests.

```ts
import { Langfuse } from "langfuse";
import { createMaskSecrets } from "./examples/tracing-masking/langfuse-mask.mjs";

const maskSecrets = await createMaskSecrets();
const langfuse = new Langfuse({ mask: ({ data }) => maskSecrets(data) });
```

```python
from langfuse import Langfuse
from langfuse_mask import mask_secrets

langfuse = Langfuse(mask=mask_secrets)
```

## Redact secrets in logs

Wire the same detection into application logging, alongside pino's own
path-based `redact` or Python's standard `logging`, so a secret in a
message, a field, or an error's text never reaches a log destination. See
[`examples/logging-redaction/`](examples/logging-redaction/) for both
integrations, the API details they're pinned against, and their tests.

```js
import pino from "pino";
import { createRedactingLogMethod } from "./examples/logging-redaction/pino-redact.mjs";

const logMethod = await createRedactingLogMethod();
const logger = pino({ hooks: { logMethod } });
```

```python
import logging
import redact_secret
from logging_filter import RedactSecretFilter

handler.addFilter(RedactSecretFilter(redact_secret.scan_and_redact))
```

## CLI quick start

The `redact-secret` binary is a host adapter over the same core, for CI,
pre-commit hooks, and safe redaction pipelines.

```bash
redact-secret src/config.ts src/client.ts   # check files; exit 1 on a finding
git diff --cached | redact-secret           # check a staged diff
redact-secret --json .env.example           # machine-consumable safe report
redact-secret --redact log.txt > safe.txt   # sanitize; the input is untouched
```

Check output carries safe file identity and finding metadata only — a range
names a span in the input, never the bytes in that span. Check exit codes are
the enforcement contract: `0` when nothing was found, `1` when anything was, and
`2` for a usage, decoding, or processing failure. A failure outranks a finding,
and input that is not valid UTF-8 fails closed. Redaction reports `0` or `2`
only: finding something is what it is for, not a failure.

Standard input is streamed through the incremental core under explicit limits,
because a credential may straddle any chunk boundary; a path is read whole under
the same total-input bound. See
[`crates/secret-scan-cli/README.md`](./crates/secret-scan-cli/README.md) for
the full surface and `redact-secret --help` for the limits in force.

## Conformance

[`conformance/`](./conformance/README.md) is the single language-neutral,
executable behavioral contract for the Rust core and every supported binding.
Canonical fixtures use UTF-8 byte offsets; JavaScript and Python runners convert
them to their native units and verify that the selected span is unchanged.

The corpus covers detector results, exclusions, overlap precedence, policy,
redaction, Unicode boundaries, incremental partition equivalence, adversarial
limits, and input-free diagnostics. Fixtures contain only unmistakably
synthetic or revoked values, and expected metadata never copies matched text.

Binding-local lifecycle, callback, packaging, and host-integration tests add
surface-specific evidence without copying or replacing the shared corpus.

## Evaluation

[`assessment/`](./assessment/README.md) defines the cross-language evaluation
protocol: a synthetic assessment corpus, named workload profiles, and a
common result contract covering accuracy, initialization, processing,
throughput, repetition, and memory metrics, with full reproducibility
provenance. It is distinct from `conformance/` and is never a release gate —
it measures accuracy and performance, not pass/fail behavioral conformance.
Repository-only Node, browser, Rust, and installed-Python runners record raw
timing distributions and separate sampled memory categories without adding
product instrumentation APIs. The Python adapter exercises whole-input and
incremental public APIs and normalizes code-point ranges to canonical UTF-8
byte spans before common scoring.

## Development

Install JavaScript tooling and run the main repository checks:

```bash
npm ci
npm run ci
```

Validate workspace policy and the Rust surfaces:

```bash
npm run rust:check
cargo fmt --all --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --locked
cargo package -p redact-secret --locked
```

Build and qualify the CPython artifacts (see
[docs/python-packaging.md](./docs/python-packaging.md)):

```bash
npm run python:check
uvx maturin build --release -m bindings/python/Cargo.toml -o dist
uvx maturin sdist -m bindings/python/Cargo.toml -o dist
python3 scripts/qualify-python-wheel.py --conformance dist/*.whl
python3 scripts/qualify-python-wheel.py --build-sdist dist/*.tar.gz
```

Build and qualify the Node addon, the browser artifact, and the CLI for this
host (see [docs/qualification.md](./docs/qualification.md)):

```bash
npm run artifacts:check
npm --prefix bindings/node ci && npm --prefix bindings/node run build
npm run js:build && npm run addon:qualify -- --target <triple>
npm run wasm:build && npm run browser:qualify
cargo build --release --locked -p redact-secret-cli
npm run cli:qualify -- --binary target/release/redact-secret
```

The repository layout is:

```text
conformance/             shared cross-language contract
assessment/              cross-language evaluation protocol (corpus, profiles, result contract)
crates/secret-scan-core canonical Rust implementation
crates/secret-scan-cli  CLI host adapter
bindings/node           Node N-API binding
bindings/wasm           browser WebAssembly binding
bindings/python         Python PyO3 binding and package
packages/javascript     unified JavaScript package, published as @redact-secret/core
```

Release qualification builds, tests, and smoke-tests the Rust crate, npm
package, Python package, and CLI from the same commit without publishing,
across every declared target and browser engine, and records an artifact
inventory tied to the source commit. See
[Versioning, qualification, and release](./ARCHITECTURE.md#versioning-qualification-and-release)
in ARCHITECTURE.md for the full workflow and
[docs/qualification.md](./docs/qualification.md) for how to run it locally.

## Security and release process

See [SECURITY.md](./SECURITY.md) for private vulnerability reporting and the
security model. Never submit active credentials in a report, issue, fixture,
snapshot, log, or diagnostic.

A release requires explicit approval after tests pass and the public API and
changelog have been reviewed. Readiness checks do not authorize selecting a
version, creating a tag, publishing a package, deploying, or archiving another
repository. See the [changelog](./CHANGELOG.md).

The accepted architectural decisions are indexed in
[docs/decisions/DECISIONS.md](./docs/decisions/DECISIONS.md).

Acceptance evidence and independent reviews — the closed-issue migration
ledger, the core/conformance/CLI boundary review, the JavaScript and Python
binding review, the CI and supply-chain review, and their release-gap
disposition and deferred-quality backlog — are indexed in
[docs/audits/README.md](./docs/audits/README.md). These documents record
evidence and classify work only; none of them authorizes any release
operation.

## License

[MIT](./LICENSE)
