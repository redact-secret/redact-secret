# Redact Secret

Deterministic secret detection and redaction for JavaScript, Python, Rust, and
command-line applications.

Redact Secret inspects untrusted text before it is logged, persisted, indexed,
sent to a tool, or added to model context. One side-effect-free Rust core owns
built-in detection, overlap resolution, policy, redaction, and bounded
incremental sanitization. Runtime bindings adapt that behavior without
reimplementing it.

> Client-side scanning is preventive UX. Server-side scanning is the
> authoritative enforcement boundary.

## Start here

Read the [documentation](./docs/README.md) for installation, language guides,
policy, detection limits, and troubleshooting. The current checkout uses one
Rust core through runtime-specific bindings; its executable behavior contract
lives in [conformance](./conformance/README.md).

Public beta packages are available; see [release status](./docs/releases/status.md)
for verified versions and artifacts. Development manifest versions alone do not
establish availability. To build this checkout, use the
[source setup](./docs/getting-started.md).

Pino, Python `logging`, and OpenTelemetry `SpanProcessor` integrations are
published as versioned packages in a separate repository,
[`redact-secret-adapters`](https://github.com/redact-secret/redact-secret-adapters)
(`@redact-secret/adapter-pino`, `@redact-secret/adapter-otel`, and the PyPI
`redact-secret-adapters` distribution) — see
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
glibc Linux, macOS, and Windows (x64 and arm64 each: six platform packages,
`engines.node` `20.x || 22.x || 24.x`) as an optional dependency, since npm
ships glibc addons only — musl Linux (e.g. Alpine) has no published
package. `initialize()` rejects with `INITIALIZATION_FAILED` on a musl
host, the same failure an unsupported platform/architecture gets. See
[docs/qualification.md](./docs/qualification.md) for the full target matrix
and how CI keeps it from drifting.

```ts
import { initialize, scanAndRedact } from "@redact-secret/core";

await initialize();

const input = "API_KEY=SYNTHETIC_REVOKED_CONTEXT_VALUE";
const result = scanAndRedact(input);

console.log(result.text);
// API_KEY=<SECRET_1>
```

All examples use unmistakably synthetic, revoked values. Findings contain
classification, action, and original-input offsets, never the matched plaintext
value.

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
core parses and matches itself, never a callback — for JavaScript, Python,
and the CLI; see that decision for status.

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

Built-in Rust detection covers:

- PEM-style private-key blocks;
- AWS access-key IDs;
- GitHub and GitLab token families;
- JWTs and bearer, Basic, and Token authorization credentials;
- OpenAI, Anthropic, Shopify, and modern HashiCorp Vault credentials;
- qualified Stripe, Slack, PyPI, Hugging Face, Docker Hub, Cloudflare,
  DigitalOcean, Linear, Supabase, Vercel, npm, SendGrid, Google Cloud/Gemini,
  Microsoft Entra client secret, Azure DevOps personal access token, Notion, Atlassian Cloud (Jira / Confluence), Twilio Auth Token/API Key
  Secret, Telegram Bot API, Discord bot, Sentry user/organization auth token,
  Datadog API/Application Key, Grafana service account, and Grafana Cloud access
  policy, and New Relic User API Key/License Key credentials;
- contextual credential assignments, including AWS secret-access-key and
  session-token setting names;
- credential-bearing PostgreSQL, MySQL, MariaDB, MongoDB, Redis, and AMQP URLs;
  and
- `otpauth://totp` and `otpauth://hotp` URIs carrying a base32-encoded shared
  secret.

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
