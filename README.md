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

Logging, telemetry, model context, and MCP are application use cases. This
repository provides core APIs and generic integration examples, but no dedicated
LangChain, OpenTelemetry, pino, Python logging, or MCP integration packages.

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

The replacement JavaScript package presents one typed API across Node.js and
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
implementation.

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
  DigitalOcean, Linear, Supabase, Vercel, SendGrid, Google Cloud/Gemini,
  Notion, Atlassian Cloud (Jira / Confluence), Twilio Auth Token/API Key
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

Whole-input operations have no implicit input-size or finding-count limit.
Authoritative servers must bound transport bytes, decoded input, accepted
findings, sanitized output, concurrency, and memory before downstream use.

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

Release qualification must build and test the Rust crate, npm package, Python
package, and CLI from the same commit without publishing. The artifacts share
one SemVer version and one eventual `v{version}` tag. The `Qualification
Matrix` workflow is that run: it builds the N-API addon, the CPython abi3
wheels, the browser WebAssembly artifact, and the CLI binary for every
declared target, smoke-tests each on the architecture it targets, exercises
the browser artifact in Chromium, Firefox, and WebKit, and records an artifact
inventory tied to the source commit. `[workspace.metadata.redact-secret]`
declares those matrices once and `npm run artifacts:check` fails when any file
that consumes them drifts. See
[docs/qualification.md](./docs/qualification.md).

On both JavaScript runtimes the matrix loads `@redact-secret/core` on the real
artifact — the N-API addon on every target's own runner, and the WebAssembly
build in each browser engine — and runs the canonical corpus through its
public API. It then packs the candidate wrapper, native addon, and WebAssembly
packages, installs them in clean consumer directories, and exercises the
public incremental and stream APIs on Node.js 20, 22, and 24 and in Chromium,
Firefox, and WebKit. Each installed-package result records the source revision
and SHA-256 identities of those candidate packages. Both artifacts open the
same core `IncrementalSanitizer` session the Python binding wraps; the Node
`Transform` and Web `TransformStream` adapters add one fatal stateful UTF-8
decoder plus host backpressure and cancellation behavior.

## Security and release process

See [SECURITY.md](./SECURITY.md) for private vulnerability reporting and the
security model. Never submit active credentials in a report, issue, fixture,
snapshot, log, or diagnostic.

A release requires explicit approval after tests pass and the public API and
changelog have been reviewed. Readiness checks do not authorize selecting a
version, creating a tag, publishing a package, deploying, or archiving another
repository. See the [candidate changelog](./CHANGELOG.md).

The accepted architectural decisions are indexed in
[docs/decisions/DECISIONS.md](./docs/decisions/DECISIONS.md).

Criterion-level acceptance evidence for the closed Rust-core migration issues,
including the gaps that remain open, is recorded in
[docs/audits/closed-issue-acceptance-evidence-ledger.md](./docs/audits/closed-issue-acceptance-evidence-ledger.md).
It records evidence only; it does not authorize any release operation.

An independent review of the canonical core, the conformance contract, and the
CLI boundary, with its findings and their exit conditions, is recorded in
[docs/audits/core-conformance-cli-boundary-review.md](./docs/audits/core-conformance-cli-boundary-review.md).
It records evidence only; it does not authorize any release operation.

An independent review of the JavaScript and Python runtime adapters and the
package contracts they declare, with its findings and their exit conditions, is
recorded in
[docs/audits/javascript-python-bindings-package-contracts-review.md](./docs/audits/javascript-python-bindings-package-contracts-review.md).
It records evidence only; it does not authorize any release operation.

An independent review of CI, the release and reconcile automation, the
documented support matrices, and the supply-chain controls behind them, with its
findings and their exit conditions, is recorded in
[docs/audits/ci-release-automation-supply-chain-review.md](./docs/audits/ci-release-automation-supply-chain-review.md).
It records evidence only; it does not authorize any release operation.

One disposition for every finding those four documents produced — which findings
block a release, which are deferred, and which are intentional exclusions — with
the bounded remediation Task each blocker becomes, is recorded in
[docs/audits/release-gap-disposition.md](./docs/audits/release-gap-disposition.md),
and the deferred remainder in
[docs/audits/deferred-quality-backlog.md](./docs/audits/deferred-quality-backlog.md).
They classify and specify work only; they do not authorize any release operation.

## License

[MIT](./LICENSE)
