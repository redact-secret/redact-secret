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

`@redact-secret/core` presents one typed API across Node.js and modern
browsers. On Node.js it loads a prebuilt N-API addon and falls back to the
browser WebAssembly artifact where no addon loads; `artifact()` reports which
one did. Cloudflare Workers is supported; Vercel Edge is not yet. Findings
carry classification, action, and original-input offsets (UTF-16 code units
in JavaScript), never the matched plaintext. The
[JavaScript guide](docs/guides/javascript.md) covers runtime selection,
policies, limits, profiles, and browser loading.

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
implementation. A caller with an internal credential format uses a
[declarative ruleset](#declarative-rulesets) instead.

## Declarative rulesets

An organization with an internal credential format can declare it as a
**declarative ruleset**: UTF-8 data (at most 64 KiB) the core parses and
matches itself with the same linear-time engine as every built-in detector,
never a callback. Ruleset detections always carry medium confidence and can
never outrank a built-in finding. Rust, JavaScript, Python, and the CLI
(`--ruleset <path>`) all accept one. See the
[rulesets guide](docs/guides/rulesets.md) for the format, matching semantics,
and rejection classes.

## Incremental sanitization

Independently scanning chunks is unsafe because a credential can cross any
chunk boundary. Rust, Python, CLI standard input, and both JavaScript
artifacts provide a bounded incremental API whose concatenated output equals
one whole-input operation, under explicit limits that fail closed. See
[streaming](docs/guides/streaming.md).

## Detection coverage

<!-- support-matrix:start -->
**Support status** (42 providers, 93 credential families; stable: 34, provisional: 38, pending: 2, unsupported: 19) -- generated from evaluation evidence, never hand-written. `provisional` means useful but evidence-incomplete, not "almost stable"; unsupported families are listed with their reason. See the full [support matrix](docs/support-matrix.md).
<!-- support-matrix:end -->

Built-in detection covers private keys, provider-issued tokens, JWT and
authorization headers, contextual credential assignments, credential-bearing
connection URLs, and `otpauth://` URIs. Entropy is only a supporting signal,
and whole-input operations are bounded by default. The
[detection reference](docs/reference/detection.md) lists every built-in
detector (generated from the inventory), the false-positive and
false-negative tradeoffs, and the limits.

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

Everything above uses `full`, the default on every surface. `common`
(`@redact-secret/core/common`, or `DetectorRegistry::with_common_built_in` in
Rust) is a smaller, opt-in set for preventive browser and agent consumers
that drops provider-specific detectors. Keep the authoritative server
boundary on `full`. See [detector profiles](docs/reference/detection.md#detector-profiles)
for its false-negative tradeoff and measured savings.

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
redact-secret --redact log.txt > safe.txt   # sanitize; the input is untouched
```

See the [CLI guide](docs/guides/cli.md) for exit codes, reports, and limits.

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

```bash
npm ci
npm run ci
```

[Developer onboarding](docs/onboarding.md) lists the Rust, Python, and
artifact qualification commands and the repository layout; the
[contribution guide](CONTRIBUTION.md) covers pull requests and review.

## Security and release process

See [SECURITY.md](./SECURITY.md) for private vulnerability reporting and the
security model. Never submit active credentials in a report, issue, fixture,
snapshot, log, or diagnostic. For a false positive or missed detection, use
the [reporting guide](docs/guides/reporting-detection-issues.md) instead.

Releases follow the [release authority](AGENTS.md#release-authority) and the
[release runbook](docs/releasing.md); see the [changelog](./CHANGELOG.md).
Accepted architectural decisions are indexed in
[docs/decisions/DECISIONS.md](./docs/decisions/DECISIONS.md), and review
evidence in [docs/audits/README.md](./docs/audits/README.md).

## License

[MIT](./LICENSE)
