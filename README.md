# Redact Secret

[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/15000/badge)](https://www.bestpractices.dev/projects/15000)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/redact-secret/redact-secret/badge)](https://scorecard.dev/viewer/?uri=github.com/redact-secret/redact-secret)
[![SAST](https://github.com/redact-secret/redact-secret/actions/workflows/sast.yml/badge.svg?branch=main)](https://github.com/redact-secret/redact-secret/actions/workflows/sast.yml)
[![License: MIT](https://img.shields.io/github/license/redact-secret/redact-secret)](./LICENSE)
[![npm: @redact-secret/core](https://img.shields.io/npm/v/@redact-secret/core/beta?label=%40redact-secret%2Fcore)](https://www.npmjs.com/package/@redact-secret/core)
[![PyPI: redact-secret](https://img.shields.io/pypi/v/redact-secret?include_prereleases&label=redact-secret)](https://pypi.org/project/redact-secret/)
[![crates.io: redact-secret](https://img.shields.io/crates/v/redact-secret?label=crates.io)](https://crates.io/crates/redact-secret)
[![docs.rs](https://img.shields.io/docsrs/redact-secret)](https://docs.rs/redact-secret)

Deterministic secret detection and redaction for runtime data and AI context.

Your application handles text it does not fully control: user input, pasted
configuration, error messages, HTTP bodies, and tool results. Before that text
reaches logs, persistence, telemetry, tool output, or model context, pass it
through Redact Secret. It finds supported credential formats (plus opt-in
structured PII, whose `pii-v1` statuses at the Beta.11 qualification were five families
`provisional`, US SSN `pending`, none `stable`)
and returns the text with those matches replaced, plus findings that describe what was
found and where without ever including the secret itself. It runs in your
process. It makes no network calls and sends no telemetry, and the same input
always gives the same result.

## Quick start

Every release so far is a beta; the stable `0.1.0` is not published yet.

> **Version status.** Latest published: `0.1.0-beta.14`
> ([release record](docs/releases/0.1.0-beta.14/README.md), [status](docs/releases/status.md)).
> The install commands below pin it, because the install paths are qualified
> against it.

Pick your runtime, install, and redact
one synthetic value in about five minutes:

| Runtime | Install | Steps |
| --- | --- | --- |
| JavaScript: Node.js 20, 22, 24, and browsers | `npm install @redact-secret/core@beta` | [Node.js](docs/quickstart.md#nodejs), [browser](docs/quickstart.md#browser-with-a-bundler) |
| Python 3.10 or newer | `pip install --only-binary=:all: redact-secret` | [Python](docs/quickstart.md#python) |
| Rust 1.88 or newer | `cargo add redact-secret` | [Rust](docs/quickstart.md#rust) |
| Command line | `cargo install redact-secret-cli --locked --version 0.1.0-beta.14` | [CLI](docs/quickstart.md#command-line); `--version` is required while every release is a beta |

These pin the latest published beta. The [quickstart](docs/quickstart.md#which-version-you-get)
pins an exact version, says what a bare install resolves today, and says what
changes when `0.1.0` is published. No prebuilt CLI binary is published.

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

Two things to know before you rely on it. Scanning in a browser is preventive;
the server must scan again, and that scan is the authoritative boundary
([where scanning belongs](#where-scanning-belongs)). And an empty finding list
does not prove text is secret-free ([what it does not replace](#what-it-does-not-replace)).

| I want to | Read |
| --- | --- |
| Use it from [JavaScript](docs/guides/javascript.md), [Python](docs/guides/python.md), [Rust](docs/guides/rust.md), or the [CLI](docs/guides/cli.md) | the guide for my language |
| Decide what gets redacted, blocked, or only reported | [policy and safe integration](docs/guides/safe-integration.md) |
| Process a stream or large input in chunks | [streaming](docs/guides/streaming.md) |
| Detect an in-house credential format | [declarative rulesets](docs/guides/rulesets.md) |
| Protect logs, traces, MCP, or model context | [integrations](docs/integrations.md) |
| Fix an error or check a runtime is supported | [troubleshooting](docs/troubleshooting.md) |
| See every document | [documentation home](docs/README.md) |

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
  a model's context window ([AI-context example](examples/ai-context/)).

The logging, tracing, and AI-context examples are executable
[reference architectures](docs/guides/reference-architectures.md): each
installs only released or pinned packages, states where plaintext exists and
where the authoritative scan happens, and runs an end-to-end smoke test in CI.

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

- **It is not a DLP platform.** It finds credentials, plus opt-in structured PII (six bounded
  families: at the Beta.11 qualification, five `provisional`, US SSN `pending`), not general personal data, and
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

## Integrations and release status

This repository ships the core: the Rust crates, the JavaScript and Python
packages, and the CLI. They are beta today and move together on one version.
Stable contract 1 ([API concepts](docs/reference/api-contract.md#stable-contract-1))
applies to them from `0.1.0`; the promise is deterministic, evidence-qualified
runtime detection and redaction across the supported core runtimes, with
documented limits and cross-runtime conformance.

Integrations are separate packages in separate repositories, on their own
versions, and Stable contract 1 does not cover them:

- **Logging, tracing, MCP, and model context**: Pino, Python `logging`,
  OpenTelemetry spans, a `mask` callback, AI-context, and MCP packages, from
  [`redact-secret-adapters`](https://github.com/redact-secret/redact-secret-adapters).
  Each requires core `0.1.0-beta.6` or later.
- **Vault** (opt-in; hides secrets from a model and restores them only where
  you allow): [`redact-secret-vault`](https://github.com/redact-secret/redact-secret-vault).
  Its in-memory packages are beta and its persistent server profile is alpha;
  it pins the core version exactly.

[Integrations](docs/integrations.md) says which package fits which job and what
each lifecycle means. [Release status](docs/releases/status.md) lists the
versions each registry carried when last observed. Model context (MCP) is
specified by the [MCP boundary contract](docs/reference/mcp-boundary.md);
[`examples/mcp-redact/`](examples/mcp-redact/) composes the adapter into a
tested agent turn. LangChain remains an application use case with no
integration in this repository. The adapters live apart for the reasons in
[`docs/decisions/2026-09-19-graduate-adapters-to-a-separate-repository.md`](./docs/decisions/2026-09-19-graduate-adapters-to-a-separate-repository.md),
including why this repository's own release matrix is unaffected.

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

## JavaScript runtimes and PII

`@redact-secret/core` presents one typed API across Node.js and modern
browsers. On Node.js it loads a prebuilt N-API addon and falls back to the
browser WebAssembly artifact where no addon loads; `artifact()` reports which
one did. Cloudflare Workers is supported; Vercel Edge is not yet. Findings
carry classification, action, and original-input offsets (UTF-16 code units
in JavaScript), never the matched plaintext. The
[JavaScript guide](docs/guides/javascript.md) covers runtime selection,
policies, limits, profiles, and browser loading.

PII activation is opt-in and defaults off across Rust, JavaScript, Python, and
the CLI. The shared `pii-domain` adapter registers the context-qualified
`pii:global:email`, `pii:global:iban`, `pii:global:network-address`,
`pii:global:payment-card`, and `pii:global:phone` families. They suppress only
their reviewed named negative classes. Under `pii-v1` these five global
families are `provisional`, not `stable`, from the Beta.11 qualification of
candidate core `8b6a5fde`; availability alone is not a support claim, and phone
covers only `+1` / NANP numbers. The jurisdictional `pii:us` selector closes
over those global families plus `pii:us:ssn`; `pii:family:us:ssn` selects only
SSNs. The SSN family (United States only) uses SSA-published structural
exclusions and reviewed field labels, not issuance or identity lookup, and it
stays `pending`: it is available when selected but did not qualify. No other jurisdiction or national identifier
is available, and these six bounded families are not general PII coverage; the
[detection reference](docs/reference/detection.md#opt-in-pii-availability-is-not-support)
lists what each one excludes. See the [email family contract](docs/contracts/pii/email-v1.md),
the [IBAN family contract](docs/contracts/pii/iban-v1.md), the
[payment-card family contract](docs/contracts/pii/payment-card-v1.md), the
[phone family contract](docs/contracts/pii/phone-v1.md), and the
[US SSN family contract](docs/contracts/pii/us-ssn-v1.md), plus each
language guide, for activation identity and limits.

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
never a callback. Ruleset detections always carry medium confidence, so the
default policy only warns about them (`scanAndRedact` and `redact-secret
--redact` leave the matched text unchanged; only a caller policy redacts it),
and they can never outrank a built-in finding. Rust, JavaScript, Python, and the CLI
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
**Support status** (92 providers, 173 credential families; stable: 144, provisional: 7, pending: 5, unsupported: 17; stable qualification: documented: 106, empirical: 38, policy-qualified: 0; evidence tiers: T1: 106, T2: 41, T3: 4, T0: 1) -- generated from evaluation evidence, never hand-written. Stable families are labeled `Stable · Provider documented` or `Stable · Empirically qualified`; empirical qualification remains T2. `provisional` means useful but evidence-incomplete, not "almost stable"; unsupported families are listed with their reason. See the full [support matrix](docs/support-matrix.md). Counts are families and statuses, not detectors: a family is one provider x credential-family entry, one detector can back several families, and some families have no shipped detector. Measured on product commit `fe6e9234d40e` (`0.1.0-beta.13`) with benchmarks revision `573e128863e0` over 5950 fixtures; code shipped after the measured build is not covered by these statuses. This source ships 118 credential detectors, 110 of them mapped to at least one family. The opt-in PII families are outside this count and outside the matrix; their statuses are in [the detection reference](docs/reference/detection.md#opt-in-pii-availability-is-not-support). 8 shipped detectors are not yet measured and carry no status: `buildkite-token`, `fly-token`, `mapbox-token`, `pydantic-logfire-token`, `sourcegraph-token`, `square-token`, `unkey-root-key`, `xata-api-key`.
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
keep a high-confidence credential on the device. These two snippets are
illustrative: `showSecretWarning`, `serverPolicy`, `conversationStore`, and
`modelGateway` stand for your own code.

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
spans never carry a secret into observability storage, with the released
[`@redact-secret/adapter-otel`](https://www.npmjs.com/package/@redact-secret/adapter-otel)
`SpanProcessor` (the adapters repository now documents it as
`@redact-secret/adapter-otel-trace`) or the masking callback in
[`@redact-secret/adapter`](https://www.npmjs.com/package/@redact-secret/adapter).
See the [tracing reference](examples/tracing-masking/) for the trust zone,
the failure behavior, and what it does not cover.

```ts
import { Langfuse } from "langfuse";
import { createMaskSecrets } from "@redact-secret/adapter";

const maskSecrets = await createMaskSecrets();
const langfuse = new Langfuse({ mask: ({ data }) => maskSecrets(data) });
```

```python
from langfuse import Langfuse

from langfuse_mask import mask_secrets  # example file, not a package: copy it

langfuse = Langfuse(mask=mask_secrets)
```

`langfuse_mask` is the example module
[`examples/tracing-masking/python/langfuse_mask.py`](examples/tracing-masking/python/langfuse_mask.py),
which you copy into your application together with its sibling `mask_secrets.py`; the released Python package
`redact-secret-adapters` does not provide it.

## Redact secrets in logs

Wire the same detection into application logging, alongside pino's own
path-based `redact` or Python's standard `logging`, so a secret in a
message, a field, or an error's text never reaches a log destination, with
the released [`@redact-secret/adapter-pino`](https://www.npmjs.com/package/@redact-secret/adapter-pino)
or the released [`redact-secret-adapters`](https://pypi.org/project/redact-secret-adapters/)
`logging.Filter`. See the [logging reference](examples/logging-redaction/)
for the trust zone, the failure behavior, and what it does not cover.

```js
import pino from "pino";
import { createRedactingLogMethod, createRedactingStreamWrite } from "@redact-secret/adapter-pino";

const logger = pino({
  hooks: {
    logMethod: await createRedactingLogMethod(),
    streamWrite: await createRedactingStreamWrite(), // bindings and mixin() output never pass logMethod
  },
});
```

```python
import logging
from redact_secret_adapters.logging_filter import RedactSecretFilter

handler.addFilter(RedactSecretFilter())
```

## CLI

The `redact-secret` binary is a host adapter over the same core, for CI,
pre-commit hooks, and safe redaction pipelines. Install it with the command in
the [quick start](#quick-start).

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

## Project governance

- [GOVERNANCE.md](GOVERNANCE.md): roles, how decisions are made, and access
  continuity.
- [ROADMAP.md](ROADMAP.md): what the next year is expected to bring, and what
  is out of scope.
- [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md): expected behavior in every
  project space.
- [Security assurance case](docs/assurance-case.md): why the security
  requirements are met, with evidence.

## Security and release process

See [SECURITY.md](./SECURITY.md) for private vulnerability reporting and the
security model, how reports are handled, and how to verify signed releases.
Never submit active credentials in a report, issue, fixture,
snapshot, log, or diagnostic. For a false positive or missed detection, use
the [reporting guide](docs/guides/reporting-detection-issues.md) instead.

Releases follow the [release authority](AGENTS.md#release-authority) and the
[release runbook](docs/releasing.md); see the [changelog](./CHANGELOG.md).
Accepted architectural decisions are indexed in
[docs/decisions/DECISIONS.md](./docs/decisions/DECISIONS.md), and review
evidence in [docs/audits/README.md](./docs/audits/README.md).

## License

[MIT](./LICENSE)
