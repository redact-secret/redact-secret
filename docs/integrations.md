# Integrations and release lifecycle

[Documentation home](README.md) · [Five-minute quickstart](quickstart.md)

The core library in this repository finds and redacts secrets in text you pass
it. Integrations carry text from a logger, a tracer, an MCP server, or a model
client into that core. Most of them live in other repositories and release on
their own versions, so this page tells you which package to look for and what
each one promises.

## Which package do I need

| I want to protect | Package | Install and guide |
| --- | --- | --- |
| `pino` log lines | `@redact-secret/adapter-pino` | [adapters repository](https://github.com/redact-secret/redact-secret-adapters#which-package-do-i-need) |
| Python `logging` records | `redact-secret-adapters` (PyPI) | same page |
| OpenTelemetry spans, JavaScript | `@redact-secret/adapter-otel-trace` | same page |
| OpenTelemetry spans, Python | `redact-secret-adapters[otel]` | same page |
| OpenTelemetry logs, JavaScript | `@redact-secret/adapter-otel-logs`, published under the npm `beta` tag only | same page |
| User input, tool results, and streamed text before model context | `@redact-secret/adapter-ai-context` | same page, and the [AI-context boundary contract](reference/ai-context-boundary.md) |
| MCP tool results and resource reads | `@redact-secret/adapter-mcp` | same page, the [MCP boundary contract](reference/mcp-boundary.md), and the [`resources/read` contract](reference/mcp-resources-read.md) |
| A `mask` callback such as Langfuse's | `@redact-secret/adapter` | same page |
| Secrets you must hide from a model and put back later | `@redact-secret/vault`, the opt-in vault | [vault repository](https://github.com/redact-secret/redact-secret-vault#readme) |

`@redact-secret/adapter-otel` is the earlier name of `adapter-otel-trace`; the
adapters repository documents `adapter-otel-trace`. The adapters repository
lists OpenTelemetry metrics and model output as not covered by anything
installable today. There is no LangChain integration: it remains an
application use case.

Each adapter takes a policy, so the same rule applies to all of them: the
adapter replaces what the policy says to redact and reports the rest; your
application rejects what it must not accept
([safe integration](guides/safe-integration.md)).

If you would rather see where redaction belongs than pick a package, the
[reference architectures](guides/reference-architectures.md) show logging,
tracing, and AI context end to end, each with a runnable example and a stated
trust boundary. The [MCP example](../examples/mcp-redact/) composes the MCP
adapter into one tested agent turn.

## What is stable and what is not

| Part | Where it lives | Version line | What the version means |
| --- | --- | --- | --- |
| Core: `@redact-secret/core` (Node.js and browser), `redact-secret` (PyPI and crates.io), `redact-secret-cli` | this repository | `0.1.0-beta.N`; the stable `0.1.0` is not published | Beta now. From `0.1.0` the [Stable contract 1](reference/api-contract.md#stable-contract-1) applies to the Rust, JavaScript, Python, and CLI surfaces it lists |
| Adapters | [`redact-secret-adapters`](https://github.com/redact-secret/redact-secret-adapters) | `0.1.x`, released on their own trains | Not covered by Stable contract 1. Each requires core `^0.1.0-beta.6` (Python: `redact-secret>=0.1.0b6,<0.2`) and says which host versions it was tested against |
| Vault | [`redact-secret-vault`](https://github.com/redact-secret/redact-secret-vault) | `0.1.0-beta.N`; its persistent server profile is alpha | Not covered by Stable contract 1. It pins the core version exactly, so each core release needs a matching vault release |

The promise `0.1.0` is meant to make is: deterministic, evidence-qualified
runtime detection and redaction across the supported core runtimes, with
documented limits and cross-runtime conformance. It covers the core only.
Adapters and the vault depend on the core and are not part of it, and an
adapter or vault version does not tell you the core is stable. Beta releases of
the core may still change public names and behavior; read the
[changelog](../CHANGELOG.md) before moving between them.

The exact versions, dist-tags, and dates each registry carried when last
observed are in [release status](releases/status.md#host-integration-adapters).
Registries change faster than this repository, so check the live value:

```bash
npm view @redact-secret/adapter-pino dist-tags
pip index versions redact-secret-adapters
```

## Where plaintext still exists

An integration narrows where unredacted text lives; it does not remove it. Each
reference architecture names the trust zone in which plaintext is still present
and where the authoritative scan runs. For a browser client, scanning on the
device is preventive; the server scans again, and that scan is the one your
security decisions rely on. How long plaintext stays in memory inside the core
is in [plaintext memory lifetime](reference/plaintext-lifetime.md).
