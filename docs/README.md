# Redact Secret documentation

Redact Secret is deterministic secret detection and redaction for runtime
data and AI context. It finds supported credential patterns in text and
replaces them before the text reaches logs, persistence, telemetry, tool
output, or model context. JavaScript, Python, Rust, and the CLI share one
deterministic Rust implementation that runs locally, with no network access.

Client-side scanning is preventive; server-side scanning is the authoritative
enforcement boundary. Redact Secret is not a DLP platform, does not detect
every secret, and complements repository and history scanners rather than
replacing them. See the [README](../README.md#what-it-does-not-replace) and
the generated [support matrix](support-matrix.md).

## Get started

1. [Five-minute quickstart](quickstart.md): install a published package in an
   empty project and redact one value with Node.js, Python, a browser bundler,
   Rust, or the command line. It says which version each command installs
   today. [Installation and supported runtimes](getting-started.md) covers the
   rest.
2. Follow a guide: [JavaScript](guides/javascript.md), [Python](guides/python.md),
   [Rust](guides/rust.md), or [CLI](guides/cli.md).
3. Read [policy and safe integration](guides/safe-integration.md) before sending
   output downstream.
4. Find the package for your logger, tracer, MCP server, or model client in
   [integrations](integrations.md), which also says what the core promises and
   which packages release on their own.

| Question | Read |
| --- | --- |
| What does a finding mean? Which offsets does it use? | [API concepts](reference/api-contract.md) |
| What credentials can be detected, and what can be missed? | [Detection and limits](reference/detection.md) |
| What did the bounded reliability assessment observe? | [Detection reliability](reference/detection-reliability.md) |
| Can I process a stream? | [Streaming](guides/streaming.md) |
| How long does plaintext stay in memory, and what is erased? | [Plaintext memory lifetime](reference/plaintext-lifetime.md) |
| What must an AI-context integration guarantee? | [AI-context boundary contract](reference/ai-context-boundary.md) |
| What may an MCP integration claim, and which tool-call points must it protect? | [MCP redaction boundary contract](reference/mcp-boundary.md) |
| What may an MCP integration claim for resource contents it reads (`resources/read`)? | [MCP `resources/read` boundary contract](reference/mcp-resources-read.md) |
| Which package protects my logs, traces, MCP server, or model context? What is stable and what is not? | [Integrations and release lifecycle](integrations.md) |
| Where does redaction belong in logging, tracing, or AI context? | [Reference architectures](guides/reference-architectures.md) |
| Which runtimes are supported, and which are not? | [Supported runtimes](getting-started.md#supported-runtimes) |
| How do I turn on PII detection, and what does "available" mean? | [Opt-in PII availability is not support](reference/detection.md#opt-in-pii-availability-is-not-support) |
| How do I detect an in-house credential format? | [Declarative rulesets](guides/rulesets.md) |
| How do I change what one kind of finding does without copying the default? | [Declarative action policy](guides/action-policy.md) |
| Which profile, PII selector, ruleset and isolation does each runtime support, and who owns the configuration? | [Detector capability and ownership matrix](reference/detector-capability-matrix.md) |
| How do I keep several configurations (PII selections, policies) in one deployment, and who owns what on each surface? | [Configuration ownership](guides/configuration-ownership.md) |
| Why did initialization or sanitization fail? | [Troubleshooting](troubleshooting.md) |
| How do I report a false positive or missed detection safely? | [Reporting guide](guides/reporting-detection-issues.md) |
| How do I contribute or run checks? | [Developer onboarding](onboarding.md) · [Contribution guide](../CONTRIBUTION.md) |
| How do I benchmark an unreleased local candidate? | [Local candidate benchmark](benchmark-candidate.md) |
| How do I prepare, publish, or recover a release? | [Release runbook](releasing.md) |

JavaScript, Rust, Python, and CLI standard input all support incremental
sanitization alongside whole-input operations. A `block` finding is replaced
in output, but your application must enforce rejection. An empty finding
list is not proof that input contains no secrets.

## Project internals and release evidence

- [Architecture](../ARCHITECTURE.md) and [architecture decisions](decisions/DECISIONS.md);
  [folded decision ids](decision-aliases.md) map a removed id to the record that carries it
- Current rules, one spec per area, each linking the decision that set it:
  [detector families](specs/detector-families.md),
  [contextual detection](specs/contextual-detection.md),
  [engine](specs/engine.md), [distribution](specs/distribution.md), and
  [evidence and gates](specs/evidence-and-gates.md)
- [Threat model](specs/threat-model.md): assets, attackers, data flow, and
  trust boundary for the deterministic core — not a rule-bearing spec;
  complements `ARCHITECTURE.md`'s security-boundaries section and `SECURITY.md`
- [Rust workspace](rust-workspace.md), [Python packaging](python-packaging.md),
  and [artifact qualification](qualification.md)
- [Detection coverage evidence](coverage/README.md)
- [Live contracts](contracts/README.md): CI-read inputs, kept outside the temporary review archive
- [Support matrix](support-matrix.md): per-family status (`stable` /
  `provisional` / `pending` / `unsupported`), generated from evaluation
  evidence in [`redact-secret-benchmarks`](https://github.com/redact-secret/redact-secret-benchmarks)
- [Detection reliability evidence](reference/detection-reliability.md)
- [Temporary review archive](audits/README.md), retired before release qualification, and [beta.2 final code review](https://github.com/redact-secret/redact-secret/blob/2816897f96c405c3eb8c87a0c70eba5df273c121/docs/audits/beta2-final-code-review.md)
- [Release records](releases/status.md): every published version and its durable record,
  stored per version under [`docs/releases/`](releases/)
- [Support-matrix drift gate](support-matrix-drift.md): the pre-release regression
  check between a baseline and candidate support matrix
- [Python repository redirect](python-repository-redirect.md) and
  [repository transfer runbook](repository-transfer-runbook.md)
- [Conformance fixture schema](../conformance/README.md),
  [cross-language evaluation protocol](../assessment/README.md), and
  [OpenGrep SAST baseline](../sast/README.md)
- [Repository conventions](../CONVENTIONS.md)
- [Changelog](../CHANGELOG.md), [security reporting](../SECURITY.md), and [MIT license](../LICENSE)
- [Documentation readiness and delivery follow-up](documentation-readiness.md)
- [v0.1.0 release-readiness checklist](releases/release-readiness-v0.1.0.md)

## Where a document or generated file belongs

[`decision-decide-artifact-taxonomy-spec-routing-and-evidence-placement`](decisions/2026-09-22-decide-artifact-taxonomy-spec-routing-and-evidence-placement.md)
gives every committed document or generated file under `docs/`, `assessment/`,
and `benchmarks/` exactly one kind, found by what reads or produces it, not by
its current path.
[`decision-retire-historical-audit-bodies-before-release-qualification`](decisions/2026-10-06-retire-historical-audit-bodies-before-release-qualification.md)
supersedes only that ADR's permanent retention of product-judgement evidence
and separates six kinds: current contract, live input, generated-and-checked
artifact, temporary review, historical judgement, and release record.

| Kind | Test | Location |
| --- | --- | --- |
| Live contract / input | CI, a script, or code reads it | a non-archive path (for example `docs/contracts/`) |
| Generated | a script produces it | committed only with a regeneration-equality test; otherwise gitignored |
| Temporary review (product judgement) | written during development; owner, reviewed source, status and retirement trigger in a front matter block | `docs/audits/` until retired, never past release qualification |
| Historical judgement | a temporary review that reached `final` | repository history, cited by a verified 40-hex main-commit permalink; current conclusions live in the spec, contract or release record, with no per-issue stub |
| Final evidence, benchmark measurement | a benchmark or scanner run produced it | `redact-secret-benchmarks`, per [`decision-govern-benchmark-regression-promotion`](decisions/2026-09-18-govern-benchmark-regression-promotion.md) |
| Iterative / exploratory log | only people read it, not a final record | an issue comment; final records keep a permalink to it, not a copy |
| Detail of a settled record | nothing reads the full text any more | a commit-pinned permalink plus a summary |
| Release record | one per version | `docs/releases/<version>/` |

These Markdown pages are the source documentation. Relative links and ordinary
code fences keep them usable in the repository and portable to a future public
delivery platform. During beta, each feature change updates the corresponding
Markdown guides. A separate web-app repository versus GitHub Wiki remains
undecided. No site generator or hosting account is required.
