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

1. [Five-minute quickstart](quickstart.md): install the published package in an
   empty project and redact one value with Node.js, Python, or a browser bundler.
   [Installation and source setup](getting-started.md) covers every runtime.
2. Follow a guide: [JavaScript](guides/javascript.md), [Python](guides/python.md),
   [Rust](guides/rust.md), or [CLI](guides/cli.md).
3. Read [policy and safe integration](guides/safe-integration.md) before sending
   output downstream.

| Question | Read |
| --- | --- |
| What does a finding mean? Which offsets does it use? | [API concepts](reference/api-contract.md) |
| What credentials can be detected, and what can be missed? | [Detection and limits](reference/detection.md) |
| What did the bounded reliability assessment observe? | [Detection reliability](reference/detection-reliability.md) |
| Can I process a stream? | [Streaming](guides/streaming.md) |
| What must an AI-context integration guarantee? | [AI-context boundary contract](reference/ai-context-boundary.md) |
| What may an MCP integration claim, and which tool-call points must it protect? | [MCP redaction boundary contract](reference/mcp-boundary.md) |
| Where does redaction belong in logging, tracing, or AI context? | [Reference architectures](guides/reference-architectures.md) |
| How do I detect an in-house credential format? | [Declarative rulesets](guides/rulesets.md) |
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
- [Rust workspace](rust-workspace.md), [Python packaging](python-packaging.md),
  and [artifact qualification](qualification.md)
- [Detection coverage evidence](coverage/README.md)
- [Live contracts](contracts/README.md): CI-read inputs, kept outside the frozen evidence archive
- [Support matrix](support-matrix.md): per-family status (`stable` /
  `provisional` / `pending` / `unsupported`), generated from evaluation
  evidence in [`redact-secret-benchmarks`](https://github.com/redact-secret/redact-secret-benchmarks)
- [Detection reliability evidence](reference/detection-reliability.md)
- [Review archive](audits/README.md) and [beta.2 final code review](audits/beta2-final-code-review.md)
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
its current path:

| Kind | Test | Location |
| --- | --- | --- |
| Live contract / input | CI, a script, or code reads it | a non-archive path (for example `docs/contracts/`) |
| Generated | a script produces it | committed only with a regeneration-equality test; otherwise gitignored |
| Final evidence, product judgement | an ADR or release relies on it | `docs/audits/evidence/<issue>/`, frozen |
| Final evidence, benchmark measurement | a benchmark or scanner run produced it | `redact-secret-benchmarks`, per [`decision-govern-benchmark-regression-promotion`](decisions/2026-09-18-govern-benchmark-regression-promotion.md) |
| Iterative / exploratory log | only people read it, not a final record | an issue comment; final records keep a permalink to it, not a copy |
| Detail of a settled record | nothing reads the full text any more | a commit-pinned permalink plus a summary |
| Release record | one per version | `docs/releases/<version>/` |

These Markdown pages are the source documentation. Relative links and ordinary
code fences keep them usable in the repository and portable to a future public
delivery platform. During beta, each feature change updates the corresponding
Markdown guides. A separate web-app repository versus GitHub Wiki remains
undecided. No site generator or hosting account is required.
