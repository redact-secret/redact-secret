# Redact Secret documentation

Redact Secret finds supported credential patterns in text and replaces them
before the text reaches logs, storage, tools, or model context. JavaScript,
Python, Rust, and the CLI share one deterministic Rust implementation.

## Get started

1. [Installation and source setup](getting-started.md): choose your runtime.
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
| Why did initialization or sanitization fail? | [Troubleshooting](troubleshooting.md) |
| How do I contribute or run checks? | [Developer onboarding](onboarding.md) · [Contribution guide](../CONTRIBUTION.md) |
| How do I benchmark an unreleased local candidate? | [Local candidate benchmark](benchmark-candidate.md) |
| How do I prepare, publish, or recover a release? | [Release runbook](releasing.md) |

JavaScript, Rust, Python, and CLI standard input all support incremental
sanitization alongside whole-input operations. A `block` finding is replaced
in output, but your application must enforce rejection. An empty finding
list is not proof that input contains no secrets.

## Project internals and release evidence

- [Architecture](../ARCHITECTURE.md) and [architecture decisions](decisions/DECISIONS.md)
- [Rust workspace](rust-workspace.md), [Python packaging](python-packaging.md),
  and [artifact qualification](qualification.md)
- [Detection coverage evidence](coverage/README.md)
- [Support matrix](support-matrix.md): per-family status (`stable` /
  `provisional` / `pending` / `unsupported`), generated from evaluation
  evidence in [`redact-secret-benchmarks`](https://github.com/redact-secret/redact-secret-benchmarks)
- [Detection reliability evidence](reference/detection-reliability.md)
- [Review archive](audits/README.md) and [beta.2 final code review](audits/beta2-final-code-review.md)
- [Changelog](../CHANGELOG.md), [security reporting](../SECURITY.md), and [MIT license](../LICENSE)
- [Documentation readiness and delivery follow-up](documentation-readiness.md)

These Markdown pages are the source documentation. Relative links and ordinary
code fences keep them usable in the repository and portable to a future public
delivery platform. During beta, each feature change updates the corresponding
Markdown guides. A separate web-app repository versus GitHub Wiki remains
undecided. No site generator or hosting account is required.
