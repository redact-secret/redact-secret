# Roadmap

What Redact Secret intends to do over the next year, and what it intends
not to do. Dates are targets, not promises. Issues and milestones are the
authoritative tracking; this page summarizes them and is reviewed at every
release. Last reviewed: 2026-10-07 against `0c62fd38` (the last published
version is `0.1.0-beta.14`, with its
[release record](docs/releases/0.1.0-beta.14/README.md); no release candidate is
pending). The Beta.13 epic status below is dated 2026-10-02 and was not
re-reviewed after beta.13 or beta.14 was published.

## Near term: stable `v0.1.0` (Q4 2026)

The Beta.13 epic ([#1065](https://github.com/redact-secret/redact-secret/issues/1065))
freezes the contract and proves stable-release readiness. State on
2026-10-02 (during the Beta.13 preparation; beta.13 has since been published),
with what was still open named:

- Freeze the stable public API, behavior, and extension contracts
  ([#1066](https://github.com/redact-secret/redact-secret/issues/1066)) and
  the declarative ruleset v1 contract
  ([#1072](https://github.com/redact-secret/redact-secret/issues/1072)).
  The contract is accepted as
  [Stable contract 1](docs/reference/api-contract.md#stable-contract-1) and the
  ruleset grammar is published. It takes effect for users at `0.1.0`; the
  evidence record still needs binding to the frozen candidate.
- Close detection qualification debt and publish the `v0.1.0` reliability
  contract ([#1067](https://github.com/redact-secret/redact-secret/issues/1067)).
  The reliability page stays a draft until it is bound to the frozen candidate.
  The custodian run for the public US SSN family is pending in
  `redact-secret/redact-secret-benchmarks#667`.
- Freeze and meet performance, memory, and artifact-size budgets
  ([#1068](https://github.com/redact-secret/redact-secret/issues/1068)). The
  30 optimization and research cards in this repository are closed. The
  thresholds, the performance evaluation and the verdict belong to
  `redact-secret-benchmarks` and are not yet recorded for a candidate.
- Qualify and rehearse the exact `v0.1.0` artifact and release path
  ([#1069](https://github.com/redact-secret/redact-secret/issues/1069)).
  Not done: it needs the frozen candidate.
- Finish stable user documentation and five-minute adoption paths
  ([#1070](https://github.com/redact-secret/redact-secret/issues/1070)). The
  documentation changes are merged; delivery-platform work (D1 to D3 in
  [documentation readiness](docs/documentation-readiness.md)) is still pending.
- A final go/no-go review
  ([#1071](https://github.com/redact-secret/redact-secret/issues/1071)).
  Not started; it needs the items above.

## Next: detector coverage (Beta.14 and after)

The published `0.1.0-beta.14` carries the Buildkite, Fly, Mapbox, Pydantic
Logfire, Sourcegraph, Square, Unkey, and Xata detectors, which have no support
status until their benchmarks arrival evidence lands. Next, add the remaining
provider families researched under
[#1014](https://github.com/redact-secret/redact-secret/issues/1014) and
[#860](https://github.com/redact-secret/redact-secret/issues/860) (Ory and
others), each with synthetic conformance fixtures and stated false-positive and
false-negative trade-offs. Move opt-in structured PII families from
`provisional` toward `stable` as their evidence qualifies.

## Later in the year

- **Contribution funnel** ([#999](https://github.com/redact-secret/redact-secret/issues/999)):
  role-based contribution docs, a detector scaffolding command, and guided
  contribution-readiness output in CI, without weakening evidence gates.
- **Edge runtimes** ([#1000](https://github.com/redact-secret/redact-secret/issues/1000)):
  qualify and harden the WebAssembly build for edge and worker runtimes.
- **Deployment modes** ([#1001](https://github.com/redact-secret/redact-secret/issues/1001)):
  research a sidecar or proxy mode for runtime redaction.
- **Vault contract** ([#1002](https://github.com/redact-secret/redact-secret/issues/1002)):
  define a persistent vault contract without coupling the core to a database
  or KMS.
- **Supply chain**: keep OpenSSF Best Practices and Scorecard results current,
  sign every published artifact, and publish SBOMs with releases.

## Not planned

These stay out of scope (see [ARCHITECTURE.md](ARCHITECTURE.md#deliberate-exclusions)):
checking whether a credential is live, network access or telemetry in the
core, storing secrets, and acting as a complete data-loss-prevention product.

## Proposing changes

Open an [idea discussion](https://github.com/redact-secret/redact-secret/discussions)
or an issue. Roadmap changes are decided as described in
[GOVERNANCE.md](GOVERNANCE.md#how-decisions-are-made).
