# Architecture decisions

These records preserve accepted project-wide choices. They provide context for
future planning and implementation but do not authorize Git or release actions.

Generated from each record's `spec:` field by `python3 -B scripts/generate-decisions-index.py`; do not edit by hand.
Each spec file under `docs/specs/` states the current rules and links the records
that decided them.

## Detector families

Current rules: `docs/specs/detector-families.md`.

- [Freeze reviewed precision contracts for seven provider families and refine their default rules in place](2026-09-17-freeze-precision-contracts-for-seven-provider-families.md)
- [Map GitHub's six token families onto six independent finding types under one detector](2026-09-20-map-github-token-families-onto-independent-finding-types.md)
- [Redact a bare, marker-less OpenAI-prefixed value under a generic policy layer, beneath the frozen contract](2026-09-21-govern-bare-vendor-prefixed-policy-layer.md)
- [Claim a legacy Pinecone UUID key only under a Pinecone API-key name, and redact it](2026-09-24-claim-a-legacy-pinecone-uuid-key-only-under-its-api-key-name.md)
- [Redact a Google API key inside a Firebase Web SDK client config, reversing the client-config exemption](2026-09-24-redact-google-api-keys-inside-firebase-web-config.md)

## Contextual detection

Current rules: `docs/specs/contextual-detection.md`.

- [Exclude a value fully delimited by `{{` and `}}` as a template reference](2026-09-15-exclude-fully-delimited-template-references.md)
- [Warn unconditionally on high-signal contextual-name assignments despite prose false positives](2026-09-20-warn-unconditionally-on-high-signal-contextual-names.md)

## Engine

Current rules: `docs/specs/engine.md`.

- [Adopt a Rust-core monorepo](2026-09-09-adopt-rust-core-monorepo.md)
- [Define runtime bindings](2026-09-09-define-runtime-bindings.md)
- [Govern cross-language conformance](2026-09-09-govern-cross-language-conformance.md)
- [Define the detector profile and pack contract](2026-09-18-define-detector-profile-and-pack-contract.md)
- [Bound whole-input operations by default](2026-09-19-bound-whole-input-operations-by-default.md)
- [Define the declarative detector ruleset contract](2026-09-19-define-declarative-detector-ruleset-contract.md)
- [Normalize invisible characters before detection](2026-09-19-normalize-invisible-characters-before-detection.md)
- [Resolve overlap precedence by resolved-action severity](2026-09-19-resolve-overlap-precedence-by-resolved-action-severity.md)
- [Select optimal disjoint candidates by total evidence weight](2026-09-19-select-optimal-disjoint-candidates-by-total-evidence-weight.md)
- [Defer encoded-input decoding out of scope, with reasoning](2026-09-20-defer-encoded-input-decoding.md)

## Distribution

Current rules: `docs/specs/distribution.md`.

- [Release bindings in lockstep](2026-09-09-release-bindings-in-lockstep.md)
- [Adopt the Redact Secret naming contract](2026-09-10-adopt-redact-secret-naming-contract.md)
- [Ship the first release's full artifact set](2026-09-10-ship-first-release-artifact-set.md)
- [Add a Node WebAssembly fallback when the native addon is unusable](2026-09-19-add-node-webassembly-fallback.md)
- [Graduate logging and tracing adapters to a separate repository](2026-09-19-graduate-adapters-to-a-separate-repository.md)
- [Verify @redact-secret/core on Cloudflare Workers and Vercel Edge](2026-09-19-verify-edge-runtimes.md)

## Evidence and gates

Current rules: `docs/specs/evidence-and-gates.md`.

- [Pin OpenGrep and establish a reviewed SAST baseline](2026-09-10-pin-opengrep-and-establish-a-reviewed-sast-baseline.md)
- [Define the cross-language evaluation protocol](2026-09-12-define-cross-language-evaluation-protocol.md)
- [Measure JavaScript performance externally](2026-09-12-measure-javascript-performance-externally.md)
- [Gate beta.5 on precision gains and positive preservation](2026-09-18-gate-beta5-on-precision-gains-and-positive-preservation.md)
- [Govern benchmark-originated product regressions](2026-09-18-govern-benchmark-regression-promotion.md)
- [Resolve real-looking twin fixtures as unmistakably synthetic](2026-09-18-resolve-real-looking-twin-fixtures-as-unmistakably-synthetic.md)
- [Gate release qualification on support-matrix drift, with recorded acknowledgement to override](2026-09-21-gate-releases-on-support-matrix-drift.md)
- [Decide the artifact taxonomy, spec routing, and evidence placement](2026-09-22-decide-artifact-taxonomy-spec-routing-and-evidence-placement.md)
- [Move performance results, criteria, and judgement to redact-secret-benchmarks](2026-09-22-move-performance-results-criteria-and-judgement-to-benchmarks.md)
