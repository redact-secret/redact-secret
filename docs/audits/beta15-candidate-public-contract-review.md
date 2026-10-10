---
owner: '#1320'
reviewed_source: ca09aeb6bb360aed20914e475230836250e2759a
status: retained
retire_on: after-release:0.1.0-beta.15
candidate_version: 0.1.0-beta.15
review_scope: public-api-and-compatibility
disposition: accepted-with-limitations
limitations: Source/API review only; exact final merged-source artifact, performance, memory, size, SAST and package rehearsal gates remain pending. PII qualification remains pending/unmet where recorded, with no recall-expansion or stable-status claim. Python/CLI configuration selection and comparison, custom native artifacts, incremental rulesets and same-runtime independent scanner handles remain unsupported. Beta.15 is an unpublished candidate and this review does not authorize publication.
---

# Beta.15 candidate public-contract review

The candidate public API is accepted with the compatibility and qualification
limits below. This reviews the actual changes from released
`v0.1.0-beta.14` (`0c62fd38bca75c5b28b042dc79789b708ebf1d17`) to the
`reviewed_source` above, plus the preparation of lockstep `0.1.0-beta.15`.
It is not installed-artifact evidence or release approval. A later source
change requires review of its delta and qualification of the final merged SHA.

## Public surface reviewed

- Rust: compared the crate-root exports and workspace `core-public-api` list,
  registry/profile/error contracts, incremental constructors, configuration
  resolver, artifact manifest, comparison and static composition. The root
  inventory grows from 72 to 95 names; none is removed. The 23 additions are
  `ArtifactKind`, `ArtifactManifest`, `ArtifactManifestError`, `ConfigDiagnostic`,
  `ConfigRequest`, `ConfigResolution`, `ConfigSeverity`, `ConfigSnapshot`,
  `ConfigurationComparison`, `ConfigurationDifference`,
  `ConfigurationDifferences`, `ConfigurationResult`, `ConfigurationSide`,
  `Correspondence`, `DetectionConfigError`, `DetectionSelection`,
  `DifferenceKind`, `SampleRuleHits`, `SideStatus`, `compare_configurations`,
  `composition`, `describe_config` and `resolve_config`. The public methods on
  these types and the added registry/session constructors are also part of the
  review; the root-name count is not a count of all public methods. The private
  `CHANGE_NAMES` constant is not a new export.
- JavaScript: compared `index.ts`, `common.ts`, the shared type re-exports,
  `types.ts`, errors, formatters, runtime and Node/WASM bridges against the tag,
  and inspected exact-export and type-contract tests. Both standard entries add
  `artifactManifest`, `resolveConfig`, `describeConfig` and
  `compareConfigurations`, with readonly manifest/configuration/comparison types.
  `initialize` gains `detection`; stream subpaths retain their factory surface.
- Python: compared `__all__`, native imports and `_native.pyi`. The public
  addition is `artifact_manifest() -> dict[str, Any]`; no detector-selection,
  configuration resolver, comparison or independent scanner handle is exposed.
  Existing scan, policy, formatter and incremental signatures are retained.
- CLI: compared argument parsing, help and dispatch. The new standalone
  `--print-artifact-manifest` prints one JSON line without reading input; other
  arguments are rejected. Existing scan/redact/policy comparison flags, JSON
  reports and exit codes retain their contract. Runtime detector selection and
  configuration comparison are not CLI features.

## Compatibility and migration

1. Default initialization keeps all included detectors enabled and PII off.
   Detector selection narrows a registry before prefiltering and overlap
   resolution; it is fixed at owner/session construction, not a per-call setter.
   Equivalent initialization is idempotent; a differing detector selection is
   `DETECTION_CONFIG_CONFLICT`, and a conflict changes nothing. An allowlist does
   not automatically enable detectors added in a later release; a denylist does.
   Own per-call `detection` keys now fail with `INVALID_OPTIONS` rather than being
   silently ignored, including a key whose value is `undefined`.
2. Incremental `ruleset` keys now fail synchronously with `INVALID_OPTIONS` after
   initialization, including inherited keys and `undefined`, before allocating
   a session or reading the value/getter. Before initialization,
   `NOT_INITIALIZED` takes precedence. Beta.14 ignored these unsupported keys;
   structurally typed shared option variables may therefore require migration.
   Public Node/Web stream factories forward the options and have the same
   creation-time failure. Whole-input rulesets and incremental `actionPolicy`
   remain supported; the streaming guide gives both migrations and error handling.
3. Rust `SecretScanErrorCode::ALL` changes from `[Self; 23]` to `[Self; 26]`.
   Consumers explicitly requiring the old array length must adapt. Added codes
   are `INVALID_DETECTION_CONFIG`, `DETECTION_CONFIG_CONFLICT` and
   `EMPTY_DETECTION_SET`. Existing code/message pairs are preserved. Both the
   error enum and `Profile` were already `non_exhaustive`; `Profile::Custom` is
   an output identity, not a selectable `from_name` value.
4. JavaScript `CoreStatus.configuration` is a required readonly field whose
   value is `string | null`; `profile` widens to include `custom`. Runtime
   consumers accepting additional fields remain compatible, but user-created
   mocks, exact key assertions, narrower profile assignments and exhaustive
   error-code handling can need source changes. The new error-code union has
   the same three additions as the core.
5. `typedPlaceholderFormatter` now uppercases ASCII only, matching Rust.
   Built-in ASCII finding types retain output; custom non-ASCII finding types
   can produce different placeholders. This is an intentional parity fix.
6. `runtime-config/v1` and an omitted schema retain open-vocabulary diagnostics.
   Only explicitly tagged `runtime-config/v2` accepts `closedTypes` and
   `closedDetectors`; an absent list preserves warnings and an explicit list
   enables strict preview validation. A preview does not change later scans or
   enforce a reviewed policy. Host-shape mistakes may throw `INVALID_OPTIONS`;
   resolved configuration problems are bounded diagnostics with `ok: false`.

These are concrete migration costs, not a claim that every source-level use of
beta.14 is unchanged. No removed public entry or changed supported legacy call
signature was found. Detector additions and reviewed carrier fixes intentionally
change findings; configuration selection can intentionally change overlap winners.

## Changelog and documentation alignment

The candidate changelog must identify manifest/configuration/diagnostic/custom
composition/comparison additions, Ory and Baseten detector grammars, curl carrier
support, incremental option rejection and the formatter parity fix. The public
contract, action-policy, configuration and streaming guides explain owner-bound
selection, preview-only comparison, strict v2 validation and unsupported surfaces.
Preparation corrected the Rust root-name count, removed the private
`CHANGE_NAMES` from the public-name list, scoped JavaScript strict validation
to v2, and stated the JavaScript manifest initialization prerequisite. The
changelog also states the Rust error-array and TypeScript status migrations.

JavaScript manifest inspection requires successful `initialize()` to load the
artifact; the inspection itself changes no activation. Raw manifest inspection
on Rust/Python/CLI does not require activating PII. Manifest digests bind version
and artifact content and are not promised stable across releases.

PII regression fixtures and active evidence dispositions do not establish a
recall expansion: existing reserved-value suppression, supported context/grammar
and decoding exclusions remain. No payment-card, IBAN or network evidence gain
is claimed. PII qualification gates remain pending/unmet where the current
qualification record says so; neither passing regression tests nor unchanged
paired metrics promotes those families to stable.

The accepted #1222 documentation-only outcome remains: Rust registry values and
Node Worker/WASM-instance/Python-process recipes are the supported ownership
paths. Preview registries are not reusable independently configured scanner
handles. JFrog bare `AKCp` reader #1248 and memory hygiene #1090 remain deferred;
the candidate makes no new zeroization claim.

## Qualification and lifecycle

This source review does not establish installed package parity, final-candidate
performance, memory or artifact sizes, production Workers deployment, other
browser support, or a successful publication. Custom composition supports the
generated WebAssembly artifact; custom Node/Python/CLI artifacts remain
unsupported. Local Chromium/workerd evidence is scoped to those tested runtimes.
Final qualification must bind the merged source, candidate version, conformance
corpus and artifact identities, and require accepted benchmark verdicts or an
explicitly accepted tradeoff. Historical measurements are not final-SHA receipts.

`scripts/release_review_identity.py` selects this review only for
`candidate_version: 0.1.0-beta.15`, requires the correct scope/disposition and
retained lifecycle, and verifies that `reviewed_source` is an ancestor of the
qualified source. The beta.14 release record cannot satisfy this beta.15 review.
The inventory still records `reviewAuthorizesRelease: false`. Keep beta.15
described as unpublished until separate post-test release approval and successful
publication. After publication, move current conclusions to the durable release
record and retire this body only after verifying its complete main permalink.
