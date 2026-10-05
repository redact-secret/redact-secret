# Engine

Rules governing the shared Rust core's detection pipeline, plugin/profile contract, and cross-language binding architecture.

> Generated for [issue #597](https://github.com/redact-secret/redact-secret/issues/597) (DS6a). Each rule
> below states current behavior in the present tense and links the ADR
> (`docs/decisions/`) that decided it. An ADR records why and when; this file
> records what is true now. Per
> [`decision-decide-artifact-taxonomy-spec-routing-and-evidence-placement`](../decisions/2026-09-22-decide-artifact-taxonomy-spec-routing-and-evidence-placement.md),
> a decision that applies an existing policy to one more provider family or
> one more instance is a row here plus its supporting evidence, not a new
> ADR.

## Rules

| Rule | Governing ADR |
| --- | --- |
| One Rust core crate is shared by every language binding (JavaScript, Python, CLI) through a monorepo layout. | [Adopt a Rust-core monorepo](../decisions/2026-09-09-adopt-rust-core-monorepo.md) |
| Each language binding is a thin host adapter over the shared Rust core, not an independent reimplementation. | [Define runtime bindings](../decisions/2026-09-09-define-runtime-bindings.md) |
| Every binding is held to the same conformance corpus so detection behavior does not drift by language. | [Govern cross-language conformance](../decisions/2026-09-09-govern-cross-language-conformance.md) |
| Detector selection is scoped by a profile/pack contract (for example `full`, `common`), not by ad hoc per-caller filtering. | [Define the detector profile and pack contract](../decisions/2026-09-18-define-detector-profile-and-pack-contract.md) |
| Exactly two profiles exist, `full` and `common`. The contract's named-pack triggers were revisited at 110 built-ins and 159,403 B of `full` brotli WebAssembly: no provider group is worth 10% of that size (the largest, cloud, is 7.5%) and no issue names a consumer and budget, so no third profile is added. A new profile needs both, measured as in the #1128 evidence record (`docs/audits/evidence/1128`). | [Define the detector profile and pack contract](../decisions/2026-09-18-define-detector-profile-and-pack-contract.md) |
| Whole-input scan and redact operations carry an explicit default bound on buffered bytes and finding count, overridable by the caller. | [Bound whole-input operations by default](../decisions/2026-09-19-bound-whole-input-operations-by-default.md) |
| An organization may register additional detectors through a declarative ruleset contract; this narrows, but does not replace, the profile/pack contract's Non-goal on dynamic plugin loading. | [Define the declarative detector ruleset contract](../decisions/2026-09-19-define-declarative-detector-ruleset-contract.md) |
| The 0.1.x public contract sorts every surface into stable, experimental, internal or excluded. A breaking change to a stable surface bumps the minor version while the major version is 0; additive and behavioral changes ship in patch releases. Finding `type`/`detector` strings and error codes are open sets whose unknown values a consumer treats as a failure; `Action`, `Confidence` and `Specificity` are closed by design; CLI statuses other than 0, 1 and 2 are internal failures. Python `ScanResult.findings` stays a `list` in 0.1.x; a `tuple` would be a breaking change. | [Define the 0.1.x stable public contract and its compatibility classes](../decisions/2026-10-02-define-the-0-1-x-stable-public-contract-and-its-compatibility-classes.md) |
| `status()` (JavaScript root and `./common`; `redact_secret.status()` in Python) is the one side-effect-free, input-free lifecycle query: it reports `initialized`, `profile` and the activation identity (`null`/`None` before initialization) as fixed fields, never throws, and never loads or initializes. A core-published readiness probe is not provided; adapters keep their own synthetic probe. | [Add a side-effect-free status query and defer a published readiness probe](../decisions/2026-10-05-add-a-side-effect-free-status-query-and-defer-a-published-readiness-probe.md) |
| A thread-shareable registry is a distinct type, `BuiltInRegistry`: `Send + Sync`, built only from the `full` or `common` built-ins and an optional PII adapter, with no `register` and no custom detector or ruleset. It runs the same pipeline as `DetectorRegistry` and returns identical findings, order, ranges, output and error codes. `Detector` gains no `Send + Sync` bound and `DetectorRegistry` stays `!Send + !Sync`. | [Add a Send + Sync built-in-only registry as a distinct type](../decisions/2026-10-05-add-a-send-sync-built-in-only-registry-as-a-distinct-type.md) |
| Placeholder numbering restarts at 1 on every call. Request-wide unique numbering across the leaves of one request is a host recipe, not core API: a custom formatter returns the running offset plus `placeholder_index` and advances the offset by the last index a leaf used. `warn` and `allow` findings take no number, `block` does, identical values are numbered per occurrence, and one incremental session per streamed leaf uses the same recipe. No helper, option or request-scope type exists; the guides carry the recipe and a test per language proves it. | [Keep request-wide placeholder numbering a documented recipe, not a helper](../decisions/2026-10-05-keep-request-wide-placeholder-numbering-a-documented-recipe.md) |
| `ruleset-revision: 1` is frozen byte for byte. A new alphabet, validator, field or bound is revision 2; an unknown revision, field or vocabulary entry always fails closed; revisions coexist, and revision 1 is supported through the major series in which revision 2 ships and the next one. A ruleset detection stays `warn` under the default policy in 0.1.x. | [Define declarative ruleset revisioning and the revision 1 freeze](../decisions/2026-10-02-define-declarative-ruleset-revisioning.md) |
| Default-ignorable and other invisible Unicode code points are normalized out of the input before detection runs, using a generated table pinned to a fixed UCD version. | [Normalize invisible characters before detection](../decisions/2026-09-19-normalize-invisible-characters-before-detection.md) |
| When candidate findings overlap, the one with the more severe resolved policy action wins, not first-match or longest-match order. | [Resolve overlap precedence by resolved-action severity](../decisions/2026-09-19-resolve-overlap-precedence-by-resolved-action-severity.md) |
| Among overlapping candidates, the disjoint subset with the greatest total evidence weight is selected. | [Select optimal disjoint candidates by total evidence weight](../decisions/2026-09-19-select-optimal-disjoint-candidates-by-total-evidence-weight.md) |
| Base64, percent-encoded, and backslash-escaped input is not decoded before detection; decoding stays out of scope. | [Defer encoded-input decoding out of scope, with reasoning](../decisions/2026-09-20-defer-encoded-input-decoding.md) |
| A credential must be contiguous in the input bytes to be detected. One cut by a line break, a string-literal operator, a shell or language line continuation, a markdown line ending or escaped-newline text is outside the raw-input contract and is not reconstructed; the core does not interpret shell, string-literal, markdown or log escaping. A contextual detector may incidentally redact one fragment; that is not a claim to cover the credential. The support-scope inventory is redact-secret-benchmarks#622. | [Define a credential fragmented across lines, literals or continuations as outside the raw-input contract](../decisions/2026-10-04-define-fragmented-credentials-as-outside-the-raw-input-contract.md) |
| The core declares no `netrc`, kubeconfig, HTTP session-cookie, Azure SAS, S3-presigned or GCS-signed-URL family. A value in one is claimed only when a supported detector reads it independently (an assignment under a credential name, an `Authorization` carrier, a PEM block, an AWS access key id), and that claim is incidental. A base64 or hex carrier stays out of scope, `Authorization: Basic` is claimed without decoding, and a PEM block ends at its footer. A `(sensitive value)` Terraform marker, an `exa` placeholder and a PEM frame whose body is a placeholder name are not credentials. The out-of-scope inventory is redact-secret-benchmarks#622. | [Settle the structured-file, URL-carrier and control root causes that #1203 collected](../decisions/2026-10-04-settle-the-open-structured-file-url-carrier-and-control-roots-of-1203.md) |
| A token behind a percent-encoded delimiter (`%22`, `%3D`) is not read: the byte before it is a hex digit and percent-decoding stays out of scope, for every family. A JSON `{"name": ..., "value": ...}` object pair (HAR, Postman) and a credential name that keys an object whose `value` member holds the string (Terraform state outputs) are not assignments, and no HTTP session-cookie family is declared. A secret cut by a notebook `source` array element is a fragment, and a value ended by a JSON-escaped line break (`\n`) keeps the two escape bytes. A Compose `${NAME:?message}` message and a value equal to its own assigned name are not credentials. The out-of-scope inventory is redact-secret-benchmarks#622. | [Settle the root causes that credential-evidence snapshot-2026.10.04.4 added](../decisions/2026-10-05-settle-the-snapshot-2026-10-04-4-added-case-roots.md) |

| The beta.9 evidence scorer is shadow-only. It computes an internal integer evidence score and a shadow band (`none < low < medium < high`) for `contextual` and `entropy` candidates, and neither value is ever a probability. It never changes a candidate's `Confidence`, specificity, range, overlap weight or action, never removes a deterministic positive, and is not consulted for `private-key`, `provider` or `structural` candidates. | [Freeze the shadow evidence score and confidence contract](../decisions/2026-09-25-freeze-the-shadow-evidence-score-and-confidence-contract.md) |
| Evidence signals belong to five groups (`randomness`, `lexical`, `contextual`, `validation`, `negative`). A group's signals combine with halving diminishing returns under a cap, no single group and not `randomness` plus `lexical` can reach `high`, and negative evidence applies only when the whole value matches a reviewed exclusion grammar. The scorer is monotone in its signals. | [Freeze the shadow evidence score and confidence contract](../decisions/2026-09-25-freeze-the-shadow-evidence-score-and-confidence-contract.md) |
| Scorer arithmetic from features to band is integer fixed-point with no floating point or `libm` calls, so every host produces identical scores and bands. Maintainer diagnostics carry signal and group identifiers and integer values only, never matched bytes or hashes of them. No public item, field or benchmark projection carries a score, probability, threshold, weight or contribution (`scripts/check-rust-workspace.py` check 10), and changing the scoring model's identity invalidates evidence keyed to the old one. | [Freeze the shadow evidence score and confidence contract](../decisions/2026-09-25-freeze-the-shadow-evidence-score-and-confidence-contract.md) |
| The shadow scorer's `randomness` and `lexical` inputs are the integer statistical features of schema `evidence-features/v2`, defined exactly in the "Shadow evidence feature schema" (features 0 to 26) and "Shadow evidence residual features" (features 27 to 29) sections below. Extraction is not a detector: it reads at most 256 Unicode scalar values of one candidate value, allocates nothing, stores no part of the value, and changes no finding, `Confidence`, overlap weight or action. | [Freeze the shadow evidence score and confidence contract](../decisions/2026-09-25-freeze-the-shadow-evidence-score-and-confidence-contract.md) |
| The residual randomness features that feature schema `evidence-features/v2` appends to `v1` (the symbols no repetition, constant step or earlier copy predicts, and their Shannon and min-entropy) are defined in the "Shadow evidence residual features" section below. Extraction has the `v1` bounds and integer arithmetic. The reviewed model `evidence-aggregation/v3` reads the residual entropy (feature 28) as its only randomness signal, in place of Shannon entropy (#829). | [Freeze the shadow evidence score and confidence contract](../decisions/2026-09-25-freeze-the-shadow-evidence-score-and-confidence-contract.md) |
| The shadow scorer aggregates evidence under the reviewed model `evidence-aggregation/v3`, defined in the "Shadow evidence aggregation" section below: five groups with fixed caps, the halving rule inside each group, a strict whole-value exclusion grammar as the only negative evidence, and integer band thresholds. `private-key`, `provider` and `structural` candidates are never scored; their shadow band is their legacy `Confidence`. The model enforces nothing in beta.9. | [Freeze the shadow evidence score and confidence contract](../decisions/2026-09-25-freeze-the-shadow-evidence-score-and-confidence-contract.md) |
| The shadow scorer has one reviewed scoring artifact, `docs/contracts/scoring/shadow-scoring-artifact.json`, defined in the "Shadow scoring artifact" section below. It binds the feature schema, the aggregation model, calibration and tuning provenance, and the review method. CI fails when the artifact and the compiled scorer disagree in either direction, and when scorer values change under an unchanged model identity. It is a review and CI artifact: nothing loads it at runtime, no package ships it, and it is not public API. | [Freeze the shadow evidence score and confidence contract](../decisions/2026-09-25-freeze-the-shadow-evidence-score-and-confidence-contract.md) |
| The shadow scorer runs next to `generic-token`'s legacy decision without enforcing anything, defined in the "Maintainer-local shadow evaluation" section below. The pipeline evaluates the candidates that overlap resolution selects only when the maintainer-local evaluation path asks for it; every public entry point asks for nothing, so findings, `Confidence`, actions, overlap and every public API are unchanged and the scorer never runs on the public path. The path is an unpublished example that compiles the core's own source and writes JSON Lines holding identifiers and integers only, never matched bytes or hashes of them. | [Freeze the shadow evidence score and confidence contract](../decisions/2026-09-25-freeze-the-shadow-evidence-score-and-confidence-contract.md) |
| No shipped artifact links the shadow scorer: outside tests the incremental session calls `run_detector_pipeline` and, for a batch of closed lines, `detect_units`, both without a sink, so only the evaluation example and tests compile it. Its integer scores and bands are byte-identical on Linux, macOS, Windows and `wasm32` for the conformance corpora and a hostile battery (CI job `shadow-determinism`), no scorer source outside tests names floating point (`scripts/check-rust-workspace.py` check 11), and its worst cases are bounded by the 4,096-byte contextual value and the 256-symbol analysis limit. Defined in the "Shadow scorer qualification" section below. | [Freeze the shadow evidence score and confidence contract](../decisions/2026-09-25-freeze-the-shadow-evidence-score-and-confidence-contract.md) |
| The PII domain adapter keeps identity separate from sensitivity, enforces each context obligation and bounded negative transition, admits only sensitive outcomes to public overlap/policy, keeps evidence alternatives internal, and represents a sensitive ambiguous identity as one safe domain finding rather than multiple jurisdiction findings. Internal colon-form family ids map injectively to existing-grammar public types (`pii_global_email`, `pii_jurisdiction_us_ssn`, `pii_ambiguous_national_id`); the core identifier grammar does not change. No production family is registered by this substrate. | [Define the PII domain, scope, arbitration, and activation contract](../decisions/2026-09-26-define-the-pii-domain-scope-arbitration-and-activation-contract.md) |
| Before ordinary overlap resolution, same-range PII identities in one identity domain are reduced to one established or ambiguous internal candidate. Its confidence is the conservative minimum of identity and applicable sensitivity confidence, specificity is structural or contextual without claiming provider authority, obfuscation is the union of alternatives and normalization, and default severity/action still comes from `default_action_for(type, confidence)`. The aggregate then uses the existing ranked, optimal-disjoint overlap pipeline. | [Define the PII domain, scope, arbitration, and activation contract](../decisions/2026-09-26-define-the-pii-domain-scope-arbitration-and-activation-contract.md) |
| PII activation uses the accepted selector grammar, closure, registry composition, canonical activation identity, fixed safe errors, and equivalent target APIs across Rust, JavaScript, Python, and CLI. Credential `full`/`common` identity remains separate, PII defaults off, and unavailable selection fails closed. | [Define the PII domain, scope, arbitration, and activation contract](../decisions/2026-09-26-define-the-pii-domain-scope-arbitration-and-activation-contract.md) |
| Structured PII type checks use a crate-private, compile-time registry of bounded, versioned built-in validators. Validators return type evidence only, expose no callback or ruleset extension, and never decide sensitivity or policy. | [Define the bounded built-in structured-validator registry](../decisions/2026-09-26-define-the-bounded-built-in-structured-validator-registry.md) |
| The core's memory-lifetime contract is copy minimization plus bounded retention, never erasure. "Released" (the core dropped its owner) and "zeroized" (bytes overwritten by a write the optimizer cannot remove) are never interchangeable, no build zeroizes any buffer, and a zeroization claim needs a named mechanism, buffers, build mode and a test for every terminal incremental state. An incremental session owns no input-derived text after `finalize`, `abort` or any failure. Native Rust, CLI, Node, WebAssembly and Python are stated separately, and a change that adds an owned copy of input-derived text states its reason and updates the inventory (`docs/reference/plaintext-lifetime.md`, `docs/audits/evidence/1079/`). | [Define the plaintext memory-lifetime contract](../decisions/2026-09-30-define-the-plaintext-memory-lifetime-contract.md) |

## Structured PII validator foundation

The
[bounded built-in structured-validator registry](../decisions/2026-09-26-define-the-bounded-built-in-structured-validator-registry.md)
is a crate-private, compile-time foundation under the still-separate PII
evidence policy. It does not add a detector or make a PII support claim.

- A detector requests an exact validator `identity` and positive integer
  `version`. Successful evidence records that pair, so evaluation provenance
  cannot silently mix changed semantics under one identity.
- The initial contracts are `luhn` version 1 and `iban-mod97` version 1. Both
  use the same registry entry point. The registry is fixed at compile time:
  there are no user callbacks, scripts, runtime registration, or declarative
  ruleset v1 changes.
- Lookup occurs before candidate inspection. Each registration declares a
  byte limit (19 for Luhn, 34 for IBAN), oversized candidates fail before the
  algorithm runs, and accepted candidates take one bounded integer-only pass.
  The same Rust code is therefore used by native, Node, WebAssembly and Python
  artifacts without a host-specific copy.
- Failure is input-free and total: an unknown identity/version,
  `candidate-too-long`, malformed lexical shape, and checksum mismatch are
  distinct outcomes. No partial evidence is returned on failure.
- Validator success is type/identity evidence only. Sensitivity and context
  remain a later PII decision; checksum success alone never selects policy or
  proves that an occurrence is sensitive.

## Maintainer-local PII identity evaluation

Issue [#910](https://github.com/redact-secret/redact-secret/issues/910). A
public PII finding says only that the product decided an occurrence is
sensitive. Its absence does not say whether the family recognized the
authored value as a non-sensitive identity (an RFC 2606 domain, a NANPA
555-01xx line, an IANA documentation range), recognized it without
establishing sensitivity, or did not recognize it. The adapter holds that
distinction internally, and this evaluation path lets benchmarks measure it
without adding any public item.

`crates/secret-scan-core/examples/pii_identity_evaluation.rs` is outside the
published package. Like `shadow_evaluation`, it compiles the core's own source
files as modules of the executable, so it runs the product's family detector,
`pii-context/v2` vocabulary and join at the same commit rather than a
reimplementation:

```bash
cargo run --release --locked -p redact-secret --example pii_identity_evaluation -- \
  --family pii:global:email < cases.jsonl > identity.jsonl
```

- **Selection.** Exactly the family named by `--family` (one of the production
  families compiled into the build), vocabulary `pii-context/v2`, and the
  `full` credential profile's activation identity. An unknown or
  non-production family fails with exit status 2.
- **Input.** JSON Lines. Each line has exactly the keys `id`, `family` (equal
  to `--family`), `text`, and `candidate`, where `candidate` is
  `{"start": <utf8 byte>, "end": <utf8 byte>}` or `null`. The candidate is
  the benchmark's authored range, never product output. Malformed input fails
  with exit status 2. The error names the line number and key, never input
  content.
- **Output.** One header line
  `{"format": "redact-secret/pii-identity-evaluation/1", "family", "vocabulary", "activationIdentity"}`,
  then exactly one `{"id", "family", "identity", "sensitivity"}` line per
  input, in input order. `identity` is `established` or `unmatched`, and
  `sensitivity` is `sensitive`, `non-sensitive` or `not-established`. No line
  carries a confidence, specificity, obfuscation, score, threshold, feature,
  other alternative, other range, or any input text.
- **Semantics.** The family runs on the same scan copy as the public
  pipeline, with governed invisible code points removed and ranges translated
  back to the input. The line reports the alternative the join keeps for
  exactly the candidate range: the first established alternative whose
  translated range equals it. The pipeline drops some alternatives before
  overlap resolution: one from a family that rejects invisible normalization
  when it touches a removed run, and a known vendor placeholder literal. The
  evaluation reports none of those. A null candidate, a range no kept
  alternative has, or a range that is not a slice of `text` reads
  `unmatched` / `not-established`. The core has no invalid identity state, so
  an invalid lookalike and unrecognized text both read `unmatched`.
  Benchmarks keeps valid, invalid and not-established as authored truth and
  compares only `valid` with `established`.
- **Equivalence.** `sensitivity` is `sensitive` exactly when the public
  surface reports one finding of that family at exactly that range.
  `crates/secret-scan-core/tests/pii_identity_evaluation.rs` checks this for
  the built example over every character-boundary range, plus a null
  candidate, of every case in the six family conformance fixtures. It also
  pins the exact header and line key sets, checks that no line repeats an
  input, and checks that malformed input fails closed. The `pii::tests` unit
  tests cover, for each family, a synthetic positive, the authority-reserved
  benign control (for IBAN and US SSN, which reserve no non-sensitive
  `pii-v1` value, a valid identity without context), a one-property twin,
  email credential URI userinfo, and null or misaligned candidates.
  Benchmarks repeats the equivalence check against the installed Node and
  Wasm artifacts on every run.

## Shadow evidence feature schema

Schema identity **`evidence-features/v2`** (issues
[#769](https://github.com/redact-secret/redact-secret/issues/769) and
[#829](https://github.com/redact-secret/redact-secret/issues/829)). This
section defines features 0 to 26, the whole of `v1`; `v2` appends features
27 to 29, defined in "Shadow evidence residual features" below. The Rust
core is authoritative: `crates/secret-scan-core/src/evidence/features.rs`
(`extract_features`, `EvidenceFeatures::to_vector`, `FEATURE_NAMES`,
`FEATURE_SCHEMA_VERSION`) and `crates/secret-scan-core/src/evidence/fixed_point.rs`
(`log2_q16`, `permille`). Every item is `pub(crate)`; none is public API. The
benchmark-side candidate-feature dataset
([redact-secret-benchmarks#254](https://github.com/redact-secret/redact-secret-benchmarks/issues/254))
reproduces these definitions and records this identity. Changing a formula,
unit, bound, class boundary or the vector order below is a new identity,
and evidence keyed to `v1` is stale under it.

These features change no shipped behavior, so they carry no
false-positive or false-negative cost in beta.9. Their bounds are a
research trade-off: a value longer than 256 symbols is described by its
first 256 only, so repetition or randomness that appears later is invisible
to the features.

### Input, unit and bound

- The input is one candidate value as a Rust `&str` (for #771, the
  candidate's range in the scan copy, after invisible-character
  normalization). No decoding, case folding or Unicode normalization is
  applied.
- The **symbol** is the Unicode scalar value, the unit `shannon_entropy`
  already counts. A 2-, 3- or 4-byte UTF-8 sequence is one symbol.
- `s` is the first `min(total, 256)` symbols of the value; `n = |s|`.
  Truncation is by symbol, so it never splits a character. Lengths below
  are symbol counts unless named `byte_len`.
- Per-symbol counts `c_x` are taken over `s`. `d` is the number of distinct
  symbols, `c_max` the largest count.

### Arithmetic

Every value is an unsigned 32-bit integer and no floating point is used.
`floor(a / b)` is integer division rounding toward zero. `a ⊖ b` is
`max(0, a − b)`.

- **Q16** values are `real × 65536`.
- `permille(a, b) = floor(1000 × a / b)` computed in 64 bits, and `0` when
  `b = 0`.
- `log2_q16(x)` for `x ≥ 1` is this exact algorithm, and `log2_q16(0) = 0`.
  Its result is never above `log2(x) × 65536` and less than 2 below it.

```python
def log2_q16(x):
    if x == 0:
        return 0
    k = x.bit_length() - 1          # floor(log2 x)
    m = x << (32 - k)               # x / 2**k in Q32: 2**32 <= m < 2**33
    frac = 0
    for _ in range(16):
        m = (m * m) >> 32           # truncating square
        frac <<= 1
        if m >= 1 << 33:
            m >>= 1
            frac |= 1
    return (k << 16) | frac
```

Reference values: `log2_q16(3) = 103872`, `log2_q16(5) = 152169`,
`log2_q16(10) = 217705`, `log2_q16(62) = 390214`, `log2_q16(255) = 523917`.

### Character classes

| Class | Code points | Class alphabet size |
| --- | --- | --- |
| `lower` | `a`–`z` | 26 |
| `upper` | `A`–`Z` | 26 |
| `digit` | `0`–`9` | 10 |
| `symbol` | U+0021–U+007E that is not a letter or digit | 32 |
| `space_control` | U+0000–U+0020 and U+007F | 34 |
| `non_ascii` | U+0080 and above | the number of distinct non-ASCII symbols in `s` |

### Features, in vector order

| # | Name | Definition |
| --- | --- | --- |
| 0 | `byte_len` | UTF-8 byte length of the **whole** value, saturating at `2^32 − 1` |
| 1 | `analysed_chars` | `n` |
| 2 | `truncated` | `1` if the value has more than 256 symbols, else `0` |
| 3 | `distinct_symbols` | `d` |
| 4 | `max_symbol_count` | `c_max` (`0` when `n = 0`) |
| 5 | `shannon_entropy_q16` | `H = log2_q16(n) ⊖ floor(Σ_x c_x × log2_q16(c_x) / n)`, bits per symbol in Q16; `0` when `n = 0`. Same definition and counts as the legacy `f64` `shannon_entropy`, which never enters this value. |
| 6 | `min_entropy_q16` | `log2_q16(n) ⊖ log2_q16(c_max)`, bits per symbol in Q16 |
| 7 | `information_bits_q16` | `n × H`, estimated bits of information in Q16 |
| 8–13 | `class_lower`, `class_upper`, `class_digit`, `class_symbol`, `class_space_control`, `class_non_ascii` | number of symbols of `s` in each class |
| 14 | `class_count` | number of classes with a non-zero count |
| 15 | `class_transitions` | number of `i ∈ [1, n)` whose class of `s[i]` differs from the class of `s[i−1]` |
| 16 | `class_alphabet_size` | `A`: sum of the class alphabet sizes of the classes present |
| 17 | `entropy_efficiency_permille` | `min(1000, permille(H, log2_q16(d)))` when `d ≥ 2`, else `0` |
| 18 | `alphabet_efficiency_permille` | `min(1000, permille(H, log2_q16(A)))` when `A ≥ 2`, else `0` |
| 19 | `distinct_ratio_permille` | `permille(d, n)` |
| 20 | `length_permille` | `permille(n, 256)` |
| 21 | `longest_run` | length of the longest run of one repeated symbol (`0` when `n = 0`) |
| 22 | `adjacent_repeat_permille` | `permille(#{i ∈ [1, n) : s[i] = s[i−1]}, n ⊖ 1)` |
| 23 | `repeated_bigram_permille` | `permille(#{i ∈ [1, n−1) : ∃ j < i, (s[j], s[j+1]) = (s[i], s[i+1])}, n ⊖ 1)` |
| 24 | `smallest_period` | smallest `p ∈ [1, floor(n/2)]` with `s[i] = s[i+p]` for every `i ∈ [0, n−p)`, else `0` |
| 25 | `max_autocorrelation_permille` | `max_k permille(#{i ∈ [0, n−k) : s[i] = s[i+k]}, n − k)` over lags `k ∈ [2, min(32, floor(n/2))]`; `0` when there is no such lag. Lag 1 is `adjacent_repeat_permille`. |
| 26 | `max_autocorrelation_lag` | the smallest lag reaching feature 25 when it is non-zero, else `0` |

Work is bounded by `256²` symbol comparisons and fixed-size stack arrays,
whatever the value's length. The feature vector carries counts and ratios
only: no symbol, substring, class run or hash of the value
(`decision-freeze-the-shadow-evidence-score-and-confidence-contract`,
section 8).

### Golden vectors

The core's unit tests pin these, and an independent reimplementation
written from this page reproduces them. Values are synthetic.

| Input | Vector (features 0–26) |
| --- | --- |
| empty | all `0` |
| `aaaaaaaaaaaaaaaa` | `16,16,0,1,16,0,0,0,16,0,0,0,0,0,1,0,26,0,0,62,62,16,1000,933,1,1000,2` |
| `abcabcabcabcabcabc` | `18,18,0,3,6,103872,103872,1869696,18,0,0,0,0,0,1,0,26,1000,337,166,70,1,0,823,3,1000,3` |
| `XXXX-XXXX-XXXX-XXXX` | `19,19,0,2,16,41239,16248,783541,0,16,0,3,0,0,2,6,58,629,107,105,74,4,666,833,5,1000,5` |
| `Q7vK2mZp9LxR4tWb8NcY3hJd6FsG1eUa` | `32,32,0,32,1,327680,327680,10485760,12,12,8,0,0,0,3,31,62,1000,839,1000,125,1,0,0,0,0,0` |
| U+1F600 `a` U+1F603 `b`, twice | `20,8,0,4,2,131072,131072,1048576,4,0,0,0,0,4,2,7,28,1000,416,500,31,1,0,428,4,1000,4` |
| `ab` | `2,2,0,2,1,65536,65536,131072,2,0,0,0,0,0,1,0,26,1000,212,1000,7,1,0,0,0,0,0` |
| `aabc` | `4,4,0,3,2,98304,65536,393216,4,0,0,0,0,0,1,0,26,946,319,750,15,2,333,0,0,0,0` |

## Shadow evidence residual features

Issue [#829](https://github.com/redact-secret/redact-secret/issues/829).
These three features are the only difference between feature schema
**`evidence-features/v2`** and `v1`: `v2` is the `v1` vector above with
features 27 to 29 below appended, and features 0 to 26 keep their `v1`
definitions and positions. The Rust core is authoritative:
`crates/secret-scan-core/src/evidence/residual.rs`
(`extract_residual_features`, `RESIDUAL_FEATURE_NAMES`), with the same
input, symbol, 256-symbol bound and integer arithmetic as the section above.
Every item is `pub(crate)`; none is public API. The benchmark-side
candidate-feature dataset reproduces `v2` from this section.

`extract_features` appends these features to the `v1` vector
(`residual_features` over the same analysed symbols), and the reviewed
model below, `evidence-aggregation/v3`, reads feature 28 as its only
randomness signal. Like every feature, they change no finding,
`Confidence`, overlap weight or action.

### Why

The reviewed model's `randomness` group is a ramp over Shannon entropy per
symbol (feature 5). The attacker-known evaluation
([redact-secret-benchmarks#289](https://github.com/redact-secret/redact-secret-benchmarks/issues/289))
and #829 found two faults in that measure:

- it rates a benign periodic or sequence value as high as random material
  (`abcdefghijklmnopqrstuvwxyz` has about 4.7 bits per symbol, and
  `0123456789abcdef` twice has 4), so such a value in a credential-bearing
  context reaches the top band;
- it falls when repetition, padding or a period is inserted into real
  material, which is the first reshaping an attacker who has read the
  scorer would try.

The residual keeps only the symbols that no repetition, constant step or
earlier copy explains. A benign periodic or sequence value keeps a residual
of a few symbols, and inserting a run of one symbol adds at most one
residual symbol, so the residual entropy of reshaped random material stays
close to that of the original.

### Residual predictor

Position `i` of `s` is **predicted** when any of these holds, comparing code
points as unsigned integers:

1. repeat: `i ≥ 1` and `s[i] = s[i−1]`;
2. constant step: `i ≥ 2` and `s[i] + s[i−2] = 2 × s[i−1]` (runs, and
   ascending or descending sequences such as `abc`, `987`, `ace`);
3. constant step at lag 2: `i ≥ 4` and `s[i] + s[i−4] = 2 × s[i−2]`
   (interleaved sequences such as `aAbBcC`, `1a2b3c`);
4. context copy: `i ≥ 2` and some `j ∈ [2, i)` has
   `(s[j−2], s[j−1], s[j]) = (s[i−2], s[i−1], s[i])`: the two symbols before
   `i` were followed by `s[i]` before (tiled, copied and periodic bodies).

The **residual** is the subsequence of symbols at unpredicted positions, in
order, and `r` its length. Each rule reads only `s[i]` and the symbols
before it, so the residual of a prefix is a prefix of the residual. Work is
bounded by `256²` trigram comparisons.

### Features, in `v2` vector order

| # | Name | Definition |
| --- | --- | --- |
| 27 | `residual_symbols` | `r` |
| 28 | `residual_entropy_q16` | Shannon entropy of the residual: feature 5's formula over the residual symbol counts, with `r` in place of `n`; `0` when `r = 0` |
| 29 | `residual_min_entropy_q16` | `log2_q16(r) ⊖ log2_q16(c'_max)`, `c'_max` the largest residual symbol count; `0` when `r = 0` |

Golden values for the golden inputs of the section above, as features
27, 28, 29 (reproduced by an independent reimplementation written from this
page):

| Input | Features 27–29 |
| --- | --- |
| empty | `0,0,0` |
| `aaaaaaaaaaaaaaaa` | `1,0,0` |
| `abcabcabcabcabcabc` | `4,65536,65536` |
| `XXXX-XXXX-XXXX-XXXX` | `2,65536,65536` |
| `Q7vK2mZp9LxR4tWb8NcY3hJd6FsG1eUa` | `32,327680,327680` |
| U+1F600 `a` U+1F603 `b`, twice | `6,125718,103872` |
| `ab` | `2,65536,65536` |
| `aabc` | `2,65536,65536` |

### Measure choice and trade-offs

Feature 28, the residual's Shannon entropy, replaces feature 5 in the
`randomness` group of `evidence-aggregation/v3`. Feature 29 is the
min-entropy variant #829 also named. It is recorded for comparison and not
used: min-entropy
is set by the single most frequent symbol, so one inserted separator
repeated between blocks (not in runs, so every copy is residual) lowers it
by a bit or more while feature 28 moves by less than half a bit. The unit
tests pin that contrast, together with benign periodic and sequence values
whose residual is at most a few symbols and random material whose residual
entropy stays within half a bit under inserted runs and padding.

What the residual does not remove:

- mapping material into fewer character classes (all lower case, or
  digits) lowers every per-symbol measure, residual or not, because it
  removes information;
- a mirrored body is not a copy, so its second half stays residual (which
  keeps the measure high, not low);
- keyboard walks (`qwerty`) and other benign shapes that are not steps or
  copies stay residual;
- random material has a few accidental steps or trigram repeats, so its
  residual is slightly shorter than its length (at least 56 of 64 symbols in
  the unit tests).

The false-positive and false-negative effect depends on the ramp that reads
the feature, which the calibration fits; these features alone change no
shipped or shadow outcome.

## Shadow evidence aggregation

Model identity **`evidence-aggregation/v3`** over feature schema
`evidence-features/v2` (issues
[#770](https://github.com/redact-secret/redact-secret/issues/770) and
[#829](https://github.com/redact-secret/redact-secret/issues/829)). The Rust
core is authoritative: `crates/secret-scan-core/src/evidence/aggregate.rs`
(`SHADOW_MODEL`, `AggregationModel`, `aggregate`, `shadow_evidence`,
`halving_sum`, `EvidenceExplanation`), `evidence/context.rs`
(`context_class_of`) and `evidence/exclusion.rs` (`exclusion_grammar`).
Every item is `pub(crate)`; none is public API. This section applies the
existing contract
([`decision-freeze-the-shadow-evidence-score-and-confidence-contract`](../decisions/2026-09-25-freeze-the-shadow-evidence-score-and-confidence-contract.md),
sections 2 to 6) to one reviewed configuration. It is not a new decision.

The configuration is the one the benchmark calibration selected for #829
(redact-secret-benchmarks PR #437, merged to `develop` at
`5823751c16df4776035f5a0bd6f9640f8013a6a7`). Its method,
`calibration-experiments/2`, is stated in
[`docs/specs/calibration-experiments.md`](https://github.com/redact-secret/redact-secret-benchmarks/blob/5823751c16df4776035f5a0bd6f9640f8013a6a7/docs/specs/calibration-experiments.md)
and its context and negative classes in
[`docs/specs/candidate-features.md`](https://github.com/redact-secret/redact-secret-benchmarks/blob/5823751c16df4776035f5a0bd6f9640f8013a6a7/docs/specs/candidate-features.md).
It differs from `v2`, the #300 selection, only in the randomness signal:
the residual entropy replaces Shannon entropy per symbol, with its own
fitted ramp. The caps and bands are the ones the same selection rule chose
again.
The reviewed scoring artifact
([#798](https://github.com/redact-secret/redact-secret/issues/798), "Shadow
scoring artifact" below) records these values with drift detection. Changing any of them is a new model
identity, and evidence keyed to `v1` or `v2` is stale under it.

The values below are published on purpose. Redact Secret is open source,
the contract assumes an attacker has read the scorer, and security does not
depend on these weights and thresholds staying secret. What the benchmark
keeps out of its public projection (contract section 11) is a fitted map of
the decision boundary over its corpora, not these constants.

### Authority

`shadow_evidence` reads the candidate's effective specificity first. For
`private-key`, `provider` and `structural` it extracts no feature, records
`authority: deterministic`, and sets the band to the legacy `Confidence`
(`low`, `medium`, `high`). Statistical input cannot change that band. For
`contextual` and `entropy` (an unset specificity is `entropy`) it records
`authority: statistical` and evaluates the groups below.

### Groups, signals and caps

| Group | Signal | Points | Cap |
| --- | --- | --- | --- |
| `randomness` | `residual_entropy_q16` (feature 28) | ramp: `0` at or below `234123`, `30` at or above `263562`, otherwise `floor(30 * (R - 234123) / (263562 - 234123))` | 30 |
| `lexical` | none | `0` | 0 |
| `contextual` | `credential-context` | `50` when the context class is `credential-name`, `authorization-header` or `url-userinfo`, otherwise `0` | 50 |
| `validation` | none yet | `0` | 50 (placeholder, not fitted) |
| `negative` | `strict-exclusion` | `130` when the whole value matches the strict exclusion grammar, otherwise `0` | 130 |

The ramp ends are Q16 bits per residual symbol, about 3.57 and 4.02 bits.
Within
every group the contract's halving rule applies: signal points sorted in
descending order, the `k`-th (from `0`) counts `points >> k`, the sum
saturates and is then capped. A group with one signal is that signal's
points capped. The rule is general, so correlated signals added to a group
later still cannot add up linearly.

### Combination and bands

`score = max(0, randomness + lexical + contextual + validation - negative)`,
in saturating `u32` arithmetic. The band is `none` below `35`, `low` from
`35`, `medium` from `40` and `high` from `51`. So:

- context alone (`50`) is `medium`;
- randomness alone (at most `30`) stays below `low`;
- `high` needs context plus randomness of at least `1`;
- a strict exclusion match subtracts `130`, the sum of every positive cap,
  so it always floors the score at `0` (`none`).

These invariants are compile-time assertions on `SHADOW_MODEL`
(`AggregationModel::violation`): `0 < t_low < t_medium < t_high`; every
positive cap is below `t_high`; `cap_randomness + cap_lexical < t_high`;
the negative cap covers every positive cap; strict exclusion appears only in
the `negative` group, which holds nothing else; context signals appear only
in `contextual`. Unit tests check the contract's monotonicity rules
(section 4). The contract also allows `high` from `contextual` plus
`validation`. With the placeholder validation cap, a future validation
signal would make that reachable without randomness, so adding one needs a
refit and a new model identity.

### Contextual evidence class

The core does not re-parse the text around a candidate for this. It maps
the evidence the emitting detector already recorded, matched on the pair of
candidate type and internal signal label:

| Candidate type | Signal | Class |
| --- | --- | --- |
| `connection_string_password` | `credential-bearing-authority` | `url-userinfo` |
| `authorization_credential` | `authorization-<scheme>-scheme` | `authorization-header` |
| `bearer_token` | `bearer-scheme` | `authorization-header` |
| `contextual_secret` (specificity `contextual`) | `high-signal-name` or `ambiguous-name` | `credential-name` |
| anything else | | `bare` |

Divergences from the benchmark's `contextClass`:

- The benchmark classifies every span from up to 64 scalar values before it
  on its line, with its own coarse name-segment vocabulary. The core reuses
  `generic-token`'s name vocabulary (its high-signal and ambiguous names, and
  a ruleset's declared names), so the two agree on whether a name is
  credential-bearing only as far as those vocabularies overlap.
- `other-name` exists in the core's enum but no built-in detector emits a
  candidate for a non-credential assignment name, so the core never
  produces it. It scores like `bare`, as in the benchmark.
- `url-userinfo` and `authorization-header` come only from `structural`
  candidates, which are never scored. They are mapped so the class is
  complete, and they carry weight only if a later detector emits a
  `contextual` or `entropy` candidate in those positions.
- Any other candidate, including `generic-token`'s bare `sk-` policy
  candidates and ruleset value-pattern candidates, is `bare`, even when the
  benchmark would find an assignment name before it.

### Strict exclusion grammar

The `negative` group applies only when the **whole** candidate value is one
of these forms (`exclusion_grammar`), checked in order:

1. `template-reference`: `{{` … `}}` with no brace inside.
2. `environment-reference`: `${NAME}`, `${NAME:-default}`,
   `${NAME-default}` (no `}` in the default), `$NAME` or `%NAME%`, `NAME`
   being `[A-Za-z_][A-Za-z0-9_]*`.
3. `command-substitution`: `$(` … `)` with no parenthesis inside, or a
   backtick-delimited value with no backtick inside.
4. `angle-placeholder`: `<` `[A-Za-z0-9_ .-]+` `>`.
5. `mask`: three or more of one symbol from `* x X • # . - 0`.
6. `placeholder-vocabulary`: the lower-cased value split on `_`, `-`, `.`
   and whitespace gives only words from the benchmark's placeholder
   vocabulary, at least one of them a marker word.

A prefix, suffix, substring, edit-distance or other fuzzy resemblance never
matches: `EXAMPLE` followed by random material, a template reference next
to random material, or a mask around it are all positive-only. The
benchmark's `dotted-reference` class (`process.env.API_KEY`) is excluded on
purpose, because the same shape matches JWT-like and `SG.`-style
credentials. The benchmark also accepts a span that is the entire interior
of delimiters immediately around it on its line. The core does not: the
candidate value itself must be the whole delimited form, which is stricter.
Whitespace for word splitting is Rust's `char::is_whitespace`, which differs
from JavaScript's `\s` only at a few rare code points.

### Explanation

A statistical result carries an `EvidenceExplanation`: the model identity,
each group's signal identifiers and points, its uncapped halving sum and
capped contribution, the context class, the matched exclusion grammar, the
positive and negative totals, the score and the band. Every field is an
identifier from a closed static set or an integer. It holds no part of the
value, no class run and no hash (contract section 8), and it never reaches
a finding, error, log, placeholder or policy input.

### Cost and trade-offs

Aggregation reads the value once through feature extraction (bounded at
256 scalar values, no allocation) and one bounded grammar check, then does
a handful of integer operations. It runs only when the maintainer-local
evaluation path asks for it
([#771](https://github.com/redact-secret/redact-secret/issues/771),
"Maintainer-local shadow evaluation" below), never on a public entry point,
and it enforces nothing: it changes no finding, `Confidence`, overlap weight
or action, so it adds no false positive or false negative to shipped
behavior.

The selection generalizes poorly: its development medium-band balanced
error is `0.049172226340499135`, while evaluation balanced error is
`0.6244338423530675`, a gap of `0.5752616160125684`; the worst
leave-one-category-out balanced error is `0.6666666666666666`. Those results
are a limitation, not promotion evidence.

The randomness signal matters only at `high`. Randomness alone is capped
below `low`, and context alone reaches `medium`, so whether a candidate is
at least `medium` depends only on its context and the exclusion grammar.
Replacing Shannon entropy therefore changes which contextual candidates
reach `high`: benign periodic and sequence values in a credential-bearing
context, which reached `high` under `v2`, stay at `medium`, and inserted
repetition or padding no longer lowers random material from `high`. It
cannot change an outcome read at `medium`, including the future-promotion
Q4 projection of redact-secret-benchmarks#289, where a statistical
candidate without credential-bearing context never reaches `medium` under
either model. That Q4 failure is structural to this operating point, not to
the randomness measure. The scorer therefore remains
shadow-only, non-enforcing, absent from the public API, and incapable of
changing a finding, confidence, overlap weight, policy decision, or action.

## Shadow scoring artifact

The reviewed scoring artifact of the shadow scorer (issue
[#798](https://github.com/redact-secret/redact-secret/issues/798)) is
`docs/contracts/scoring/shadow-scoring-artifact.json`, format
`redact-secret/shadow-scoring-artifact/1`, validated against
`docs/contracts/scoring/shadow-scoring-artifact.schema.json`.
There is one artifact and it is the authoritative record of what the
compiled scorer is. This section applies the existing contract
([`decision-freeze-the-shadow-evidence-score-and-confidence-contract`](../decisions/2026-09-25-freeze-the-shadow-evidence-score-and-confidence-contract.md),
sections 8 to 11). It is not a new decision.

### What it binds

| Field | Content |
| --- | --- |
| `artifact` | `redact-secret/shadow-scoring-artifact` and an integer `revision` |
| `model.featureSchema` | the feature schema identity (`evidence-features/v2`), its bounds and fixed-point scale, the feature names in vector order, and the compiled feature vector of each golden input above |
| `model.aggregation` | the model identity (`evidence-aggregation/v3`) and every group, direction, rule, cap, signal rule, context class, exclusion grammar and vocabulary word, and the band thresholds, as the compiled `SHADOW_MODEL` holds them |
| `modelFingerprint` | SHA-256 of `model` as canonical JSON (keys sorted, no whitespace, UTF-8) |
| `identityLedger` | every model identity the artifact has recorded, each with the one fingerprint it stands for; append-only |
| `sources` | SHA-256 of the "Shadow evidence feature schema", "Shadow evidence residual features", "Shadow evidence aggregation" and "Maintainer-local shadow evaluation" sections of this page, and of `features.rs`, `residual.rs`, `fixed_point.rs`, `context.rs`, `exclusion.rs`, `aggregate.rs` and `shadow.rs` under `crates/secret-scan-core/src/evidence/` |
| `calibration` | the benchmark calibration run it came from (for `v3`, the #829 run merged in redact-secret-benchmarks PR #437): repository, issue, pull request, 40-hex `develop` commit, method permalink, selected configuration, selection method and source hash, feature dataset (extractor version, extractor source hash, dataset hash, the core commit its features were pinned to) and scoring identity with its component hashes |
| `corpora` | the benchmark pin manifest's hash and every tuning and evaluation corpus hash |
| `tuningManifest` | the redact-secret-benchmarks#256 tuning manifest: `pending` with `hash: null` until it is bound, plus the deterministic identity of its draft |
| `productRevision` | how a candidate's source commit is bound (below) |
| `knownLimitations` | limits a reviewer must weigh before any change (below) |
| `review` | how each part is generated, how the artifact is reviewed, and which checks enforce it |

The artifact records identities and hashes of benchmark evidence only. The
fitted per-configuration detail of the calibration run (curves, candidate
rows, other configurations' values) stays maintainer-local in
redact-secret-benchmarks and is never copied here or into the benchmark
repository's committed files.

### Not public API

The `use` block is fixed by the schema: `shadowOnly: true`, `enforcing:
false`, `publicApi: false`, no `findingFields`, `loadedAtRuntime: false`,
`shippedInPackages: false`, `runtimeLearning: false`,
`remoteCalibration: false`, `securityDependsOnSecrecy: false`. So:

- raw scores, weights, thresholds, calibration curves and contributions are
  not public API, and no finding gains a probability, score or contribution
  field (contract sections 2 and 9, `scripts/check-rust-workspace.py` check
  10);
- the scorer enforces nothing. Provider, private-key and structural
  evidence never reaches it (contract section 5), so reading the open
  source scorer, or this artifact, gives an attacker no way to downgrade
  that evidence;
- there is no runtime learning, remote calibration, mutable model file or
  user adaptation. The compiled constants are the model. No product code
  reads this file at runtime, and core source cannot (it may not name
  `std::fs` or `include_str!`). The maintainer-local evaluation example
  (below) reads only its `revision`, `modelFingerprint` and identities, to
  label its output and refuse a mismatched scorer.

The artifact is not secret, only not API. It lives under `docs/contracts/`
as a live contract (CI reads it). No package ships it: the npm package's
`files` is `dist`, `README.md` and `LICENSE`; the core crate's `include` is
`src/**/*.rs` and `README.md`; the Python wheel and source distribution
build from the crates and `bindings/python`. The drift check fails if a
package file list would pick it up. The compiled constants and the test
mirror below are Rust source, so they travel in the published crate source
like every other `pub(crate)` item, and none of them is public API.

### Drift detection

Core source may not read files, so the check has two halves that meet at
one literal, `REVIEWED_MODEL_JSON` in
`crates/secret-scan-core/src/evidence/aggregate/artifact_drift.rs`:

1. `cargo test` (`the_compiled_scorer_matches_the_reviewed_scoring_artifact`)
   renders the compiled `SHADOW_MODEL`, the feature schema constants, the
   golden feature vectors and the exclusion vocabulary, and requires the
   rendering to equal that literal byte for byte. A constant changed in Rust
   fails here, and the assertion prints the new rendering.
2. `npm run scoring-artifact:check` (`scripts/check-scoring-artifact.py`, in
   the offline `npm run ci`) validates the artifact against its schema and
   requires `model` to equal the literal, `modelFingerprint` to match
   `model`, the current model identity's ledger entry to carry that
   fingerprint, and every `sources` hash to match the tree. A value changed
   only in the artifact fails here.
3. On a pull request, the `scoring-artifact-identity` CI job runs the same
   check with `--base` set to the pull request's base commit. Any change to
   the artifact needs a higher `artifact.revision`; a changed `model` needs
   a new model identity; a changed `model.featureSchema` needs a new feature
   schema identity; and ledger entries from the base may not change or
   disappear.

So a constant changed with an unchanged model identity is an error at every
level: the test and the literal force the artifact to change, the ledger
rejects a new fingerprint for an old identity, and the base comparison
rejects rewriting that ledger entry.

### Change semantics

Any change to feature semantics, aggregation, groups, signals, weights,
caps, thresholds or bands is a new model identity (`evidence-aggregation/vN`),
and a change to feature semantics is also a new feature schema identity
(`evidence-features/vN`) (contract section 10). Any change to the artifact
at all, including a provenance update or a re-hashed source file, is a new
`artifact.revision`. Either one is a new candidate identity: beta.9
qualification, calibration and holdout evidence keyed to the old model
identity or artifact revision is stale and is regenerated, never carried
over. The benchmark side applies the same rule to tuning and holdout
evidence (redact-secret-benchmarks `docs/specs/statistical-tuning.md`,
section 4). An editorial change to a hashed source file changes no identity
in the model but still needs a new revision, so the reviewer confirms in
the pull request that it is editorial.

### Product source revision

The artifact cannot contain the commit that contains it. A candidate's
product revision is the commit it was built from, and its scoring artifact
is this file at that commit. The release manifest's `source_revision`
(`scripts/release-manifest.py`), the #256 tuning manifest's
`product.sourceRevision` and the beta.9 qualification record
([redact-secret-benchmarks#282](https://github.com/redact-secret/redact-secret-benchmarks/issues/282))
bind that commit. Evidence about a candidate records the commit together
with `artifact.revision`, `modelFingerprint` and the SHA-256 of this file
at the commit, and is stale for any candidate where one of them differs.

### Known limitations

- The `validation` group has no signal, and its cap of `50` is a
  placeholder that calibration did not fit. Context (`50`) plus validation
  (`50`) would reach `high` (`51`) without any randomness, so adding any
  validation signal needs a refit and a new model identity.
- The `lexical` group has no signal and a cap of `0`, because calibration
  selected randomness-only statistics. Adding a lexical signal is a new
  model identity.
- The #256 tuning manifest remains unbound with `product: null`. The artifact
  records the draft's deterministic identity and marks the binding `pending`;
  the final beta.9 qualification record therefore carries
  `tuningManifestHash: null`. This is an explicit provenance limitation, not
  an indication that the candidate or its qualification is missing. Binding a
  manifest later requires a new artifact revision and candidate identity.
- Randomness alone stays below `low` and context alone reaches `medium`, so
  no randomness signal can change an outcome read at `medium`. The
  future-promotion Q4 projection reads `medium`, and a statistical
  candidate without credential-bearing context never reaches it, so Q4
  cannot pass at this operating point whichever randomness measure the
  model uses (#829). Changing the operating point is a calibration decision
  and a new model identity.

## Maintainer-local shadow evaluation

Issue [#771](https://github.com/redact-secret/redact-secret/issues/771) runs
the shadow scorer next to `generic-token`'s legacy decision and defines the
one maintainer-local evaluation path the contract
([`decision-freeze-the-shadow-evidence-score-and-confidence-contract`](../decisions/2026-09-25-freeze-the-shadow-evidence-score-and-confidence-contract.md),
sections 2, 5, 8 and 9) allows. It applies that contract and is not a new
decision. The benchmark consumes it, first in
[redact-secret-benchmarks#289](https://github.com/redact-secret/redact-secret-benchmarks/issues/289)
and then in later benchmark evidence.

Final adversarial and release-candidate evidence is frozen in the
[beta.9 qualification record](https://github.com/redact-secret/redact-secret-benchmarks/blob/3fb195818eb31c481aaebc0257384386d17b2d7c/evidence/767/09e1d7f8/README.md)
for product source `09e1d7f85cd2ada9f387cc5c9beef3b29023d17d`. All four
attacker-known invariants held, but the future-promotion Q4 gate failed, so
the scorer remains shadow-only and non-enforcing. That record covers
`evidence-aggregation/v2`; evidence for `v3` (#829) is regenerated against
the product commit that carries it and is pending.

### Where the comparison is computed

`detect` in `crates/secret-scan-core/src/pipeline.rs` runs detection and
overlap resolution once. When its caller passes a sink, it then evaluates
every selected candidate with `shadow_evidence` under `SHADOW_MODEL`, from
the candidate and its matched text in the scan copy, and records a
`ShadowComparison` (`crates/secret-scan-core/src/evidence/shadow.rs`).
`run_detector_pipeline` passes no sink, and so do `scan`,
`scan_and_redact`, every binding and the incremental session, which all go
through it. So:

- the scorer is lazy: it runs only when the evaluation path asks. On every
  public path the added work is one `Option` check per call; the scorer
  and the renderer are never reached and allocate nothing. Performance and
  size are qualified in
  [#772](https://github.com/redact-secret/redact-secret/issues/772);
- findings, ids, ranges, `Confidence`, obfuscation, overlap resolution and
  the resolved action are the same with or without a sink. A candidate that
  loses overlap resolution is never evaluated;
- no comparison reaches a `Finding`, an error, a placeholder, a policy
  input or a log, and there is no telemetry.

The incremental session records the same comparisons, shifted to session
offsets and finding numbers, only under `cfg(test)`. Unit tests require
them to equal the whole-input comparisons for every chunking. The
evaluation path itself is whole-input.

With the built-in registries only `generic-token` emits `contextual` or
`entropy` candidates (its `contextual_secret` assignments and its bare
`vendor_prefixed_credential` policy candidates), so every `statistical`
record comes from `generic-token`. Every other finding gets a
`deterministic` record: the scorer is not consulted and the band is the
legacy `Confidence`.

### Why an example that compiles the core source

The scorer's items are `pub(crate)`, the core declares no Cargo features,
and no public Rust, JavaScript, Python or CLI item may carry a score or
band. The options were:

- **An unpublished crate that links the core.** It cannot name a
  `pub(crate)` item. Reaching the scorer would need a public item, and a
  `doc(hidden)` item is still public API.
- **A `cfg(test)` harness run with `cargo test -- --ignored`.** The core
  source boundary (`scripts/check-rust-workspace.py`) bans `std::io`,
  `std::env`, `std::fs` and `println!` in every file under `src/`, test
  modules included, so such a harness could read no input and write no
  output.
- **A benchmark-side reimplementation checked against golden vectors.** It
  would measure a copy, not the product. The context class comes from
  internal candidate types and signal labels that public findings do not
  carry, and the edge cases an evasion study probes (truncation at 256
  scalar values, Unicode whitespace in the exclusion grammar) are where a
  copy drifts.
- **Chosen: `crates/secret-scan-core/examples/shadow_evaluation.rs`.** It
  declares the modules of `src/lib.rs` with `#[path]` attributes, so it
  compiles the library's own source files, at the same commit, as modules
  of one executable, and can call `pub(crate)` items without any item
  becoming public. It runs the product's normalization, detectors, overlap
  resolution and scorer, not a copy. Like `assessment_adapter`, it is
  outside the published package (`include` is `src/**/*.rs` and
  `README.md`), it is the only part that does I/O, and it uses the existing
  `serde_json` dev-dependency. `cargo clippy --workspace --all-targets` and
  `cargo test --workspace` build it, so a core change that breaks it fails
  CI.

### Command

From a clean checkout of the product commit under evaluation:

```sh
cargo run --release --locked -p redact-secret --example shadow_evaluation -- \
  [--profile full|common] [--artifact <path>] < inputs.jsonl > shadow.jsonl
```

`--profile` selects the built-in registry (`full` by default, as
`DetectorRegistry::with_built_in([])`). `--artifact` defaults to
`docs/contracts/scoring/shadow-scoring-artifact.json` in the same checkout.
The run exits with status `2` on an unreadable or mismatched artifact, an
unknown argument or an invalid input line. The message names the line
number, never its content.

### Input

JSON Lines on standard input, one object per line. Blank lines are skipped
and other fields are ignored.

| Field | Type | Meaning |
| --- | --- | --- |
| `id` | string | the caller's record id, echoed as `input` |
| `text` | string | the whole input, scanned as `scan` would scan it |

A line that is not JSON in valid Unicode, for example one with a lone
UTF-16 surrogate escape, is rejected, because the core scans Rust `&str`.

### Output

JSON Lines on standard output. Fields are always written in the order
below, so the same product commit, artifact and input give the same bytes.
The first line is the header:

| Field | Value |
| --- | --- |
| `record` | `"shadow-evaluation"` |
| `format` | `"redact-secret/shadow-evaluation/1"` |
| `productVersion` | the core crate version |
| `model` | `SHADOW_MODEL.id`, `"evidence-aggregation/v3"` |
| `featureSchema` | `"evidence-features/v2"` |
| `artifactRevision` | `artifact.revision` of the artifact read |
| `modelFingerprint` | `modelFingerprint` of the artifact read |
| `profile` | `"full"` or `"common"` |
| `path` | `"whole-input"` |

The run refuses to start when the artifact's model or feature schema
identity differs from the compiled one. At a commit where CI passed, the
compiled scorer also equals the artifact's `model` exactly ("Drift
detection" above).

Then, for each input in input order, the default whole-input limits are
checked as `scan` checks them. On success there is one `shadow-comparison`
line per finding, in finding order, and an input with no finding writes
nothing. On failure there is one line
`{"record":"shadow-error","input":<id>,"code":<code>}`, where `<code>` is
the `SecretScanErrorCode` string, for example `"INPUT_LIMIT_EXCEEDED"`.

| Field | Type | Meaning |
| --- | --- | --- |
| `record` | string | `"shadow-comparison"` |
| `input` | string | the input line's `id` |
| `finding` | string | the id `scan` gives this finding for this input (`finding-1`, …) |
| `start`, `end` | integer | the finding's range, in UTF-8 bytes of `text` |
| `byteLength` | integer | `end - start` |
| `detector` | string | the finding's detector id |
| `type` | string | the finding's type |
| `specificity` | string | the candidate's effective specificity |
| `legacyConfidence` | string | the finding's `Confidence` |
| `legacyAction` | string | `DefaultPolicy`'s action for the finding |
| `authority` | string | `"deterministic"` or `"statistical"` |
| `model`, `featureSchema` | string | as in the header |
| `contextClass` | string or null | the context class; `null` when deterministic |
| `exclusion` | string or null | the exclusion grammar the whole value matches, or `null` |
| `groups` | object or null | each group's capped contribution, keys `randomness`, `lexical`, `contextual`, `validation`, `negative`; `null` when deterministic |
| `signals` | array | every model signal as `{"group","signal","points"}`, in model order; empty when deterministic |
| `positive`, `negative` | integer | only when statistical: the summed positive contributions and the negative contribution |
| `score` | integer or null | the evidence score; `null` when deterministic |
| `band` | string | `none`, `low`, `medium` or `high`; the legacy `Confidence` when deterministic |
| `promotion` | string | `promote` (band above the legacy `Confidence`), `demote` (below it, `none` included) or `preserve` (equal, or deterministic) |
| `reasons` | array | reason codes, a subset of the list below, in its order |

The reason codes are a closed set: `deterministic-authority` (scorer not
consulted); `credential-context` or `no-credential-context`;
`randomness-capped` (randomness at its cap), `randomness-partial` or
`randomness-none`; `strict-exclusion` (a whole-value exclusion grammar
matched); `no-positive-evidence`; `band-none` (a promotion would drop the
finding).

No record holds the matched value, a substring, a class run, a feature
vector or a hash of it (contract section 8), only the fields above. The
test `diagnostics_carry_no_part_of_a_matched_value` checks the rendered
lines and their `Debug` form against every six-character window of each
matched value. Scores, contributions and signals are maintainer-local:
public benchmark projection may report aggregate outcomes per stratum,
never these per-candidate values (contract section 11).

### Reproducibility

Evidence produced this way records the product commit, the header's
`artifactRevision` and `modelFingerprint`, and the SHA-256 of the artifact
file at that commit ("Product source revision" above). The artifact's
`sources` hash this section and `evidence/shadow.rs`, so any change to the
record format or its reason codes needs a new artifact revision, and
evidence keyed to the old revision is stale. A change to a field, its
meaning or a reason code is also a new `format` identity.

### Tests

`crates/secret-scan-core/src/evidence/shadow/tests.rs` checks, over a
synthetic battery, that:

- recording changes no finding, and each comparison carries its finding's
  legacy `Confidence` and `DefaultPolicy` action;
- `generic-token` comparisons equal `aggregate` under `SHADOW_MODEL` for
  their context class: a credential name with a random value is `high`, a
  human-chosen password after a credential name is `low`, and a bare
  vendor-prefixed value is at most `medium`;
- provider, private-key and structural findings stay deterministic, with
  the band equal to the legacy `Confidence`;
- whole-input and incremental comparisons are equal for every chunking,
  and invisible characters inside a value do not change its comparison;
- the rendering is fixed and deterministic and escapes the record id;
- no rendered or `Debug` output holds any part of a matched value.

The existing conformance-corpus tests of `run_detector_pipeline`, `scan`
and the incremental session pin the legacy outputs, which now run through
`detect` without a sink.

## Shadow scorer qualification

Issue [#772](https://github.com/redact-secret/redact-secret/issues/772)
qualifies the beta.9 shadow scorer for cost, size and cross-runtime
determinism. This section applies the existing contract
([`decision-freeze-the-shadow-evidence-score-and-confidence-contract`](../decisions/2026-09-25-freeze-the-shadow-evidence-score-and-confidence-contract.md),
sections 5 and 7) and is not a new decision. The measurements are in
[`docs/audits/evidence/772/`](https://github.com/redact-secret/redact-secret/blob/main/docs/audits/evidence/772/README.md) and, for
performance and size budgets, in redact-secret-benchmarks
([#143](https://github.com/redact-secret/redact-secret-benchmarks/issues/143)).

### Not linked into shipped artifacts

No shipped build contains the scorer. `run_detector_pipeline`, which every
public entry point uses, passes no sink to `detect`, and the incremental
session's recording field, its `detect` call with a sink and its recording
block exist only under `cfg(test)`; outside tests the session calls
`run_detector_pipeline`, or `detect_units` with no sink for a batch of
closed lines (#985). The compiler therefore removes the scorer from the
library, the bindings, the CLI and the WebAssembly artifact. Before this, the
session's always-present `Option` kept the scorer reachable, and it added
about 26 KB to the `full` WebAssembly module (8.2% gzip) with no public caller.
The shadow evaluation example and the core's unit tests still compile it.

### Cross-runtime determinism

The scorer uses integer arithmetic only, and `scripts/check-rust-workspace.py`
check 11 rejects a floating-point type or literal in non-test code under
`src/evidence/`. CI proves the result, not just the rule:

- the `rust-native` job builds `shadow_evaluation` in release mode on Linux,
  macOS and Windows and runs it, for the `full` and `common` profiles, over
  the input set `scripts/shadow-determinism.mjs inputs` writes: every fixture
  of the synchronous, incremental and Unicode-conversion conformance corpora
  and a generated battery of hostile maximum-length and periodic values;
- the `rust-wasm` job compiles the same example for `wasm32-wasip1` and runs
  it on V8's WebAssembly engine through Node's built-in WASI host
  (`scripts/wasi-run.mjs`), after running the core's unit tests and the
  canonical corpus test there;
- the `shadow-determinism` job requires the four hosts' outputs to be byte
  for byte identical and fails otherwise. Its report carries counts and
  SHA-256s only.

The shipped `wasm32-unknown-unknown` binding cannot reach the scorer. The
`wasm32-wasip1` build compiles the same source with the same wasm32 code
generator; the two differ only in the operating-system layer, which the
scorer does not use.

### Worst cases

A contextual value is at most 4,096 bytes (`generic-token`'s
`MAX_CONTEXT_VALUE_LENGTH`), and a longer one is not a candidate. Feature
extraction reads at most 256 scalar values of it, with work bounded by
`256²` comparisons; the exclusion grammar reads the whole value once.
`src/evidence/qualification_tests.rs` pins the feature vectors of each
feature function's worst case (period 32, period 33, a late period break, no
repeated bigram, one repeated symbol, 256 distinct astral symbols, a random
maximum-length value), checks that a 1 MiB value is described by its first
256 symbols alone, and requires equal whole-input and incremental
comparisons for those values in credential-bearing contexts at six chunk
sizes.
