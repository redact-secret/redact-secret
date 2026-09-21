---
decision_id: decision-govern-bare-vendor-prefixed-policy-layer
status: accepted
scope: workspace
title: Redact a bare, marker-less OpenAI-prefixed value under a generic policy layer, beneath the frozen contract
decided_at: 2026-09-21
---

# Redact a bare, marker-less OpenAI-prefixed value under a generic policy layer, beneath the frozen contract

## Decision

`generic-token` (`crates/secret-scan-core/src/detectors/generic_token.rs`)
gains a third candidate source, alongside its existing contextual-assignment
and `Basic`/`Token` authorization matching: a bare, vendor-prefixed,
high-entropy value with no surrounding context at all.

```
sk-[A-Za-z0-9]{48}                          legacy
sk-proj-[A-Za-z0-9]{48}                     early project
sk-svcacct-[A-Za-z0-9]{48}                  early service account
sk-admin-[A-Za-z0-9]{48}                    early admin
```

boundary-delimited (the byte before the prefix and the byte after the body
must not be in `[A-Za-z0-9_-]`), and only when the 48-byte body clears the
same entropy floor (`HIGH_ENTROPY_THRESHOLD`, 3.0 bits/symbol) a high-signal
contextual assignment's value already has to clear. Classified
`vendor_prefixed_credential` — **never** `openai_api_key` — at
[`Confidence::Medium`] and [`Specificity::Entropy`]: below every provider
contract's `Specificity::Provider`, so a genuine `openai-token` match always
wins overlap and keeps its own finding, byte-for-byte, untouched. Added to
`ALWAYS_REDACT_TYPES` so the default policy redacts it despite the
deliberately-not-`High` confidence, the same way `authorization_credential`
already does for a structural-but-unverified match.

`decision-freeze-openai-api-key-grammar` (#368) is untouched: `openai-token`
still requires the `T3BlbkFJ` marker, still rejects a mutated marker, and
still validates each namespace independently with no fallback. This is a
separate, lower layer beneath that contract, not a widening of it — the
grammar above matches strictly more values than the contract accepts (no
marker required), and is registered so it structurally cannot outrank the
contract.

## Rationale

Issue #552 (rescoped 2026-09-21) traced the redact-secret-benchmarks
`detector-coverage--openai-token-{1,2,3}-{bare,quoted,unicode-crlf}`
fixtures' nine misses to a real, if narrow, gap: a `sk-`-family value that
matches its provider's actual, documented body width (exactly 48 bytes) but
carries no `T3BlbkFJ` marker — an unrotated pre-2024 legacy key (which
authenticates until rotated; OpenAI issues no marker-less keys today, so
there is no live provider format this widens into), or a near-miss that
merely mutated the marker — was invisible to every default detector. Neither
`gitleaks` nor `trufflehog` catch it either (both key on the marker), so
matching their blind spot was the wrong target; `flare-redact` reaches the
same nine fixtures with `sk-(?:proj-)?[A-Za-z0-9_-]{20,64}` and pays four
false positives on the accuracy corpus while also missing the in-contract
`proj`/`svcacct` positives this repository gets exactly.

Two earlier framings of this issue were tried and retracted (recorded in the
issue thread, not repeated here): a permissive band accepting 20–64 bytes of
`[A-Za-z0-9_-]` (too wide — needs a reject list for `sk-ant-`/`sk-or-`, the
same defect `flare-redact` has), and a proposal to widen `openai-token`
itself to accept the marker-less shape (would have reversed #368). What
survives from both is the shape the provider's own documented formats
actually establish:

- **Legacy, pre-2024**: `sk-` + exactly 48 `[A-Za-z0-9]`, no marker. No
  longer issued, but an unrotated key keeps authenticating.
- **Early project/service-account/admin**: `sk-proj-`/`sk-svcacct-`/
  `sk-admin-` + exactly 48 `[A-Za-z0-9]`, before the format grew to the
  ~156-byte marker-bearing body `openai-token` already covers.

48 is the recurring unit in both, and — combined with an alphanumeric-only
alphabet and a boundary check — it is a self-disambiguating discriminator:
no reject list is needed. `sk-ant-...` (Anthropic) and `sk-or-...`
(OpenRouter) both place a `-` well inside the first 48 bytes, so the
alphanumeric-only run never reaches the required length; `anthropic-token`
keeps owning its namespace exactly as before. A modern, marker-bearing
`sk-proj-` key (~156 bytes, its own alphabet including `-`/`_`) is excluded
the same way whenever its body contains a separator in the first 48 bytes;
on the rare chance it does not, the in-contract `openai-token` match at the
full, longer span wins overlap regardless (`Specificity::Provider` strictly
dominates `Specificity::Entropy` in
`decision-resolve-overlap-precedence-by-resolved-action-severity`'s ranking,
independent of range width or confidence).

The primary audience is LLM users, and a bare `sk-`-prefixed value on its
own line — pasted into a notebook, a `.env` file, or a chat log — is the
credential this product's users leak most often as exactly that: bare, with
no assignment name or `Authorization:` scheme around it for `generic-token`'s
existing contextual and authorization candidates to key on. The "quoted" and
"unicode-crlf" fixture contexts add nothing that "bare" would not already
resolve: the boundary check is quote/emoji/CRLF-agnostic by construction.

## What this costs

The whole false-positive surface: any 48-character alphanumeric run directly
behind a known OpenAI-family prefix, boundary-delimited, above the entropy
floor. Narrower than `flare-redact`'s `{20,64}` band, and unlike it this
does not lose the in-contract `proj`/`svcacct` positives — those still
resolve to `openai_api_key` at `Specificity::Provider`. The cost is paid at
`Confidence::Medium`/generic classification, never at `openai_api_key`: a
consumer that filters on finding type keeps the ability to trust
`openai_api_key` specifically as a verified provider match, while
`vendor_prefixed_credential` is legible as exactly what it is — a policy
heuristic, not a contract match.

## Consequences

- `crates/secret-scan-core/src/detectors/generic_token.rs` gains
  `bare_vendor_prefix_candidates`, wired into `GenericTokenDetector::detect`
  for the built-in instance only (the ruleset-names variant does not
  duplicate it, the same way it does not duplicate
  `authorization_candidates`).
- `crates/secret-scan-core/src/policy.rs`'s `ALWAYS_REDACT_TYPES` gains
  `vendor_prefixed_credential`.
- `conformance/fixtures/synchronous-corpus.json` gains the nine canonical
  regression fixtures (three shapes × bare/quoted/unicode-crlf), an
  `sk-admin-` positive, three benign controls (entropy floor, one byte
  short, embedded in a wider identifier), and one dedicated overlap-evidence
  fixture. Five existing fixtures whose input happens to be an exact
  48-byte `sk-`-family body with no marker (or a mutated one) — previously
  silent everywhere — are reclassified from `kind: "negative"` to
  `kind: "overlap"` with a note naming this decision, since the input itself
  is unchanged but the whole-registry result is not:
  `openai-negative-368-legacy-plain-twin`,
  `openai-negative-368-legacy-unicode-crlf-twin`,
  `openai-negative-explicit-namespace-legacy-body`,
  `openai-negative-marker-dotenv`, `openai-negative-marker-toml`. Every
  other `openai-negative-*`/`openai-boundary-*` fixture (the namespaced,
  underscore-bodied ones) is unaffected: the alphanumeric-only alphabet
  never reaches 48 bytes through an underscore.
- `conformance/fixtures/incremental-corpus.json`'s
  `openai-legacy-marker-twin-discriminating-boundary` and
  `openai-368-unicode-crlf-pairs` gain the same second finding and their
  redacted `text` shifts placeholder numbers accordingly; every later
  partition must still resolve it identically.
- `conformance/fixtures/common-profile-expectations.json` is regenerated
  (`REDACT_SECRET_UPDATE_COMMON_EXPECTATIONS=1 cargo test -p redact-secret
  --test common_profile_corpus`): `generic-token` ships in the `common`
  profile, so this layer is available even without any `provider` detector
  loaded.
- `docs/coverage/detector-inventory.json` gains a `vendor_prefixed_credential`
  row (`always-redact` policy class); `coverage-declarations.json`,
  `inventory-report.json`, and `coverage-report.md` are regenerated.
  `docs/audits/evidence/367/corpus-audit.json` is regenerated to reflect the
  five reclassified fixtures' new `kind`/`tier`; `docs/audits/evidence/367/
  precision-contracts.json` — the frozen contract description of
  `openai-token` itself — is untouched, since `openai-token`'s own behavior
  does not change.
- `docs/audits/evidence/552/README.md`, written against an earlier framing
  of this issue that concluded no product code change was warranted for the
  four provider families, is superseded for `openai-token` specifically by
  this decision and the fix it describes; it is not rewritten, per
  `decision-govern-benchmark-regression-promotion`'s historical-record rule,
  and this document's cross-reference is the correction of record.
- `redact-secret/redact-secret-benchmarks#82` (re-scoping the
  `openai-token-legacy-*-twin` fixture's scoring so a correct
  `generic-token` finding is not recorded as a twin failure) is a
  prerequisite this decision assumes is already resolved; it was closed
  before this change landed. Promoting these fixed-corpus misses through
  the benchmarks repo's own `known-gaps.json` lifecycle, and re-running the
  measurement to confirm the nine misses are zero, is benchmarks-side
  follow-up (`redact-secret/redact-secret-benchmarks#66`'s tracked gap for
  this issue family), not performed by this record.
- `assessment/fixtures/accuracy-corpus.json` is not touched: its own
  `code-openai-api-key` fixture already uses the contract-conformant
  marker-bearing shape, unaffected by this layer.
