---
decision_id: decision-freeze-openai-api-key-grammar
status: accepted
scope: workspace
title: Freeze the OpenAI API key grammar as a marker-gated shape with exact segment lengths
decided_at: 2026-09-17
spec: detector-families
---

# Freeze the OpenAI API key grammar as a marker-gated shape with exact segment lengths

## Decision

`openai-token` (`crates/secret-scan-core/src/detectors/openai.rs`) classifies
a value as `openai_api_key` only when it is one of these shapes, bounded on
both sides by a byte outside `[A-Za-z0-9_-]` or the edge of input:

```
sk-<20 [A-Za-z0-9]>T3BlbkFJ<20 [A-Za-z0-9]>                        legacy (51 bytes)
sk-proj-<74|58 [A-Za-z0-9_-]>T3BlbkFJ<74|58 [A-Za-z0-9_-]>        project
sk-svcacct-<74|58 [A-Za-z0-9_-]>T3BlbkFJ<74|58 [A-Za-z0-9_-]>     service account
sk-admin-<74|58 [A-Za-z0-9_-]>T3BlbkFJ<74|58 [A-Za-z0-9_-]>       admin
```

`T3BlbkFJ` is the base64 encoding of the ASCII text `OpenAI`; every key the
provider issues carries it between two opaque segments. Each segment's
length is validated on its own, so 74/58 and 58/74 are both accepted. Each
variant is validated independently: an explicit `proj-`/`svcacct-`/`admin-`
namespace owns the value outright, and a malformed namespaced body is
rejected rather than re-read as a legacy key. Anthropic's `sk-ant-`
namespace stays excluded so `anthropic-token` keeps owning it (the `-` in
`ant-` already breaks the legacy alphabet; the explicit check documents the
intent). Confidence, specificity, finding type, detector id, and the
always-redact policy class are unchanged; there is no new option, mode, or
result field.

This replaces the pre-#368 rule, "`sk-` (optionally `proj-`/`svcacct-`) plus
at least 20 bytes of `[A-Za-z0-9_-]`", which classified any long enough
`sk-` value regardless of the marker or the segment lengths.

Known unsupported forms, all deliberately out of scope:

- `sk-service-`: an alias trufflehog 3.97.4 accepts with an open-ended body
  and no other reviewed source lists. This is a support-policy exclusion
  pending the #367 contract review, not an evidence-backed rejection.
- Any segment length other than 20 (legacy) or 74/58 (namespaced), any
  value without the marker, and any prefix OpenAI has not documented and
  neither reference rule lists. These are intentional false negatives until
  the contract is revised, not fuzzy matches.

## Rationale

Issue #368 reproduced six must-not-flag controls from the independent
`redact-secret-benchmarks` common-formats corpus (measurement protocol v4,
tier T2) that `@redact-secret/core@0.1.0-beta.4` flagged at the same range
as their paired positives: the legacy marker mutated to `T3BlbkFK`, and the
project and service-account left segments shortened from 74 to 73 bytes,
each in a plain and a Unicode/CRLF host context. That failure was confirmed
against the published beta.4 package before any change (all twelve of the
issue's inputs reproduced its snapshot exactly). The old rule could not
distinguish them because it never inspected the marker or the lengths.

The contract is sourced from the two references the issue and the benchmark
name; no code is reproduced from either:

- gitleaks 8.30.1 `openai-api-key`:
  `\b(sk-(?:proj|svcacct|admin)-(?:[A-Za-z0-9_-]{74}|[A-Za-z0-9_-]{58})T3BlbkFJ(?:[A-Za-z0-9_-]{74}|[A-Za-z0-9_-]{58})\b|sk-[a-zA-Z0-9]{20}T3BlbkFJ[a-zA-Z0-9]{20})(?:[\x60'"\s;]|\\[nr]|$)`
- trufflehog 3.97.4 `openai`:
  `\b(sk-(?:(?:proj|svcacct|service)-[A-Za-z0-9_-]+|[a-zA-Z0-9]+)T3BlbkFJ[A-Za-z0-9_-]+)\b`,
  with the comment that the marker is base64 `OpenAI` and that admin keys
  are not matched.

Both sources agree on the marker, the `proj`/`svcacct` namespaces, the
legacy alphabet (`[A-Za-z0-9]`), and the namespaced alphabet
(`[A-Za-z0-9_-]`). Where they differ, the resolution is recorded here
rather than guessed:

- **Segment lengths.** gitleaks asserts exact lengths (20/20; 74 or 58);
  trufflehog's `+` is open-ended. An open-ended rule does not contradict an
  exact one, it is merely less informative, so the exact lengths are the
  only source-backed claim and are adopted. The 58-byte alternate rests on
  gitleaks alone, which the corpus notes state.
- **`sk-admin-`.** gitleaks lists it under the same 74/58 grammar;
  trufflehog skips it because its live verifier cannot check admin keys,
  which is a verification-scope choice, not a claim that the shape differs.
  beta.4 already flagged admin keys through the old bare branch, so leaving
  the namespace out would turn a secret-bearing, source-backed form into a
  regression. It is kept.
- **`sk-service-`.** trufflehog only, no lengths. Excluded (above).
- **Trailing boundary.** gitleaks requires one of `` ` ``, `'`, `"`,
  whitespace, `;`, a literal `\n`/`\r`, or end of input after the key;
  trufflehog uses `\b`, which accepts `-` and `_` right after the key. This
  detector keeps its existing wider-identifier rule: the byte after the key
  must not be in `[A-Za-z0-9_-]`. That is stricter than `\b` on `-`/`_`
  (a key glued to `-v2` is a slice of a wider identifier) and looser than
  gitleaks on prose punctuation (`Rotate <key>, then redeploy.` still
  matches), consistent with every other prefixed detector in this registry.

Trade-offs, stated per `AGENTS.md`:

- False negatives: a future OpenAI format without the marker, with new
  lengths, or under a new prefix is missed by this detector until the
  contract is revised. A value under an assignment such as `api_key=` or
  `apiKey:` still surfaces through `generic-token` at contextual
  specificity, and a Bearer credential through `bearer-token`, so the
  policy outcome for a malformed provider shape legitimately differs
  between a bare value (silent) and an assignment or scheme context
  (redacted by another detector). No other detector is suppressed to make
  the twins silent. Observed while attributing: `generic-token` does not
  claim an `OPENAI_API_KEY=` assignment at all (even with a non-OpenAI
  value), while it claims `API_KEY=`, `api_key=`, and `apiKey=`; that is a
  pre-existing `generic-token` name-coverage gap, recorded here for a
  separate issue rather than changed under this one.
- False positives: a placeholder built entirely from valid bytes in the
  exact shape (for example `sk-proj-` + 74 `x` + marker + 74 `x`) is
  indistinguishable from a real key and is still classified. The marker
  plus exact lengths make this far narrower than before: a marker-less
  filler such as `sk-proj-xxxxxxxxxxxxxxxxxxxx` is no longer classified.

## Consequences

- Marker-less `sk-`, `sk-proj-`, and `sk-svcacct-` values that beta.4
  classified are no longer classified. In
  `conformance/fixtures/synchronous-corpus.json` the eleven existing
  broad-shape positives and the three overlap/host-context fixtures built
  on `sk-proj-SYNTHETIC_REVOKED_CONFORMANCE_KEY`-style values are kept
  verbatim and reclassified in place with a note naming this decision
  (`boundary`/`intentionally-unsupported` where nothing claims the input;
  `overlap` where `generic-token` or `bearer-token` now owns it), and the
  marker-less adversarial fixture now expects no finding. Nothing is
  deleted. Contract-conformant counterparts are added for every dimension
  the reclassified fixtures covered (bare, JSON, YAML, CRLF, dotenv, shell,
  log, Markdown, punctuation, repeated values, Unicode byte offsets,
  overlap with `client_secret=` and `Bearer`), plus the issue's twelve
  inputs verbatim, boundary mutations one byte off every contracted length
  on both sides of the marker, a lowercase-marker mutation, a
  legacy-alphabet violation, the no-fallback case, wider-identifier guards,
  the unsupported `sk-service-` form, and a prefix-flood adversarial case.
- `conformance/fixtures/incremental-corpus.json` gains four partition
  fixtures that split every byte of a positive and its twin, including
  inside the marker and at the 73/74 boundary; the
  `legacy-variable-detector-families` fixture's OpenAI line now carries
  the contracted shape (its other lines' offsets shift accordingly).
- `crates/secret-scan-core/tests/grammar_mutation_discovery.rs` no longer
  models `openai-token`: that harness describes only "prefix, run,
  boundary" grammars and cannot express a marker between two exact-length
  segments. Its one expected exploratory difference (the `sk-ant-`
  exclusion) went with it; the explicit corpus mutations above replace
  that coverage.
- `docs/coverage/detector-inventory.json`'s `openai_api_key`
  reconciliation trigger is the contracted project key quoted verbatim in
  `openai.rs`; the derived coverage files are regenerated.
- `assessment/fixtures/accuracy-corpus.json`'s `code-openai-api-key`
  fixture still expects the marker-less
  `sk-ASSESSMENTSYNTHETIC_OPENAI_KEY_0000000000` to be classified. It is
  deliberately left unchanged here: the acceptance tests pin that file's
  SHA-256 to the committed five-repetition evidence runs, and re-authoring
  it requires a new complete evidence run and a criteria re-pin, which is
  release-qualification work (#376), not this detector fix. Until then the
  accuracy protocol will report that fixture as a policy mismatch; the
  contract-conformant replacement is
  `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` at bytes 22–73 of
  the same line.
- The independent `redact-secret-benchmarks` corpus (a separate repository
  and release process) is not modified by this change. Its six twins and
  six positives are reproduced verbatim in this repository's corpus with
  their benchmark ids in the fixture notes. Counterparts worth adding
  there, without rewriting its historical inputs: a 58-byte-segment
  positive with a 57-byte twin, an `sk-admin-` positive, a right-segment
  73-byte twin, and a lowercase-marker twin.
- Issue #367 (the contract-freeze review for seven provider families) is
  still open. This record is the OpenAI entry of that review; if #367
  reaches a different resolution on `sk-admin-`, `sk-service-`, or the
  58-byte alternate, it amends this decision explicitly rather than
  silently.
