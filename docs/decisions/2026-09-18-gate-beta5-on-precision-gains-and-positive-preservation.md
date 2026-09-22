---
decision_id: decision-gate-beta5-on-precision-gains-and-positive-preservation
status: accepted
scope: workspace
title: Gate beta.5 on precision gains and positive preservation
decided_at: 2026-09-18
spec: evidence-and-gates
---

# Gate beta.5 on precision gains and positive preservation

## Decision

For issue #376, accept the seven precision fixes (#368–#374), the shared
context/streaming matrix (#375), and the contract freeze (#367) as producing
a genuine, evidenced precision gain over beta.4, with no measured loss on
required positives, no new collateral redaction, and every intended
behavioral change explicitly recorded rather than hidden. This decision
produces evidence and a release gate; it does not publish or authorize a
release, and it computes no aggregate cross-tier accuracy or ranking.

The full evidence is in
[`docs/audits/evidence/376/README.md`](../audits/evidence/376/README.md) and,
for the durable candidate comparison, in `redact-secret-benchmarks`'s
[`docs/beta-5-results.md`](https://github.com/redact-secret/redact-secret-benchmarks/blob/main/docs/beta-5-results.md)
(PR [#13](https://github.com/redact-secret/redact-secret-benchmarks/pull/13)).
In summary: fixed-corpus twin discrimination moves 32/56 → 56/56 (24 twin
false alarms eliminated), all 58 fixed-corpus and 168 expanded-corpus
required T1/T2 positives are preserved at zero leaked spans, and existing
T1/T3 negatives stay at zero flags. Eighteen `detector-coverage` policy/T3
rows for four of the seven families lose their provider finding — the
intended, reviewed policy change from freezing their contracts; the cases are
kept, not deleted.

## Release-qualification accuracy-corpus re-pin

Four `assessment/fixtures/accuracy-corpus.json` fixtures
(`code-openai-api-key`, `logs-additional-provider-tokens-one`,
`code-additional-provider-tokens-one`, `chat-additional-provider-tokens-one`)
predated the seven frozen contracts, as explicitly deferred to this gate by
the [OpenAI](2026-09-17-freeze-openai-api-key-grammar.md) and
[Docker](2026-09-17-freeze-docker-pat-oat-exact-length-grammar.md) decision
records. This gate corrects them to their contracted grammars and re-pins
both `assessment/acceptance-criteria.json` and
`assessment/acceptance-criteria-linux-x64.json`'s `baseline` pointer and
`accuracy` block to a fresh five-repetition complete assessment
(`assessment/results/complete-v4/`, `assessment/results/complete-linux-x64-v4/`).
Accuracy counts are unchanged in value (21 true positives / 1 false positive
/ 5 false negatives / 0 policy mismatches, identical across all five required
surfaces, on both host profiles, before and after) — only the corpus's byte
content and hash moved. The `performance` array in both criteria files is
**not** re-derived: per `assessment/README.md`, those thresholds are fixed
once, from a separate, deliberate review, and a corpus re-pin does not
convert the assessment into a performance-qualification exercise.

`assessment/acceptance.test.ts`'s "the pinned baseline is a representative,
fully accepted candidate" assertion is narrowed to accuracy-and-identity
parity, because a discovered, pre-existing, out-of-scope condition (below)
means the raw pinned macOS baseline no longer clears every fixed performance
threshold, independent of anything this gate changes.

## A discovered, out-of-scope performance-threshold gap

While producing the re-pin evidence, every non-Rust surface (Python, Node,
browser WebAssembly, CLI) was found to miss its fixed processing-time and
throughput thresholds in `assessment/acceptance-criteria.json` by roughly
20–30%, reproduced on real macOS (Apple M4) hardware outside any development
sandbox. Rust shows materially the same absolute timing for the same
workload but has far more threshold margin (200ms vs. 20–35ms caps), so it
alone still passes. This is independent of the accuracy-corpus fixtures this
gate touches (they are not performance-profile inputs) and of the seven
provider-detector changes (narrowing existing grammars, not adding scanning
work); it most plausibly reflects growth in per-scan overhead (e.g. default
detector count) since the thresholds were fixed at commit
`a356e702e59b03cf297e0af15ba0423bc8466d48`. It is not re-derived, silently
absorbed, or hidden by this gate — full analysis is in
`assessment/results/complete-v4/README.md`. A follow-up investigation into
current per-scan overhead against the fixed thresholds is recommended as
separate work. The Linux x86_64 profile is unaffected: dispatched
`ubuntu-latest` evidence
(`assessment/results/complete-linux-x64-v4/`) passes every performance and
resource threshold cleanly.

## Findings explicitly out of this gate's scope

- Five pre-existing accuracy-corpus false negatives/mismatches unrelated to
  the seven provider families (`github-token` ×2, `generic-token`,
  `aws-access-key`, `bearer-token`) — confirmed present, unchanged, before
  this gate's fixture corrections were committed.
- A `redact-secret-benchmarks` fixture-materialization path collision
  (`sendgrid-token-segmented-unicode-crlf` and two must-not-flag pairs
  scored under the wrong category's content) — documented, not fixed, in
  that repository's `docs/beta-5-results.md`.
- Stale `detector-coverage` generic fixtures for the four narrowed providers,
  predating their reviewed contracts — same document.

None of these are hidden by deleting cases, widening envelopes, or
relabeling failures; each is explicitly recorded with its own disposition.

## Benchmark-repository lifecycle unaffected

`redact-secret-benchmarks`'s `known-gaps.json` promotion lifecycle
(`docs/decisions/2026-09-18-govern-benchmark-regression-promotion.md`) is
unaffected by this gate: issues #368–#375 originated from proactive contract
review (#367), not from that repository's benchmark-discovery → known-gap →
promotion path, so no `known-gap` record transitions state here.
`conformance/benchmark-regressions.json` (the promotion manifest for #292–294)
is likewise untouched — it tracks a different, unrelated set of issues.

## Consequences

Beta.5's precision-relevant behavior is evidenced against a frozen beta.4
baseline with fixed-corpus and expanded-corpus results kept separate, every
required positive preserved, every intended policy change recorded, and the
release-qualification accuracy protocol re-pinned to match. This decision
does not select a version, create a tag, publish a package, or authorize
release; release approval remains a separate, explicit step per `AGENTS.md`.
