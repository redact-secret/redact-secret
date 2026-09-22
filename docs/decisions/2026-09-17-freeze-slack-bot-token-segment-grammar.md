---
decision_id: decision-freeze-slack-bot-token-segment-grammar
status: accepted
scope: workspace
title: Freeze the Slack bot token grammar as a three-section dash-separated shape
decided_at: 2026-09-17
spec: detector-families
---

# Freeze the Slack bot token grammar as a three-section dash-separated shape

## Decision

Narrow the existing `slack-token` detector
(`crates/secret-scan-core/src/detectors/additional_providers.rs`, `SLACK`) for
issue #371 from one shared `xoxb-` + 20-byte minimum of `[A-Za-z0-9_-]` to the
reviewed three-section bot grammar, moved to its own module
(`crates/secret-scan-core/src/detectors/slack.rs`, `SlackTokenDetector`)
because the shape needs a `-`-separated section grammar the shared
`KnownFormatProviderDetector`/`PrefixShape` primitives cannot express:

```
xoxb-<10-13 [0-9]>-<10-13 [0-9]>-<18+ [A-Za-z0-9]>
```

Every other documented prefix (`xoxp-`, `xapp-`, `xwfp-`, `xoxe-`,
`xoxe.xoxb-`, `xoxe.xoxp-`) keeps beta.4's rule unchanged as a separate
interim guard per prefix, composed from the same shared `pattern` primitives
(`pattern::scan_prefixed_shapes`) inside the new module. Detector id
(`slack-token`), finding type (`slack_token`), confidence (`High`),
specificity (`Provider`), the default policy class (`always-redact`), and
every public interface are unchanged; there is no strict mode, option, or new
detector id.

A value whose second numeric section runs straight into the secret with no
separator is an intentional false negative, not a fuzzy match: the provider
defines the secret as the final `-`-separated section, so a value missing
that separator has no secret section under the provider's own structure.

Known unsupported forms, all deliberately out of scope:

- A numeric section outside the documented `10-13` digit width, under either
  section, including a section wider than 13 digits (rejected rather than
  truncated to fit, the same choice this registry's other exact/bounded-width
  detectors already make).
- A secret section shorter than 18 bytes, or one containing `_` or `-` (its
  alphabet is `[A-Za-z0-9]` only, narrower than the interim guards'
  `[A-Za-z0-9_-]`).
- Every interim-guarded prefix's own three/four-section candidate grammar
  recorded in `docs/audits/evidence/367/precision-contracts.json`
  (`user`, `app-level`, `workflow`, `refresh`, `rotating-bot`,
  `rotating-user`): each is single-tool or provider-silent evidence and is
  not adopted by this record.
- Slack's legacy `xoxa-`/`xoxr-`/`xoxs-`/`xoxo-` workspace and custom
  integration tokens: deprecated by the provider, not supported by beta.4,
  and not added by this contract.

## Rationale

The published `@redact-secret/core@0.1.0-beta.4` package flags two
must-not-flag fixtures in the beta.4 common-formats benchmark
(`slack-token-bot-plain-twin`, `slack-token-bot-unicode-crlf-twin`): a bot
value whose second numeric section runs directly into the secret, with no
separator, one structural property away from its paired positive.
Reproduced against the published package before modification with the
issue's self-contained inputs: both twins flagged, both paired positives
matched at the recorded UTF-8 byte ranges. The old `RunLength::AtLeast(20)`
shared by every prefix cannot express a section grammar or a required
internal separator at all.

Issue #367 (docs/decisions/2026-09-17-freeze-precision-contracts-for-seven-provider-families.md)
is the contract-freeze prerequisite this record's child of: it reviews
Slack's own documentation (`https://docs.slack.dev/authentication/tokens`)
against gitleaks `v8.30.1` and trufflehog `v3.97.4`, and resolves the one
conflict explicitly (`docs/audits/evidence/367/precision-contracts.json`,
`slack-token.conflicts`): the provider states sections are `-`-separated and
the final section is the secret, while both tools' bot rules accept a bare
`[a-zA-Z0-9-]*` tail with no separator — provider documentation wins, which
is why all three baseline scanners flag the twin and why competitor
agreement is not the negative oracle here. The two numeric section widths
(`10-13` digits) are tool-agreement, since the provider states only that
sections are `-`-separated; the 18-byte secret floor is a support-policy
choice, the smallest bot-secret width any consulted tool accepts
(gitleaks' `slack-legacy-bot-token`), since the provider documents no bot
secret length.

This record freezes only the Slack bot contract, from the evidence issue
#367 already pins for the `bot` variant; it does not decide any of the
other six Slack prefixes' pending candidate grammars, and it does not
reopen #367 itself.

## Consequences

- **Corrected classifications, inputs untouched.** Thirteen existing
  `synchronous-corpus.json` fixtures and two `incremental-corpus.json`
  fixtures were authored to the retired shared minimum with `xoxb-` bodies
  carrying no digit sections at all. Their `input` bytes are unchanged;
  their expectations are corrected and each `note` names this record:
  `slack-positive-qualified`, `slack-positive-min-length`,
  `slack-positive-doc-style-placeholder`, `slack-positive-punctuation-adjacent`,
  `slack-positive-yaml`, `slack-positive-log`, `slack-positive-shell-quoted`,
  `slack-positive-yaml-crlf`, `slack-positive-repeated-value`, and
  `slack-positive-markdown-delimiter` (now `boundary`/
  `intentionally-unsupported`/`malformed`, no finding);
  `slack-overlap-context` and `slack-positive-json` (the value under a
  generic contextual assignment key is now owned by `generic-token` as a
  `contextual_secret` and still redacted);
  `slack-positive-unicode-byte-offset` (the literal `Bearer` scheme is now
  owned by `bearer-token` at the same byte offsets); and
  `slack-adversarial-long-suffix` (`maxFindings` 1 to 0, no finding, still
  bounded). In the incremental corpus, `additional-provider-families` and
  `slack-lookalike-token-discriminating-boundary` keep their `xoxb-` line as
  plain text at every partition. This is a classification correction, not a
  detector improvement, and is not scored as one.
- **Paired positives preserved and extended.** `slack-positive-all-prefixes`
  (the six interim-guarded prefixes) is unchanged. One new synchronous
  fixture, `slack-overlap-context-bot-grammar`, restores the `overlap`
  evidence dimension the reclassifications above emptied: a bot value
  carrying the full section grammar under a generic contextual assignment
  key is still owned by `slack-token` (provider specificity) over
  `generic-token`'s contextual candidate, the corrected counterpart of
  `slack-overlap-context`. `crates/secret-scan-core/src/detectors/slack.rs`
  carries its own deterministic unit tests for the section-width boundary,
  the secret-length floor and alphabet, the missing-separator twin, every
  interim prefix's minimum-length rule and longest-prefix-wins behavior, and
  the issue's exact attached synthetic inputs
  (`issue_371_twins_are_rejected_and_their_paired_positives_preserved`).
- `docs/coverage/detector-inventory.json`'s `slack_token` reconciliation
  trigger is now a full bot-grammar value; `inventory-report.json`,
  `coverage-declarations.json`, and `coverage-report.md` are regenerated,
  and `fp-fn-summary-371.json` records this issue's Slack-only view.
  `docs/audits/evidence/367/corpus-audit.json` is regenerated from the
  corrected corpus; `beta4-twin-baseline.json` and
  `precision-contracts.json` are frozen historical/decision evidence and are
  not rewritten.
- A real Slack bot token whose numeric sections fall outside `10-13` digits,
  or whose secret section is shorter than 18 bytes, would go undetected by
  this detector until the contract is re-reviewed; that is the accepted
  cost of rejecting the near-miss twin, bounded by the fact that the
  section widths are what both consulted reference scanners agree on.
