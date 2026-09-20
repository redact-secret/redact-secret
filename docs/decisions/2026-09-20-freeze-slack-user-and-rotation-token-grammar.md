---
decision_id: decision-freeze-slack-user-and-rotation-token-grammar
status: accepted
scope: workspace
title: Complete the Slack credential family by freezing the user-token grammar and the rotation family's version section
decided_at: 2026-09-20
---

# Complete the Slack credential family by freezing the user-token grammar and the rotation family's version section

## Decision

Narrow the `slack-token` detector
(`crates/secret-scan-core/src/detectors/slack.rs`, `SlackTokenDetector`) for
issue #512 from beta.4's shared "recognized prefix plus a 20-byte minimum
suffix" rule, still carried by every prefix except the `xoxb-` bot form
issue #371 froze, to a reviewed structural contract for the user token and
every `xoxe`-rooted rotation-family prefix:

```
xoxp-<10-13 [0-9]>-<10-13 [0-9]>-<10-13 [0-9]>-<28+ [A-Za-z0-9]>   user
xoxe-<1 [0-9]>-<20+ [A-Za-z0-9_-]>                                 refresh
xoxe.xoxb-<1 [0-9]>-<20+ [A-Za-z0-9_-]>                            rotating bot
xoxe.xoxp-<1 [0-9]>-<20+ [A-Za-z0-9_-]>                            rotating user
```

`xapp-` (app-level) and `xwfp-` (workflow) keep beta.4's rule unchanged; see
Rationale for why they are not promoted. Detector id (`slack-token`), finding
type (`slack_token`), confidence (`High`), specificity (`Provider`), the
default policy class (`always-redact`), and every public interface are
unchanged; there is no strict mode, option, or new detector id. Every family
Slack documents is now either contracted at a reviewed tier or explicitly
recorded as not promoted, closing the family gap issue #501 identified.

Known unsupported forms, all deliberately out of scope:

- A user-token numeric section outside the documented `10-13` digit width,
  under any of its three sections, including a section wider than 13
  digits (rejected rather than truncated, the same choice the bot contract
  and this registry's other exact/bounded-width detectors already make).
- A user-token secret section shorter than 28 bytes, or one containing `_`
  or `-` (its alphabet is `[A-Za-z0-9]` only, narrower than the boundary
  alphabet, the same choice the bot secret already makes). A pre-2016
  6- or 10-character legacy user secret is an accepted false negative of
  this floor.
- A rotation-family version section of zero digits (the shape the pre-#512
  interim guard used to accept) or of two or more digits (every provider
  example shows exactly one).
- `xoxe.xoxp-`'s own extra numeric section, shown once in the provider's
  rotation example (`xoxe.xoxp-1-1234-...`) immediately after the version
  digit: a single uncorroborated instance, not decomposed into its own
  section and left inside the unchanged opaque body.
- `xapp-`'s and `xwfp-`'s own candidate structures, recorded but not
  adopted (see Rationale).
- Slack's legacy `xoxa-`/`xoxr-`/`xoxs-`/`xoxo-` workspace and custom
  integration tokens: deprecated by the provider, not supported by beta.4,
  and not added by this record (unchanged from issue #367/#371).

## Rationale

Issue #367 (`docs/decisions/2026-09-17-freeze-precision-contracts-for-seven-provider-families.md`,
`docs/audits/evidence/367/precision-contracts.json`) reviewed all seven
Slack prefixes once already, adopted only the bot grammar (issue #371), and
recorded the other six as unpromoted "supported-interim" T3 entries, each
with a `candidateGrammar` it explicitly declined to adopt. Issue #512
re-reviews those six against the current live provider pages (both
reobserved 2026-09-20: <https://docs.slack.dev/authentication/tokens> and
<https://docs.slack.dev/authentication/using-token-rotation/>) plus the same
two pinned tool sources (gitleaks 8.30.1, trufflehog 3.97.4), and reaches a
different conclusion for four of the six:

- **User (`xoxp-`).** The provider states tokens are divided into
  `-`-separated sections with the final section the secret, and shows the
  literal example `xoxp-111-222-333-d6bc768406e5c2e6958cfc399b438004`: three
  numeric ID sections, then a secret the example renders at exactly 32
  bytes. Gitleaks' `slack-user-token` rule (`xox[pe](?:-[0-9]{10,13}){3}-[a-zA-Z0-9-]{28,34}`)
  independently corroborates the three-section-then-secret shape and the
  same `10-13` digit width the bot contract already adopted for its own two
  sections; its secret-width lower bound (28) is adopted as the same kind
  of support-policy floor the bot secret already uses, and its `-` in the
  secret alphabet is excluded for the same reason the bot secret excludes
  it (the separator must not be folded into the secret). This clears the
  provider-plus-tool-corroborated-widths bar issue #512 set out to apply,
  the same bar the bot contract already met.
- **Refresh (`xoxe-`) and rotating bot/user (`xoxe.xoxb-`, `xoxe.xoxp-`).**
  The rotation-flow page's own examples (`xoxe-1-...`, `xoxe.xoxb-1-...`,
  `xoxe.xoxp-1-1234-...`) show, for all three, a single digit immediately
  after the prefix and before the next `-`; gitleaks' `slack-config-refresh-token`
  and `slack-config-access-token` rules independently encode that same
  single-digit version section. Only that section is promoted: the body
  that follows keeps beta.4's opaque `[A-Za-z0-9_-]`, 20-byte-minimum
  interim guard unchanged, since neither source constrains its width or
  alphabet (gitleaks' own 146- and 163-166-byte exact widths are single-tool
  and not adopted, the same reasoning issue #367 already applied to
  `api_org_`-style single-tool candidates). `xoxe.xoxp-`'s own extra
  `-1234-` section, shown once, is left inside the unchanged body rather
  than decomposed on one uncorroborated example.
- **App-level (`xapp-`) and workflow (`xwfp-`) are not promoted.** Both live
  provider pages state only the bare prefix for each, with no structural or
  length detail (`xwfp-`'s only additional stated property is its 15-minute
  or function-step-completion expiry, a lifetime fact, not a shape fact).
  `xapp-`'s only candidate structure remains gitleaks' single, uncorroborated
  rule; `xwfp-` has no tool source at all. Neither clears the
  provider-documented-or-tool-corroborated bar this record and issue #367
  both hold every other promotion to, so both keep beta.4's rule unchanged,
  explicitly decided rather than left pending.

`crates/secret-scan-core/src/detectors/slack.rs` generalizes `scan_bot`'s
digit-sections-then-tail shape into a shared `scan_sectioned`/`sectioned_end`
pair, parameterized by section count, digit width, and tail floor/alphabet,
so the bot, user, and three rotation-family scans reduce to one reviewed
primitive instead of four near-duplicate hand-rolled loops.

## Consequences

- **Coverage change for `xoxp-`/`xoxe-`/`xoxe.xoxb-`/`xoxe.xoxp-`, no change
  for `xoxb-`/`xapp-`/`xwfp-`.** A value that merely starts with one of the
  four promoted prefixes and reaches the old 20-byte minimum, but does not
  carry the now-required digit section(s), no longer matches; a contextual
  assignment carrying one can still surface through `generic-token`. `xoxb-`
  is unchanged; `xapp-`/`xwfp-` are unchanged.
- **Corrected classifications, inputs untouched where evidence still
  applies.** `slack-positive-all-prefixes` (`conformance/fixtures/synchronous-corpus.json`)
  keeps its unchanged input; its expectation is corrected to the two
  prefixes (`xapp-`, `xwfp-`) that remain interim-guarded, since none of the
  six bodies in that fixture carry the newly-required digit section(s).
  `slack-negative-interim-below-min-floor` is retargeted from `xoxp-` to
  `xapp-`, one of the two prefixes for which "the retained interim guard's
  20-byte floor" is still the accurate description.
- **New structural coverage.** `slack-positive-structural-prefixes` is the
  corrected counterpart of `slack-positive-all-prefixes`, demonstrating each
  of the four promoted families detected independently at its own full
  grammar in one input. New boundary fixtures cover the user grammar's
  missing final separator, an out-of-range first numeric section, and a
  27-byte (one-below-floor) secret; the rotation grammar's zero- and
  two-digit version sections; and the shape the pre-#512 interim guard used
  to accept for each (an opaque body with no digit section at all). Two new
  benign-control fixtures (`slack-negative-placeholder-user`,
  `slack-negative-placeholder-rotation`) cover a documentation-placeholder
  value under the newly-structural prefixes. `crates/secret-scan-core/src/detectors/slack.rs`'s
  own unit tests cover every dimension exhaustively: exact section widths,
  the secret floor and alphabet, the version-section digit count, the
  missing-separator twin for both the user and rotation forms, that a
  bot-shaped body under the more specific `xoxe.xoxb-` prefix is not
  reread as a plain bot match, and that every variant is detected
  independently in the same input without one suppressing another.
- **Evidence record updated.** `docs/audits/evidence/367/precision-contracts.json`
  re-tiers the `user`, `refresh`, `rotating-bot`, and `rotating-user`
  variants from `supported-interim`/T3 to `supported`/T1, replacing each
  variant's unadopted `candidateGrammar` with the adopted `grammar` and its
  segment-level basis, and records the re-tiering reasoning in a new
  `conflicts` entry; `app-level` and `workflow` are updated only to record
  that issue #512 reverified them against the live pages and left them
  unpromoted. `docs/audits/evidence/367/corpus-audit.json` is regenerated
  from the corrected corpus and contract (every `slack-token` row is
  `retained` or `silent`; none is `broad-shape` or `review`).
  `docs/coverage/inventory-report.json` and `coverage-declarations.json`
  are regenerated; `docs/coverage/fp-fn-summary-512.json` records this
  issue's Slack-only view (0 actual false positives or negatives), alongside
  the existing `fp-fn-summary-371.json` for the bot contract.
- A real Slack user token whose numeric sections fall outside `10-13`
  digits or whose secret is shorter than 28 bytes, or a real rotation-family
  token whose version section is not exactly one digit, would go undetected
  by this detector until the contract is re-reviewed; that is the accepted
  cost of narrowing to the reviewed shape, bounded by the fact that every
  narrowed property is either provider-documented or corroborated by a
  pinned tool. `xapp-`/`xwfp-` keep whatever recall and false-alarm profile
  beta.4's opaque interim guard already had; neither is worsened or improved
  by this record.
