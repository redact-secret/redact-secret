---
decision_id: decision-freeze-new-relic-user-api-key-license-key-grammar
status: accepted
scope: workspace
title: Freeze the New Relic User API Key and License Key grammar as an exact-length prefixed shape and a keyword-gated bare hex shape
decided_at: 2026-09-16
spec: detector-families
---

# Freeze the New Relic User API Key and License Key grammar as an exact-length prefixed shape and a keyword-gated bare hex shape

## Decision

Add two dedicated detectors
(`crates/secret-scan-core/src/detectors/new_relic.rs`) for issue #307:

- **`new-relic-user-api-key`**: the literal `NRAK-`, then exactly 27 bytes of
  `[A-Z0-9]` -- 32 bytes total, bounded on both sides by a byte outside
  `[A-Za-z0-9]`. `High` confidence, `Provider` specificity, always redacted
  (`new_relic_user_api_key` in `ALWAYS_REDACT_TYPES`,
  `crates/secret-scan-core/src/policy.rs`) -- the prefix and exact length
  together are specific enough to be actionable on their own, the same class
  every other exact-length prefixed detector in this registry gets.
- **`new-relic-license-key`**: a bare run of exactly 40 lowercase-hex
  (`[0-9a-f]`) bytes, bounded the same way, required to share a physical line
  with a case-insensitive `newrelic`/`new_relic`/`new-relic`/`new relic`
  substring. `Medium` confidence, `Provider` specificity, confidence-gated
  (not in `ALWAYS_REDACT_TYPES`) -- unlike the User API Key, this format
  carries no marker of its own.

Both formats exclude a candidate that is a single repeated character
(`text::is_repeated_character_filler`), since both alphabets contain
characters (`X`, `0`) a masked placeholder commonly repeats.

The Browser Key, Mobile App Token, legacy Insights Insert/Query Keys, the
deprecated Admin Key, and the bare account-scoped "user API id" are
explicitly out of scope; see the Rationale section and the module doc
comment (`crates/secret-scan-core/src/detectors/new_relic.rs`) for why each
one is excluded rather than silently dropped.

## Rationale

New Relic's own API-key documentation
(`https://docs.newrelic.com/docs/apis/intro-apis/new-relic-api-keys/`) names
several key types but publishes a character-class grammar for neither
in-scope one -- it states only that the License Key is "a 40-character
hexadecimal string" used for data ingest, and that the User Key
authenticates NerdGraph/REST API calls. Issue #307's acceptance criteria
require freezing "the supported grammar, confidence, action, and known
unsupported variants... before implementation" and note that "ambiguous
unprefixed values require reliable context" -- since neither format's full
grammar is formally documented, this freeze is an explicit judgment call,
following the same freeze-before-implementation precedent as every other
`decision-freeze-*` record in this log.

**User API Key prefix.** The `NRAK-` prefix itself is not on the API-keys
page above; it comes from New Relic's own `terraform-provider-newrelic`
migration guide
(`website/docs/guides/migration_guide_v2.html.markdown`), which states "Your
**User API Key** has a prefix of `NRAK-`" and, separately, "Most User API
keys have the `NRAK-` prefix." The "most" is a documented hedge: the same
guide's own migration diff shows the prior, now-replaced admin-key prefix
`NRAA-`. This freeze treats that hedge as a known, accepted false negative
(see Consequences) rather than trying to also match `NRAA-` or any other
unnamed legacy prefix, since New Relic's Admin Key was itself deprecated in
favor of the User Key as of December 4, 2020, per the API-keys page's own
legacy-keys section.

**User API Key length and alphabet.** Consulted only as external behavioral
references per `AGENTS.md`, gitleaks's `new-relic-user-api-key` rule and
trufflehog 3.97.4's independent `newrelicuserkey` detector both converge on
exactly `NRAK-` followed by 27 bytes of `[A-Z0-9]` (32 bytes total), with no
documented counter-evidence of a different length from either source or from
New Relic's own docs. Unlike Atlassian's or Telegram's freeze (both
undocumented-length formats, treated as a minimum), two independent tools
agreeing on one exact length with no contrary evidence justifies
`RunLength::Exact` rather than `RunLength::AtLeast`; no code from either
project is reproduced here.

**License Key alphabet, length, and context gate.** "A 40-character
hexadecimal string" is the entirety of New Relic's own published grammar.
A bare 40-character hex string is not distinctive on its own -- it is
exactly the shape of a `git` commit SHA-1, an MD5 digest, or countless other
opaque hex blobs, and it is *shorter*, not longer, than the Telegram/
Atlassian minimum-length precedent's own justification for matching without
context, since those formats at least carry a distinguishing prefix or
separator this one does not. Per the issue's own "ambiguous unprefixed
values require reliable context" instruction, this module follows
`decision-freeze-twilio-auth-token-api-key-secret-grammar`'s same
same-line-keyword precedent instead of matching unconditionally: a bare
40-byte lowercase-hex run is only classified when a
`newrelic`/`new_relic`/`new-relic`/`new relic` substring shares its physical
line. Unlike Twilio's Auth Token, which has an available `High`-confidence
tier from a paired Account SID on the same line, the License Key has no
comparable paired identifier in New Relic's documented account model, so
this format never rises above `Medium`.

**Rejected: an unofficial license-key suffix.** trufflehog's
`newreliclicensekey` detector additionally requires the matched 40 bytes to
end in a literal `FFFFNRAL` (or, for an EU-region variant, begin with
`eu01xx`) -- a stronger structural marker that, if real, would let a License
Key be recognized at `High` confidence with no context needed at all. This
freeze does not adopt it: neither New Relic's own documentation nor gitleaks
(which has no License Key rule at all to cross-check against) corroborates
it. Treating one uncorroborated external tool's reverse-engineered suffix as
ground truth risks a worse outcome than the keyword-gated fallback -- a
documented false negative for every License Key that does not happen to
carry it, in exchange for a confidence bump this module cannot
independently verify. If a second independent source ever corroborates the
suffix, revisiting this decision to add a `High`-confidence structural path
alongside the `Medium`-confidence keyword-gated one is a natural follow-up,
not a breaking change to what is frozen here.

**Explicitly reviewed and excluded formats**, per the issue's "explicitly
review browser/mobile ingestion-key policy instead of assuming client
visibility implies harmlessness" instruction:

- The **Browser Key** and **Mobile App Token** are reviewed, not assumed
  harmless by default. New Relic's own documentation classifies both as
  public and client-visible by design: the Browser Key ships in every
  monitored page's rendered HTML, and the Mobile App Token is compiled into
  the distributed app binary. Both keys' own account page even documents
  that the *original* browser/mobile key cannot be deleted or rotated the
  way a License Key or User Key can -- consistent with New Relic treating
  them as a public embedding, not a rotatable secret. Flagging a value New
  Relic itself designs for public embedding would treat correct usage as an
  incident, so both are intentionally out of scope.
- The legacy **Insights Insert Key** (`NRII-`) and **Insights Query Key**
  (`NRIQ-`), the deprecated **Admin Key** (REST API keys reached end-of-life
  in 2025, per New Relic's own `whats-new-03-01-rest-api-keys-eol` notice),
  and the bare account-scoped **"user API id"** gitleaks separately detects
  (a 64-byte alphanumeric identifier, not a secret, excluded per the issue's
  "exclude application IDs and public configuration identifiers" scope
  note) are all outside the issue's explicit scope sentence ("Scope user API
  keys and documented license/ingest credentials") and are not implemented
  here. They remain documented gaps for a future issue, not silently
  dropped.

## Consequences

- `crates/secret-scan-core/src/detectors/mod.rs` registers both detectors
  after `discord-bot-token` and before `jwt`; overlap resolution's
  registration-order tie-break is unaffected in practice since neither
  grammar can overlap another built-in provider's shape.
- `docs/coverage/detector-inventory.json` gains `new_relic_user_api_key`
  (`always-redact`) and `new_relic_license_key` (`confidence-gated`) rows;
  `docs/coverage/coverage-declarations.json`, `inventory-report.json`, and
  `coverage-report.md` are regenerated from it and
  `conformance/fixtures/synchronous-corpus.json`, not hand-edited.
- New corpus fixtures: `new-relic-user-api-key-positive-bare`,
  `-positive-dotenv`, `-positive-json`, `-positive-yaml`, `-positive-log`,
  `-regression-crlf-and-unicode-prefix`, `-overlap-generic-context`,
  `-boundary-wrong-length`, `-negative-wrong-prefix`,
  `-negative-repeated-character-filler`,
  `-negative-environment-variable-reference`, `-adversarial-long-padding`;
  and `new-relic-license-key-positive-dotenv-keyword`,
  `-positive-json-keyword`, `-positive-yaml-keyword`, `-positive-log-keyword`,
  `-regression-crlf-and-unicode-prefix`, `-negative-bare-value-with-no-context`,
  `-negative-context-on-a-different-line`,
  `-negative-environment-variable-reference`,
  `-negative-repeated-character-filler`, `-overlap-beats-bearer-token`,
  `-boundary-wrong-length`, `-adversarial-dense-findings`.
- A User API Key issued under the legacy, pre-`NRAK-` scheme (the guide's
  own "most User API keys have the `NRAK-` prefix" hedge) goes undetected by
  this dedicated path; a qualified `name=value` assignment of one still gets
  a lower-confidence, lower-specificity contextual finding through the
  existing generic-token path regardless of format.
- A License Key with no `newrelic`/`new_relic`/`new-relic`/`new relic`
  keyword anywhere on its own line goes undetected -- the same accepted
  tradeoff `decision-freeze-twilio-auth-token-api-key-secret-grammar`'s own
  bare hex formats already carry.
- A benign 40-byte lowercase-hex value (a commit SHA, a digest) that happens
  to share a line with one of the four keywords would false positive; this
  is the same class of risk every other keyword-gated bare-format detector
  in this registry already accepts.
- The Browser Key, Mobile App Token, Insights Insert/Query Keys, Admin Key,
  and bare account/application ids are not classified by this or any other
  detector in the registry; a qualified `name=value` assignment of one of
  the secret-bearing legacy keys (Insert/Query) still gets a lower-
  confidence, lower-specificity contextual finding through generic-token.
