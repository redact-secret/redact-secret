---
decision_id: decision-freeze-telegram-bot-api-token-grammar
status: accepted
scope: workspace
title: Freeze the Telegram Bot API token grammar as a minimum-length digit-colon-secret shape
decided_at: 2026-09-16
---

# Freeze the Telegram Bot API token grammar as a minimum-length digit-colon-secret shape

## Decision

Add a dedicated `telegram-bot-token` detector
(`crates/secret-scan-core/src/detectors/telegram.rs`) for issue #302,
matching a Telegram Bot API token by the shape:

```
<at least 5 ASCII digits>:<at least 34 bytes from [A-Za-z0-9_-]>
```

with both runs matched maximally (a longer id or secret than the documented
example still matches). The token may appear bare, or glued directly onto
the literal `/bot` path segment of Telegram's own documented Bot API request
URL (`https://api.telegram.org/bot<token>/METHOD_NAME`) with no separator;
in that case only the id:secret token bytes are selected, never the `/bot`
segment or the trailing method name. Confidence is `High` and specificity is
`Provider`; the default policy always redacts a match (`telegram_bot_token`
in `ALWAYS_REDACT_TYPES`, `crates/secret-scan-core/src/policy.rs`), the same
class every other dedicated provider detector in this registry gets.

Two variants are intentionally out of scope, not fuzzy-matched:

- A bare numeric chat, user, or bot id with no `:<secret>` suffix carries no
  secret material and is not a credential; the grammar structurally excludes
  it.
- A public bot username handle (e.g. `@ExampleBot`) and Telegram's separate
  MTProto client API credentials (`api_id`/`api_hash`, a different
  authentication mechanism for building a Telegram client rather than a
  bot) share no `id:secret` shape with this grammar and are out of scope.

## Rationale

Telegram's own Bot API documentation (`https://core.telegram.org/bots/api`,
"Authorizing your bot") gives exactly one worked example,
`123456:ABC-DEF1234ghIkl-zyx57W2v1u123ew11`, and states that every Bot API
request is served as `https://api.telegram.org/bot<token>/METHOD_NAME` (an
example request URL follows immediately). It documents no character-class or
length grammar for either segment beyond that one example. Issue #302's
acceptance criteria require freezing "the supported grammar, confidence,
action, and known unsupported variants... before implementation" and note
that "ambiguous unprefixed values require reliable context" -- since neither
segment's length nor the secret's exact alphabet is formally documented,
this freeze is an explicit judgment call, matching the precedent set by
`decision-freeze-atlassian-api-token-grammar` for the same reason.

**Id length.** The documented example's own id segment (`123456`) is six
digits. There is no documented minimum or maximum. `MIN_ID_LEN = 5`, one
byte below the example's own width, follows the same "document a minimum
below the one known real sample" approach `decision-freeze-atlassian-api-token-grammar`
used, admitting a shorter id than Telegram's own illustration while never
capping the id run's length -- a future, longer id (Telegram user/bot ids
have grown over the platform's lifetime) is matched unconditionally by
construction.

**Secret length and alphabet.** The documented example's own secret segment
(`ABC-DEF1234ghIkl-zyx57W2v1u123ew11`) is 34 bytes from
`[A-Za-z0-9-]` (uppercase, lowercase, digit, hyphen -- it never happens to
contain an underscore). `MIN_SECRET_LEN = 34` uses that exact byte count as
a documented floor rather than an exact length, for the same forward-compatibility
reason as the id. The detector's alphabet is `[A-Za-z0-9_-]`
(`pattern::is_alnum_dash`), wider than the one example alone evidences:
consulted only as an external behavioral reference per `AGENTS.md`,
gitleaks's `telegram-bot-token` rule and trufflehog's `telegram` detector
both independently expect an underscore to be a valid secret byte, matching
common practice for URL-safe base64-shaped random tokens; no code from
either project is reproduced here.

**The `/bot` URL exception.** A general identifier-boundary check (the byte
immediately before the id run must be outside `[A-Za-z0-9_-]`) is necessary
everywhere else in this registry to keep a match from starting inside a
wider identifier, but it would reject every token embedded in Telegram's own
documented request URL: the `t` in `.../bot123456:...` is itself an
identifier byte. Rather than loosen the boundary check generally (which
would let a match start inside any wider alphanumeric run), this detector
recognizes exactly one documented literal, the `/bot` path segment, as an
additional admissible predecessor. This is narrower than requiring the full
`https://api.telegram.org` host, which was considered and rejected as
unnecessary complexity: the `/bot<digits>:<34+-byte secret>` shape alone,
gated by both minimum lengths, is not something an unrelated URL path
produces by chance.

## Consequences

- `crates/secret-scan-core/src/detectors/mod.rs` registers the new detector
  after `atlassian-api-token` and before `jwt`; overlap resolution's
  registration-order tie-break is unaffected in practice since this grammar
  cannot overlap another built-in provider's shape.
- `docs/coverage/detector-inventory.json` gains a `telegram_bot_token` row
  (`always-redact`); `docs/coverage/coverage-declarations.json`,
  `inventory-report.json`, and `coverage-report.md` are regenerated from it
  and `conformance/fixtures/synchronous-corpus.json`, not hand-edited.
- New corpus fixtures: `telegram-bot-token-positive-bare`,
  `-positive-dotenv`, `-positive-json`, `-positive-log`,
  `-positive-bot-api-url`, `-positive-crlf-unicode-prefix`,
  `-overlap-generic-context`, `-adversarial-long-padding`,
  `-boundary-below-min-id`, `-boundary-below-min-secret`,
  `-boundary-missing-separator`, `-negative-bare-numeric-id`,
  `-negative-public-handle`, `-negative-masked`, `-negative-reference`,
  `-negative-malformed-numeric-colon`.
- A bare numeric id, a public bot handle, and MTProto's `api_id`/`api_hash`
  all go undetected by this dedicated detector; a qualified `name=value`
  assignment of any of them still gets a lower-confidence, lower-specificity
  contextual finding through the existing generic-token path regardless of
  format.
- An id shorter than 5 digits or a secret shorter than 34 bytes -- were
  Telegram to ever issue one, which its documentation does not rule out --
  goes undetected.
- A benign string that happens to contain a 5+ digit run, a literal `:`, and
  a 34+-byte `[A-Za-z0-9_-]` run immediately after, with no boundary break,
  would false positive; this is accepted as the same class of risk every
  other length-gated structural detector in this registry already carries.
