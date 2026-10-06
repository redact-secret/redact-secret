---
decision_id: decision-keep-credential-role-facts-out-of-detection-attribution-and-default-action
status: accepted
scope: workspace
title: Keep credential role and confidentiality facts out of detection, attribution and default action
decided_at: 2026-10-06
spec: contextual-detection
---

# Keep credential role and confidentiality facts out of detection, attribution and default action

## Context

Group D of the credential-evidence adoption inventory
([#1229](https://github.com/redact-secret/redact-secret/issues/1229), 23 rows)
is where the evidence repository records roles: which privilege a credential
carries, whether a provider says it may be public, whether it is read-only,
transient, derived from another secret, one half of a pair or a composite.
Examples: an Algolia search-only key that the provider documents as safe in
frontend code (and, in the same documentation, as scrapable and floodable), a
Contentful Delivery token whose public or confidential status no page states,
a Canva authorization code, a Zoom `x-zm-signature` value that is an HMAC of the
secret token and not the secret, a Meta `{app-id}|{app-secret}` composite, the
two OAuth 1.0 halves of X.

None of the 23 roles has an identifying grammar in any provider source: a role
rides a carrier it shares with other credentials (a header, a Bearer slot, a
`client_secret` field, an `ApiKey` envelope). A finding carries only safe
metadata (type, detector, confidence, range, obfuscation) and the default policy
maps type and confidence to an action; it never reads the input. The user action
configuration epic ([#1216](https://github.com/redact-secret/redact-secret/issues/1216)
to #1222) is still open. The product therefore needs one answer to three
questions the issue asks together: do role facts select what is detected, which
type a finding gets, and which action it defaults to?

## Decision

1. **Detection reads a carrier and a value, never a role.** A role fact the
   evidence records (public by design, read-only, administrative, transient,
   derived) does not make a credential in a read carrier silent, and it does not
   make a credential in an unread carrier detected. A search-only key in a read
   slot is reported exactly like an administrative key in the same slot.
2. **A shared carrier proves no role and no provider.** No finding type, alias or
   family is added for a role, and no role is attributed from the shape of a
   carrier. A role needs its own grammar evidence first, and none of the 23 has
   it. Whether two roles are one family is an evidence question; the product
   neither merges nor splits records.
3. **The default action is a function of the finding type and confidence, frozen
   independently of role facts.** `bearer_token`, `authorization_credential` and
   `jwt` redact; `contextual_secret` redacts at high confidence and warns at
   medium; there is no role-based downgrade and no role-based upgrade.
4. **Detection stays separate from action, and a user override stays possible.**
   A user action policy replaces the default exactly as before (the policy
   callback today, the declarative overlay when #1216 to #1222 land). The
   default is the security-first one, so a user who embeds a documented public
   key in frontend code lowers the action; the product does not weaken the
   default for every user who shares the carrier.
5. **Span follows the carrier.** A composite carrier value is one span (the
   Meta `{app-id}|{app-secret}` pair under one `access_token` is one finding
   over the whole composite, public half included, like a Basic envelope); two
   halves in two fields are two spans (OAuth 1.0 token and token secret); a
   transient code is judged by the existing ambiguity tier (`code` warns,
   `code_verifier` redacts); a derived output under a credential name is read by
   that name, as for `oauth_token` in
   [#1241](https://github.com/redact-secret/redact-secret/blob/2816897f96c405c3eb8c87a0c70eba5df273c121/docs/audits/evidence/1241/README.md), and one under an unmatched name
   (`x-zm-signature`, `appsecret_proof`) is silent.

### Alternatives considered

- **A role-aware default (warn or silence for public-by-design roles, redact for
  administrative ones).** Rejected. The finding has no role to key on, and
  adding one means attributing a role from a shared carrier shape. The
  provider's own pages argue against silence: Algolia documents that a
  search-only key can be scraped and used to flood the application, the Contentful
  pages are silent on whether a Delivery token may be public, and a Preview
  token exists to protect unpublished content.
- **Warn-only for read-only roles.** Rejected. A warn leaves the value in the
  sanitized output for every credential that shares the carrier.
- **A provider type per role.** Rejected. No grammar separates the roles, so a
  type would claim more than any source states.

## Consequences

The false-positive cost is a documented public or derived value masked in a log
or a configuration (a search-only key, a Delivery token, a webhook challenge
token); a user lowers it with the action configuration. The false-negative cost
is a role in a carrier the grammar does not read, the same blind spots as every
credential. One question is left open for the configuration design
([#1217](https://github.com/redact-secret/redact-secret/issues/1217) and
[#1218](https://github.com/redact-secret/redact-secret/issues/1218)), not decided
here: because findings carry no role, a user cannot today select "search-only
keys" in a policy, only a type, a detector, a confidence or a range.

`docs/specs/contextual-detection.md` gains one row citing this record, and the
[#1229 record](https://github.com/redact-secret/redact-secret/blob/2816897f96c405c3eb8c87a0c70eba5df273c121/docs/audits/evidence/1229/README.md) applies it to the 23 rows. No
detector, vocabulary name, type or public interface changes; no version change
and no release.

### Reopening bar

A provider-documented or independently corroborated grammar for one role (prefix,
alphabet, length and separator in a reviewed contract) for a new type, or a
decision of the configuration epic that gives a policy role metadata, reopens the
corresponding clause with a benign corpus and an overlap analysis.
