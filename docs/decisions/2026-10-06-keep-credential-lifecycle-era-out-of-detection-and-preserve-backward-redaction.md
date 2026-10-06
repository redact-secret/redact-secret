---
decision_id: decision-keep-credential-lifecycle-era-out-of-detection-and-preserve-backward-redaction
status: accepted
scope: workspace
title: Keep a credential's lifecycle era out of detection and preserve backward redaction
decided_at: 2026-10-06
spec: detector-families
---

# Keep a credential's lifecycle era out of detection and preserve backward redaction

## Context

Group E of the credential-evidence adoption inventory
([#1230](https://github.com/redact-secret/redact-secret/issues/1230), 9 rows)
holds credentials that a provider has deprecated, retired or superseded: the
Adobe Service Account (JWT) private key, the Airtable legacy API key, the
Dropbox long-lived access token, the HubSpot legacy API key, the JFrog API key,
the Zendesk API token and three Reddit OAuth credentials whose only
documentation is an archived wiki that Reddit's current Help page points to. The
evidence repository records era facts as dated claims bound to pinned captures
and states, for every row, that a credential of that era found in logs or
configuration remains a redaction concern whatever the date.

The provider statements differ in strength. Airtable states a date after which
existing keys cannot call the API. HubSpot words the 2022-11-30 consequence two
ways. Dropbox gives two retirement dates and nothing about existing tokens.
JFrog states a deprecation and an End of Life notice and, in the same page, an
opt-in, off-by-default block on using existing keys, so deprecation is not a
statement that authentication stopped. Zendesk dates three phases and says
existing tokens keep working until the last. A finding carries no era and the
product has no clock, and the existing legacy detectors (`heroku_api_key_legacy`,
`datadog_application_key_legacy`, `confluent_cloud_api_secret_legacy`, the
legacy Pinecone UUID rule) already report retired forms.

## Decision

1. **An era is not a detection input.** A credential of a retired, deprecated or
   superseded era is detected exactly like a current one in the same carrier.
   Provider shutdown does not make it benign: it can still leak from a log, a
   configuration, a backup or a repository history, the provider may not have
   stopped authentication, and the product cannot know when a given value was
   issued. There is no temporal exclusion and no shutdown-date table.
2. **Current and historical claims are stated separately.** A contract says what
   the provider supports now and what a form was during a dated period, with
   the source class of each. A historical claim is made only for the period its
   pinned source states; archived evidence stays historical, and unresolved
   where a current source does not verify it.
3. **Deprecation is not shutdown.** A deprecation notice, an End of Life notice,
   a creation block or an opt-in usage block is not a statement that
   authentication ended. Without a provider statement that it ended, a retired
   credential is treated as possibly live. Where two statements of end of use
   differ, neither is chosen.
4. **Version-scoped variants are not merged.** A pattern is claimed only for the
   era its source scopes it to; two variants of one family (a prefixed and an
   unprefixed JFrog key) are never joined by a union grammar.
5. **Backward redaction is preserved.** No row's era removes or narrows an
   existing detector, vocabulary name or contract, and no row needs a dedicated
   historical detector. The generic PEM private-key, Bearer, Basic, JWT and
   credential-field readings are the contract for a retired form that rides one
   of those carriers. A dedicated detector for a historical form follows the
   ordinary adoption route, with a reviewed dated contract, and is never
   mandatory.
6. **A shared carrier is not an era.** The HubSpot `hapikey` parameter carries
   both the retired account key and the current developer key. A value in it is
   not classed by era, and the product claims neither.

### Alternatives considered

- **Suppress or warn on retired credentials by era.** Rejected. The finding has
  no era, the issue date of a value is unknowable, providers state shutdown
  inconsistently, and a warn leaves the value in the output. A retired
  credential in a published log is the leak this product exists to stop.
- **A historical detector per row.** Rejected as a requirement. Only one row, the
  version-scoped JFrog pattern, has a provider-stated grammar, and a carrier that is
  not read today (HubSpot `hapikey`, the JFrog header) is a vocabulary question,
  not a grammar one.
- **Treat an End of Life notice as shutdown.** Rejected: the JFrog pages say
  otherwise by their own opt-in block.

## Consequences

The false-positive cost is a long-dead credential, or a documentation example
of one, masked in a fixture or a log. The false-negative cost is a retired form
in a carrier the grammar does not read, the same blind spots as for any
credential. `docs/specs/detector-families.md` gains one row citing this record,
and the [#1230 record](../audits/evidence/1230/README.md) applies it to the nine
rows and records which carriers are read today. No detector, vocabulary name,
type or public interface changes; no version change and no release.

### Reopening bar

A provider statement that authentication ended, together with a reviewed dated
contract and a product reason to stop reporting that period, reopens clause 1 for
that one row. A grammar stated for a single era reopens clause 5 for a dated
detector with its benign corpus and overlap analysis.
