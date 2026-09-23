# Issue #651 — T1 provider evidence for `generic:connection-string-password`

[Audit archive](../../README.md) ·
[Issue #651](https://github.com/redact-secret/redact-secret/issues/651) ·
[Epic A #575](https://github.com/redact-secret/redact-secret/issues/575) ·
[Second-pass research](https://github.com/redact-secret/redact-secret/issues/651#issuecomment-5784951351) ·
[Broad-discovery pass](https://github.com/redact-secret/redact-secret/issues/651#issuecomment-5785441567) ·
[Benchmarks counterpart redact-secret-benchmarks#112](https://github.com/redact-secret/redact-secret-benchmarks/issues/112)

Written 2026-09-23 on branch `chore/beta7-research`. The two
iterative passes stay in the linked issue comments and are not restated here.

## Verdict: NOT FOUND — EXHAUSTIVE as of 2026-09-23

No RFC or vendor source gives this family an identifying element. The password
is chosen by the user. The sources define only where it sits (between the
first `:` of userinfo and `@`) and which characters are allowed raw. Accepted
precedent already holds that delimiters plus an alphabet are below T1:
`bearer-token` (RFC 6750 `b64token`) and `otpauth-uri` (Base32 secret) both
stay T3. The two structural T1 contracts need more than that. `private-key`
(RFC 7468) has credential-specific labels, and `jwt` (RFC 7519) has a
three-segment structure.

| property | provable at T1 | basis |
| --- | --- | --- |
| delimiter (after first `:` in userinfo, before `@`) | yes | RFC 3986 §3.2.1; RFC 1738 §3.1; every vendor's URI docs |
| alphabet | partly | RFC 3986 `userinfo` ABNF; RabbitMQ `password` production. Vendors disagree on which characters must be encoded (see contradictions) |
| prefix / namespace | no | none exists for a user-chosen password |
| length | no | no RFC or vendor states one for a URI password |
| marker / checksum | no | none documented anywhere |

Out of scope for this family: PlanetScale (`pscale_pw_`), Neon (`npg_`) and
Aiven/DigitalOcean (`AVNS_`) issue passwords with a fixed prefix. Of these,
only PlanetScale has a provider-domain prose statement, and it supports a
separate **PlanetScale password** family, not this generic one (see Open items).

## The source

The strongest standards sources are these. They were re-fetched on 2026-09-23
(`observedAt` 2026-09-23). None of them meets the bar.

- `https://www.rfc-editor.org/rfc/rfc3986` §3.2.1:
  > `userinfo    = *( unreserved / pct-encoded / sub-delims / ":" )`

  > Use of the format "user:password" in the userinfo field is deprecated.

  §7.5:
  > A password appearing within the userinfo component is deprecated and should be considered an error

  This is the source the contract already uses as its `twinSource`.
- `https://www.rfc-editor.org/rfc/rfc1738` §3.1 (Proposed Standard 1994;
  updated by RFC 3986; obsoleted by RFC 4248/4266). The earlier password
  production:
  > `password       = *[ uchar | ";" | "?" | "&" | "=" ]`

  > Within the user and password field, any ":", "@", or "/" must be encoded.
- `https://www.rabbitmq.com/docs/uri-spec`. This is the only vendor that
  gives the password its own production, and it excludes `:`:
  > `password       = *( unreserved / pct-encoded / sub-delims )`
- `https://www.mongodb.com/docs/manual/reference/connection-string-formats/`:
  > If the username or password includes the following characters, those characters must be converted using percent encoding

  The listed characters are `$ : / ? # [ ] @`.
- `https://www.postgresql.org/docs/current/libpq-connect.html`: `userspec` is
  `user[:password]`. There is no password grammar.

## Proposed `covers` sentence

None for T1. The existing T3 `twinSource` text needs one correction, which
should be made in the benchmarks counterpart and is not decided here. In place
of "The password value has no grammar", it could read:

> RFC 3986 §3.2.1 places the password after the first ":" of userinfo and
> before "@", and limits it to the userinfo character set; no RFC or vendor
> states a length or an identifying element for a user-chosen password, so
> twins mutate the context, not the value.

## Contradictions with the current contract

Contract (`redact-secret-benchmarks` `benchmarks/lib/assessment.ts`, key
`connection-string`, `origin/main` `f57e895`): tier T3, `twinSource` RFC 3986
§3.2.1, observed 2026-09-20. Detector:
`crates/secret-scan-core/src/detectors/connection_string.rs`. It has 10
`SCHEMES`, the RFC 3986 `is_userinfo_char` set, and `MAX_PASSWORD_LENGTH` 4096.
It sets no minimum length.

1. **"The password value has no grammar."** RFC 3986, RFC 1738 and RabbitMQ
   each restrict the alphabet. What the value lacks is a length and an
   identifying element.
2. **Vendors disagree on the alphabet.**
   - MongoDB requires `$` to be encoded, but RFC 3986 allows it raw.
   - MySQL Connector/J requires `( ) & =` to be encoded, but RFC 3986 allows
     these raw as sub-delims.
   - RabbitMQ forbids a raw `:`, but RFC 3986 userinfo allows it.
   - RFC 1738 allows raw `; ? & =` and forbids a raw `:`.

   All sources agree only that a raw `@`, `/` or `?`/`#` breaks the URI. An
   alphabet twin would have to be scheme-specific.
3. **Password surfaces outside userinfo.** The family description ("Password
   embedded in a URI's userinfo component") does not cover these, and neither
   does the detector:
   - PostgreSQL `password=` parameter
   - the Redis IANA `password` query key
   - MySQL/MariaDB JDBC `password=` properties
4. **Azure Storage `AccountKey=`.** The same `connection-string` detector also
   parses this key=value grammar, which lies outside the family's userinfo
   definition. This may be a scope mismatch between detector and taxonomy.
5. **Minimum length.** The detector accepts 1 character. Most tools require at
   least 3. This is not provider-backed either way.
6. **Fixture gap (from fixture IDs only).** No positives or twins were seen for
   `postgresql`, `mongodb+srv`, `rediss`, `amqp` or `amqps`.

## Sources checked

Every class listed in the issue's "Done when" was checked for the RFC and for
all 10 supported schemes. The vendor-level tables with URLs and 2026-09-22
dates are in the [second-pass](https://github.com/redact-secret/redact-secret/issues/651#issuecomment-5784951351)
and [broad-discovery](https://github.com/redact-secret/redact-secret/issues/651#issuecomment-5785441567)
comments. This table adds the 2026-09-23 checks.

| source class | result |
| --- | --- |
| RFC / standards | RFC 3986 §3.2.1, §2.2, §2.3, §7.5 and RFC 1738 §3.1 (2026-09-23): alphabet and delimiter only. RFC 2396 §3.2.2 (2026-09-23): the same `userinfo` production; it "strongly disrecommend[s]" passwords. IANA URI scheme registry: `redis`, `rediss` and `mongodb` are provisional and third-party-registered; the others are unregistered. `draft-patrick-lambert-odbc-uri-scheme-00` (expired 2015): `[user]:[password]` placeholder, no grammar |
| product docs and API reference (incl. OpenAPI) | PostgreSQL libpq, MySQL refman, MariaDB connectors, MongoDB manual, Redis CLI/client/ACL docs, RabbitMQ URI spec and passwords page: no length or identifying element. MongoDB Atlas Admin API v2 `CloudDatabaseUser.password` says "Alphanumeric", `minLength: 8`. It covers the Atlas API only and conflicts with the MongoDB manual |
| changelog / release notes | PostgreSQL 9.2 release notes (URI added), MySQL Shell and refman notes, Redis 7.8.x notes, RabbitMQ domain search: no password-format statement. Coverage used key pages plus domain-restricted search, not every archive |
| engineering / security blog | MongoDB secret-scanning and Kingfisher posts, and domain searches for postgresql.org, redis.io and rabbitmq.com: no format |
| secret-scanning partner pages | The GitHub supported-patterns list has GitHub's own generic `postgres_connection_string`, `mysql_connection_url` and `mongodb_connection_string` (tool rules; regex not published) and the partner `mongodb_atlas_db_uri_with_credentials` (no format published). There is no PostgreSQL, MySQL, MariaDB, Redis or RabbitMQ partner |
| SDK / CLI docs on provider domain | MySQL Connector/J URL format, MariaDB Connector/Python and Connector/J, Redis node/py clients: examples and encoding rules only |
| tools (corroboration only) | trufflehog, gitleaks, betterleaks, Nosey Parker and GitGuardian ("Prefixed: False"): a minimum of 3 characters and a maximum between 50 and 256. None uses an identifying element |
| community | Stack Overflow q/23353623 and web search on 2026-09-23 (squash.io, prisma discussion #15679, goose #935): percent-encoding advice only. Neon Discourse, through search restricted to community.neon.tech (2026-09-23): 10 threads, none about password format |

**Not read (recorded as unchecked):**
- **Reddit.** `www.reddit.com/search.json` returned an HTML shell to `curl` on
  2026-09-23. The web-search tool refuses `reddit.com` ("not accessible to our
  user agent").
- **The Neon Discourse JSON API.** It returned HTTP 522.

Neither source class can meet the T1 bar, so neither changes the verdict.

**Search-engine summaries not confirmed by the pages.** On 2026-09-23, web
search summaries claimed `AVNS_` and `npg_` statements on these pages:
- `aiven.io/docs/tools/cli/user`
- `neon.com/docs/connect/connect-from-any-app`
- `neon.com/faqs/reset-database-password`
- `api-docs.neon.tech/reference/getprojectbranchrolepassword`
- `aiven/aiven-client` `cli.py`

When fetched, none of these pages contains `AVNS_` or `npg_` (0 occurrences
each). The claims are not relied on.

## Open items

- **PlanetScale subfamily.** `https://planetscale.com/docs/postgres/connecting/quickstart`
  was re-fetched 2026-09-23. Under the heading "Password format", it says:
  > All PlanetScale Postgres passwords begin with `pscale_pw_` followed by a unique string

  This meets the T1 bar for a *PlanetScale password* family, but it is new
  scope under AGENTS.md: a spec-file row plus evidence, filed separately. It
  does not raise this family's tier. The body length is unresolved: doc
  examples show 32, trufflehog says 43, and gitleaks says 32–64.
- **Neon `npg_` and Aiven/DigitalOcean `AVNS_`.** The only support is examples
  and affiliated-labs code. There is no provider prose. Each needs a
  provider-domain statement or an empirical check before it can become a
  subfamily. The empirical checklist is in the
  [broad-discovery comment](https://github.com/redact-secret/redact-secret/issues/651#issuecomment-5785441567).
- **Contract wording.** Correct the `twinSource` "no grammar" text (see
  contradiction 1) in redact-secret-benchmarks#112.

## What this document does not do

It does not change any detector, contract, fixture or tier. It does not touch
`docs/contracts/precision/precision-contracts.json` or the benchmarks
`assessment.ts`. It contains no credential and no full example password value.

## Authority

This document records evidence. It does not select a version, create a tag,
publish a package, or authorize any release operation.
