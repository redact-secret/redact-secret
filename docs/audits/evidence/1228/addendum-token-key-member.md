# Addendum to #1228: the `tokenKey` member of the HubSpot access-token-info request

**Result:** a measured product gap, fixed by a scoped reader, not by a
vocabulary name and not by a change to the bare `token` rule. The independent
round-1 measurement of Group C (benchmarks, candidate `e1284537`) found the
`tokenKey` body member silent on every surface and chunking: 17 scored cases of
`hubspot:private-app-access-token` (`G-token-member`, HubSpot half), 15 with no
finding and 2 with a finding on a neighbouring password only. Before: the token
stayed in the `--redact` output. After: it is a `contextual_secret`, high,
`redact`, exactly the value. The Contentful `token` half of `G-token-member` is a
separate record (the Contentful create-response addendum of #1228).
Evidence is project-authored and maintainer-only, not independent validation.

## Evidence read (read-only, `snapshot-2026.10.06.5`)

* Case `hubspot-private-app-access-token-bearer-header-and-token-key-member`
  (`must-flag`, basis `project-policy`, redact-secret#1228 Group C): HubSpot
  documents the private app access token as the `tokenKey` body field of
  `POST /oauth/v2/private-apps/get/access-token-info`; no prefix, alphabet, length
  or grouping is stated (`no-hubspot-statement-of-token-layout`), so the value is
  flagged "because of where it sits, not its shape"; the extent is the value
  only. The evidence fixtures carry the body as `{"tokenKey":"<v>"}` in a raw
  request and a curl `--data` argument.
* Case `hubspot-private-app-access-token-placeholders-references-and-masks`
  (`must-not-flag`): the documented `Bearer [YOUR_TOKEN]` form, a `tokenKey`
  member holding `[YOUR_TOKEN]`, an environment reference, a masked display and
  prose that names the member.
* The #1228 record said a `tokenKey` entry is a candidate "only if the baseline's
  benign controls separate it from other `tokenKey` uses". The baseline's
  controls are the placeholder, mask, reference and prose forms, which existing
  rules already keep silent; they do not exercise any other use of the name. The
  separation is therefore made by the scope below and measured on the
  maintainers' repositories, not claimed from the baseline.

## Root cause

`tokenKey` normalizes to `token_key`, which is not a vocabulary name and does not
end in a name the contextual vocabulary reads (`_token`, `_secret`, `_api_key`,
`_password`): the bare `_key` suffix is deliberately not a rule (`sort_key`,
`cache_key`, `primary_key`). So `{"tokenKey":"<v>"}` was never an assignment the
generic reader evaluated.

## The change

A new module `crates/secret-scan-core/src/detectors/scoped_context.rs` holds
name-scoped readers: a scoped name is read only when its carrier or context is
present, and the value is judged under an existing high-signal name (the alias),
so the 8-byte floor, the entropy tiers and every placeholder, reference and mask
exclusion apply unchanged. It adds no vocabulary name and widens no bare-name
rule. The first entry:

* `token_key` is read **only as a quoted JSON member name** (`"tokenKey":`, also
  inside a JSON string serialized into another, `\"tokenKey\":`), judged as
  `access_token`. `tokenKey=<v>` and `GET /x?tokenKey=<v>`, `const tokenKey = "<v>"`,
  `tokenKey: <v>`, `TOKEN_KEY=<v>`, an unquoted object key and a call keyword are
  not read.
* The name also names the storage key an application saves a token under
  (`localStorage.setItem(tokenKey, ...)`, `{ tokenKey: "auth_token" }`), so a
  value that is itself a credential name is a reference: a lowercase
  credential-noun phrase (`access_token`, `auth-token-storage-key`) or a camelCase
  name ending in a credential noun (`refreshToken`,
  `authorizationTokenStorageKey`).

The square-bracket placeholder `[YOUR_TOKEN]` HubSpot writes is added to the
closed brace placeholder rule of the [#1234 addendum](../1234/addendum-brace-angle-mask-placeholders.md)
(`{name}` or `[name]`, same grammar), because the Case's must-not-flag member
holds it and it was a medium `warn` under `tokenKey`.

## Measured behaviour (synthetic values built at run time; whole input, 7-byte and 1-byte chunks equal)

| Input | Before | After |
| --- | --- | --- |
| `{"tokenKey":"<v>"}` compact, spaced, pretty, CRLF and tabs, first or last member, escaped inside a JSON string | silent | high, `redact`, exactly `<v>` |
| a raw request with the body, `curl --data '{"tokenKey":"<v>"}'` | silent | same |
| shapes: 40 alphanumeric, hyphenated, dotted and underscored, 150 bytes, 16 bytes, a UUID layout, the `pat-na1-` layout (observed, not claimed) | silent | same |
| `{"tokenKey":"<v>","password":"<w>"}`, two bodies, multibyte and large context | the password only | both values, each exact |
| `[YOUR_TOKEN]`, `********`, `<token>`, `{token}`, `${ENV}`, `{{ secrets.X }}`, empty, prose naming the member | silent | silent |
| `{"tokenKey":"accessToken"}`, `access_token`, `auth-token-storage-key`, `refreshToken`, `id_token` | silent | silent (storage-key names) |
| `tokenKey=<v>`, `?tokenKey=<v>`, `const tokenKey = "<v>"`, `tokenKey: <v>`, `TOKEN_KEY=<v>`, `{ tokenKey: "<v>" }` | silent | silent (stated false negative) |
| `tokenKeyId`, `tokenKeys`, `token_key_hint`, `myTokenKey`, `tokenId`, a bare `token` member | silent | silent |

## False-positive measurement

The CLI built before and after this change, every tracked text file of the
maintainers' repositories scanned and the finding sets compared: redact-secret
1,531 files, credential-evidence 4,398, the other sibling repositories 3,232. New
findings: **2**, both the two `tokenKey` fixtures of credential-evidence's
`hubspot-authored.json` (`SYNTHETIC-hubspot-private-app-token-...`, true
positives). Removed findings: 0. No other `tokenKey` use in 9,161 files became a
finding.

## Tradeoffs

* False positive added: a quoted `"tokenKey"` member whose value is a random
  string of 8 or more bytes that is not a credential name (a tenant-specific key
  alias, a cache key); at 16 bytes and random-looking it is `redact`, below that
  or low-entropy a `warn`.
* False negative kept, stated: the value in any layout other than a quoted
  member, a value under 8 bytes, and a storage-key name spelled as a credential
  phrase.
* No HubSpot attribution, no width, alphabet or prefix claim: the finding is the
  generic type.

## Per-party consequences

* Product: the 17 `tokenKey` positives become exact; no neighbouring name's
  reading changes.
* Benchmarks: the `tokenKey-member-*` and `fixture-replay-private-app-token-key-*`
  cases are expected to move on a re-run at a commit carrying this fix.
* credential-evidence: no correction.

## Tests

`crates/secret-scan-core/tests/hubspot_token_key_member_1228.rs` (5 tests): the
member in every layout and shape; context, multibyte and large preceding text,
two bodies and a neighbouring secret; placeholders, masks, references and prose
silent; storage-key names silent; only the quoted member and the whole name read.
`tests/placeholder_brace_angle_mask_1234.rs` gains the square-bracket forms. Every
input runs whole, in 7-byte chunks and in 1-byte chunks with equal text and
findings.
