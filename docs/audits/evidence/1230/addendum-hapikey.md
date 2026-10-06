# Addendum to #1230: the `hapikey` query parameter

**Result:** the pre-decided repair the [#1230 record](README.md) named, taken now
that its second condition is met. The independent round-1 measurement of Group E
(benchmarks, candidate `e1284537`) reproduced the miss: all 32 scored cases of
`hubspot:legacy-api-key` (`G-hapikey`) had no finding on any surface or chunking
(31 silent, 1 with a finding on a neighbouring password only). Before: the value
of `hapikey` stayed in the `--redact` output. After: it is a `contextual_secret`,
high, `redact`, exactly the value. Evidence is project-authored and
maintainer-only, not independent validation.

## Evidence read (read-only, `snapshot-2026.10.06.5`)

* Case `hubspot-legacy-api-key-hapikey-query-parameter-value` (`must-flag`, basis
  `project-policy`, credential-evidence#238): HubSpot documents that a request with
  an API key adds it in a `hapikey=` query parameter, and that the account API key
  and the developer account API key differ only by account type and travel in the
  same parameter. The value is flagged "because of where it sits, not because of
  its shape"; no prefix, alphabet or length is claimed; the account key's sunset
  (2022-11-30) is "not a reason to stay silent". Extent: the value only; the
  parameter name, `=`, `&` and the other parameters (`appId`) are outside it.
* Case `hubspot-legacy-api-key-placeholders-masked-display-and-references`
  (`must-not-flag`): `{YOUR_DEVELOPER_API_KEY}`, a masked display, an angle
  placeholder, an environment reference, an empty parameter and a sentence that
  names the parameter.
* The #1225 whole-name admission rule: the evidence names the exact field, and a
  baseline shows the miss. Both hold.

## Root cause

`hapikey` is not in the contextual vocabulary
(`generic_token.rs` `HIGH_SIGNAL_NAMES`, `EXACT_HIGH_SIGNAL_NAMES`) and is not a
`*_key`, `*_token` or `*_secret` name, so `?hapikey=<value>` was a query parameter
the generic reader never evaluated. `HUBSPOT_API_KEY=` was read (it ends in
`api_key`), `HAPIKEY=` was not.

## The change

`hapikey` is added to `EXACT_HIGH_SIGNAL_NAMES` and to
`PREFIXED_EXACT_HIGH_SIGNAL_NAMES` (`crates/secret-scan-core/src/detectors/generic_token.rs`).
`HAPIKEY`, `hapikey` and `hapiKey` normalize to the same name; a user prefix is
read like `MYAPP_API_KEY` (`HUBSPOT_HAPIKEY`, `MY_HAPIKEY`) and a prefix that says
the value is not the secret (`publishable_`) still excludes it. The 8-byte floor,
the entropy tiers and every shared placeholder, reference and mask exclusion apply
unchanged; the brace placeholder `{YOUR_DEVELOPER_API_KEY}` is silent through the
[#1234 brace rule](../1234/addendum-brace-angle-mask-placeholders.md). The finding
is generic: no HubSpot type, no era, no account or developer key subtype.

## Measured behaviour (synthetic values built at run time; whole input, 7-byte and 1-byte chunks equal)

| Input | Before | After |
| --- | --- | --- |
| `GET /x?count=10&hapikey=<v> HTTP/1.1`, first, middle and last parameter, CRLF, no HTTP version, end of input, trailing whitespace | silent | high, `redact`, exactly `<v>` |
| curl URL in double, single or no quotes, with `&appId=<id>` before or after | silent | same; `appId` untouched |
| JSON `baseUrl` string, last parameter or not; percent-escaped neighbours | silent | same |
| shapes: 32 hex, UUID layout, 64 alphanumeric, 40 URL-safe, 16 lower-case, hyphenated, dotted and underscored, 150 bytes, 16 bytes | silent | same |
| `HAPIKEY=<v>`, `export HAPIKEY="<v>"`, `HUBSPOT_HAPIKEY=<v>`, `MY_HUBSPOT_HAPIKEY='<v>'`, `"hapikey":"<v>"`, YAML `hapikey: <v>` | silent | same |
| `{YOUR_DEVELOPER_API_KEY}`, `<your-api-key>`, `${HUBSPOT_API_KEY}`, `$HUBSPOT_API_KEY`, `SY************01`, 36 `*`, `YOUR_API_KEY`, `{{ ... }}`, empty value, prose naming the parameter | silent | silent |
| `hapikeyId`, `hapikey_id`, `hapikeyHint`, `hapikeys`, `hapikey_expires_at`, `appId`, `portalId`, `mask_hapikey_note`, `publishable_hapikey` | silent | silent |

## Tradeoffs

* False positive added: a non-secret literal of 8 or more bytes in this
  parameter that the placeholder rules do not name. The parameter exists only to
  carry a key.
* False positive on the prefixed form: any name ending in `hapikey` (a made-up
  word; no other use is known).
* False negative kept, stated: a value under 8 bytes; a split value; a digits-only
  value is the [digits-only record](addendum-digits-only-values.md)'s case; the
  `hapikey` carried in a path segment or a header is not a parameter or member
  name and is not read.
* No attribution, no width, no alphabet and no era claim: the retired account key
  and the current developer key are read alike, as the Case says.

## Per-party consequences

* Product: the Group E `hubspot:legacy-api-key` positives become exact; the
  `hapikey` neighbours stay silent.
* Benchmarks: the `query-*`, `fx-*`, `developer-key-*` cases are expected to move on
  a re-run at a commit carrying this fix, except `query-shape-digits24`, which
  moves with the [digits-only record](addendum-digits-only-values.md).
* credential-evidence: no correction.

## Tests

`crates/secret-scan-core/tests/hubspot_hapikey_1230.rs` (5 tests): every shape in
raw request lines, curl, JSON configuration URLs; the name as a variable, member,
YAML property and assignment; context, large preceding body and neighbours;
placeholders, masks, references, empty and prose silent; neighbouring names silent.
Every input runs whole, in 7-byte chunks and in 1-byte chunks with equal text and
findings.
