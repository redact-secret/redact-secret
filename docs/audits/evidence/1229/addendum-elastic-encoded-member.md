# Addendum to #1229: the Elastic cross-cluster `encoded` member

**Result:** a measured product gap, fixed by a bounded sibling reader, not by a
vocabulary name. The independent round-1 measurement of Group D (benchmarks,
candidate `e1284537`) found, in `elastic:cross-cluster-api-key`, that the
`api_key` member of a create-cross-cluster-API-key response was exact in 16 cases
while the `encoded` member beside it, the base64 of `id:api_key` and so a complete
credential by itself, was not reported (`G-elastic-encoded`: 17 scored cases, 16
with only the `api_key` finding, 1 wholly silent). Before: the `encoded` value
stayed in the `--redact` output next to a redacted `api_key`. After: it is a
`contextual_secret`, high, `redact`, exactly the value, whenever an `api_key`
member sits beside it. The one case with the `encoded` member alone
(`encoded-member-only`) is recorded as policy-limited, below. Evidence is
project-authored and maintainer-only, not independent validation.

## Evidence read (read-only, `snapshot-2026.10.06.5`)

* Case `elastic-cross-cluster-api-key-create-response-members` (`must-flag`,
  basis `project-policy`, credential-evidence#243): Elastic's specification gives
  the response the members `api_key`, `id`, `name`, an optional `expiration` and
  `encoded`, with `encoded` "the base64 of the UTF-8 id and api_key joined by a
  colon"; the setup page tells the operator to copy `encoded` to a safe place.
  Both the `api_key` and the `encoded` values are spans, the `encoded` span is the
  whole string "consistent with the id and api_key beside it", and `id` is outside
  the spans and unasserted. No alphabet, padding or width is claimed.
* Case `elastic-cross-cluster-api-key-binding-attributes-and-references-non-values`
  and the evidence fixtures: `<ENCODED_API_KEY>`, a mask, empty members, a
  `{{ outputs.encoded }}` template and prose naming the member are non-values.

## Root cause

`encoded` is not a contextual vocabulary name and, as a bare JSON member name, it
must not become one: it is a common member of unrelated documents (a URL-encoded
or base64-encoded field of any kind). The `api_key` member was read by name; its
sibling was never evaluated.

## The change

`crates/secret-scan-core/src/detectors/scoped_context.rs` (the scoped-reader
module introduced with the [`tokenKey` addendum](../1228/addendum-token-key-member.md)):

* `encoded` is read **only as a quoted JSON member name** whose line, or a line
  within the sibling window, carries a quoted `api_key` member. The window is the
  next and the previous five lines, and at most 2,048 bytes from the first of the
  two lines through the last; it is positional, not a parse (a neighbouring
  object's `api_key` within the window counts, which keeps whole-input and
  incremental scans equal). The value is judged under `api_key`: the 8-byte floor,
  the entropy tiers and every placeholder, reference and mask exclusion apply
  unchanged, so a base64 value is `high` and `redact` and the `<ENCODED_API_KEY>`,
  `********`, empty, `{{ outputs.encoded }}` and `${ENCODED}` forms are silent.
  `id` is not read.
* Incremental sessions: `has_open_scoped_context_in`, a retention hint in the style
  of the Deepgram request-block one, holds the unit open while one of the last
  five lines carries an `api_key` or `encoded` member (a line over 2,048 bytes
  never does), so both siblings are scanned together whichever comes first and
  at any chunking. Holding a line that never pairs delays its output by at most
  five lines. A differential test already compares the incremental hint with a
  rescan of the unit after every closed line.

## Measured behaviour (synthetic values built at run time; whole input, 7-byte and 1-byte chunks equal)

| Input | Before | After |
| --- | --- | --- |
| pretty JSON `id`, `name`, `api_key`, `encoded`; compact JSON; a raw HTTP response; curl output; CRLF and tabs; spaced colons; `expiration` between; a nested array; `encoded` before `api_key`; padding `=`, `==` and none | `api_key` only | both `api_key` and `encoded`, each exactly its value, high, `redact`; `id` untouched |
| multibyte text around, a 64 KB preceding body, two responses in a row | `api_key` only | both values of each response |
| the response serialized into an enclosing JSON string (`"text": "{\"api_key\":...}"`) | `api_key` only | both values |
| `<ENCODED_API_KEY>`, `********`, empty, `{{ outputs.encoded }}`, `${ENCODED}`, `{encoded_api_key}`, prose naming the member | silent | silent |
| `{"encoded":"<v>"}` alone, with only `id`, or with `api_key` more than five lines away; `encoded=<v>`, `?encoded=<v>`, `encoded: <v>` | silent | silent |
| `encoded_key`, `encoded_url`, `encodedValue`, `urlencoded` beside an `api_key` | silent | silent |

## Policy-limited: `encoded-member-only`

The Case lists `encoded-member-only` as a must-flag layout (the response with the
`encoded` member and no `api_key`). Reading it needs `encoded` as a bare name or
a decoding of the value to see `id:api_key`; the first adds a vocabulary name
that is a common member of unrelated JSON, and the second reads an encoded
representation, which the decision to [defer encoded-input decoding](../../../decisions/2026-09-20-defer-encoded-input-decoding.md)
keeps outside the input contract. The product does neither: the lone member is a
**stated false negative**, one scored case of the 17. A response that carries only
`encoded` is also the member's one sibling-less form in the documentation's setup
step (the operator copies the member), so the exposure is real; the maintainers
can reopen it with a ruling on either route.

## False-positive measurement

The CLI built before and after the change, every tracked text file of the
maintainers' repositories scanned, finding sets compared: redact-secret 1,534
files, credential-evidence 4,398, the other sibling repositories 3,232. New
findings across the three Group C and D scoped readers so far: **4**, the two
`encoded` values of credential-evidence's `elastic-authored.json` fixtures
(true positives) and the two `tokenKey` fixtures of the previous addendum; no
other `encoded` member in 9,164 files became a finding. Removed findings: 0.

## Tradeoffs

* False positive added: an `encoded` member of 8 or more bytes within five lines
  of an `api_key` member that is not the Elastic response (for example a
  base64-encoded companion field next to a real key); the neighbour is itself a
  credential, so the cost is a redacted companion.
* False negative kept, stated: `encoded` without a sibling, further than five
  lines or 2,048 bytes away, in a non-member layout, and the `id`.
* No Elastic attribution and no decoding: the finding is the generic type and the
  span is the string as written.

## Per-party consequences

* Product: the 16 `encoded` omissions of `G-elastic-encoded` become exact; every
  other family's reading is unchanged.
* Benchmarks: the 16 cases are expected to move on a re-run at a commit carrying
  this fix; `encoded-member-only` stays a miss by recorded policy.
* credential-evidence: no correction; the Case's lone-member layout is the
  product's stated limit, listed above.

## Tests

`crates/secret-scan-core/tests/elastic_encoded_member_1229.rs` (6 tests): every
documented layout at four key lengths (padding `=`, `==`, none); context, large
preceding body, an id with the key's shape and two responses; placeholders, masks,
references, empty members and prose silent; the member alone, a sibling too far
away, other member names and non-member layouts silent; a window that crosses
objects; the members inside an enclosing JSON string. Every input runs whole, in
7-byte chunks and in 1-byte chunks with equal text and findings; with the
retention hint disabled the pretty layouts fail the chunked runs.
