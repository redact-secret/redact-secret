# #1014 handoff: `mapbox:secret-access-token`

[#1014 index](README.md) · rank 19 ·
[Research table #09](https://github.com/redact-secret/redact-secret/issues/1014#issuecomment-5900446812)

**Readiness: READY, conditional on ruling Q7** (a structural floor derived from
provider code is T1; see [What depends on Q7](#what-depends-on-q7)). **Route:**
new detector `mapbox-token`, finding type `mapbox_secret_access_token`
(`sk.`). Temporary `tk.` and public `pk.` tokens stay unclaimed.

## Role and blast radius

A Mapbox secret access token (`sk.`) is for server-side use. The provider
documents that it can carry secret scopes: uploads, tilesets, styles,
datasets, token management and account reads, plus billable API use. It is
typically pasted into `MAPBOX_SECRET_TOKEN`/`MAPBOX_DOWNLOADS_TOKEN`-style
env vars, `.npmrc`/`gradle.properties` downloads credentials and scripts.
The public `pk.` token is designed to ship in client code and is not a secret.

## Supported shape

Discovery was broad first (web search, GitHub issues and discussions, a
Drupal module tracker, scanner rule sets, vendor exposure docs), and sources
are labelled afterwards. Re-checked 2026-09-30.

- **Provider docs**, "Tokens", <https://docs.mapbox.com/api/accounts/tokens/>
  (undated page): "Each token is a string delimited by dots into three parts:
  header, payload, and signature"; the header is the literal `pk`, `sk` or
  `tk`; the payload is "a base64-URL-encoded JSON object containing the
  identity and authorities of the token"; `tk` tokens embed their metadata in
  the payload. The page states no segment length, maximum length or stability
  guarantee. Its one example is a `pk.` token; counted by hand (value not
  reproduced): payload 63 base64url characters decoding to a 47-byte JSON
  object with two claims, `u` (username) and `a` (a 25-character token id),
  signature 22 base64url characters (16 bytes). Every `eyJ` payload begins
  with the JSON opener `{"`.
- **Provider code (R1)**, `mapbox/parse-mapbox-token` `index.js` at
  [`015a6b4`](https://github.com/mapbox/parse-mapbox-token/blob/015a6b470fdb489a2635a4889c9f5b1d545a512c/index.js)
  (2026-06-29): `token.split('.')`, usage is the first part, the second part is
  base64-decoded and `JSON.parse`d into `u`, `a`, `exp`, `iat`, `scopes`,
  `client`, `ll`, `iu`. It validates nothing but presence of the payload. Its
  tests use `sk.`, `pk.` and `tk.` fixtures whose third segment is 22
  characters.
- **Scanner rule sets (T2, they disagree):** trufflehog `mapbox` at
  [`48b58d3`](https://github.com/trufflesecurity/trufflehog/blob/48b58d3bf3f02ba17bf23b87f095499bc80c6fd7/pkg/detectors/mapbox/mapbox.go#L25)
  `sk\.[a-zA-Z-0-9\.]{80,240}` with the keyword `mapbox`; noseyparker
  [`2e6e7f3`](https://github.com/praetorian-inc/noseyparker/tree/2e6e7f36ce36619852532bbe698d8cb7a26d2da7/crates/noseyparker/data/default/builtin/rules)
  `mapbox.yml` payload `{32,128}` and signature `{20,30}` within 30 characters
  of the word `mapbox`; a vendor exposure doc (RedHunt Labs) `pk\.eyJ…{43,}`
  plus `{6,}`; a community issue proposing `sk\.eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}`
  ([omerbek/repodx#69](https://github.com/omerbek/repodx/issues/69),
  2026-09-25, third-party, cites "Mapbox's docs" without a link).
- **Empirical, independent (T2):** a Drupal module tracker records Mapbox
  access tokens at 98 characters in 2022 and a comment in 2024-08 that they
  "increased in size further", after which the module raised its field limit
  to 255 ([drupal.org/project/mapbox/issues/3302050](https://www.drupal.org/project/mapbox/issues/3302050)).
  So the payload grows with the account and token contents and has no
  provider-stated bound.
- **Public-by-design:** [GitHub community discussion #198585](https://github.com/orgs/community/discussions/198585)
  (forum, reporter not staff) reports the `pk` tokens being flagged as secrets
  and quotes the provider's rule "all public access tokens start with `pk`".

| Part | Grammar | Provenance | Tier |
| --- | --- | --- | --- |
| Prefix | `sk.` | docs (literal header), parser code | T1 |
| Payload | `eyJ` + `[A-Za-z0-9_-]{20,}` (open-ended; 23 is the smallest JSON of the documented two-claim shape) | base64url: docs; `{"` lead and two claims: parser code (R1); upper bound: none (Drupal shows growth) | T1 alphabet and shape; floor derived, see Q7 |
| Separator | `.` | docs | T1 |
| Signature | exactly 22 `[A-Za-z0-9_-]` | docs example plus provider fixtures (R5) | T1 (R5) |

Third-party width ranges (20 to 30 for the signature) are looser than the
provider's 22 and are not used; R8 forbids narrowing an alphabet from a
third-party library, and this contract does not narrow one.

## What depends on Q7

The payload width is unbounded and the provider states no floor. A floor is
needed so the contract has a finite lower bound: `sk.eyJ` + 20 payload
characters + `.` + exactly 22 gives 3 + 3 + 20 + 1 + 22 = 49 characters. It is
derived from the documented `{"u":…,"a":…}` object, not stated by Mapbox.
The 22-character signature tail is the real anchor, so the floor has little
false-positive effect. **Q7** (see the index, added by this record) asks
whether a floor derived from provider code or wire format may serve as the T1
floor. If it is refused, this handoff stays READY only for values that show
a documented `u`+`a` payload (`eyJ1Ijoi`), which is narrower.

## Excluded shapes

| Shape | Why excluded |
| --- | --- |
| `pk.` tokens | public by design; must never be redacted (Q5) |
| `tk.` temporary tokens | documented to expire within one hour and to embed scopes in the payload; short-lived, payload grammar richer; unclaimed pending the maintainer (Q9) |
| Payload not starting `eyJ` | no fixture, doc or scanner shows a non-JSON payload |
| Signature shorter or longer than 22 | not issued in any provider example or fixture; accepted false negative if Mapbox changes the signature |
| Bare `sk.` + word text (for example `task.`-glued or `sk.` in a sentence) | fails the `eyJ` anchor and the 22-character tail |

## Tier rationale

Prefix: T1 (docs and provider parser). Structure and alphabet: T1 (docs,
parser). Signature length: T1 by R5 (one docs example plus provider fixtures
agree at 22). Payload: alphabet T1, floor T1 only if Q7. Scanner rules and
forum proposals are T2 and are used only to show that nobody reports a
contradicting shape.

## Overlap and output policy

- **Existing detectors.** `jwt` needs a header that starts `eyJ`, and a
  Mapbox token's header is `sk`, so `jwt` does not claim it and R7 does not
  apply; the test must prove the contract claims the whole `sk.…` span and
  that `jwt` does not double-report the payload. No detector claims `sk.`
  (OpenAI and similar use `sk-`, a dash). Measured on `main` `b9e9091`: a
  `MAPBOX_*` env assignment gives `contextual_secret`; bare, chat and JSON
  `"token"` are missed.
- **New output.** One provider type, high confidence, always redact.

## Implementation notes

`KnownFormatProviderDetector` anchored on `sk.eyJ`; payload run
`[A-Za-z0-9_-]` of at least 20, a `.`, then exactly 22 of the same class;
identifier-continuation boundary before `s` and after the last signature byte
(so a 23rd signature byte rejects). Signals: `mapbox-documented-prefix`,
`mapbox-parser-structure`. Keep `pk.` out of every prefix table.

## Test axes

**Positives:** every #860 index context; `MAPBOX_SECRET_TOKEN=` and
`SK_MAPBOX=` style env; a `.npmrc`/`gradle.properties` downloads credential;
a JSON `"token"`; payloads of 20, 55, 63, 100 and 250 characters; a payload
containing `-` and `_`.

**Near-miss twins:** signature of 21 and 23; payload of 19; a payload
missing `eyJ`; `SK.` uppercase; `sk_` and `sk-` separators; a leading glue
byte; a missing second dot; a `pk.` token of identical shape.

**Benign:** `pk.` tokens; `tk.` tokens; a three-part JWT; Mapbox style or
tileset ids (`user.abc123`); `sk.` inside a longer word.

## False-positive / false-negative boundary

- **Accepted false negatives:** `tk.` tokens; a future signature length; any
  token whose payload does not start `eyJ`.
- **Accepted false positives:** a non-Mapbox `sk.eyJ…` followed by exactly 22
  base64url bytes; none is known.

## Issuance checklist (optional confirmation; structure only)

For one secret token, total length, the payload length and its first four
decoded bytes class (expect `{"u"`), the signature length (expect 22),
`rawValueRetained: false` and revoked. Not required for READY.
