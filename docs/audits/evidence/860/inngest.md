# #860 handoff: `inngest:signing-key`

[Tier B re-rank](tier-b-rerank.md) ·
[Research table #50](https://github.com/redact-secret/redact-secret/issues/860#issuecomment-5852387196)

**Readiness: READY.** **Route:** new detector `inngest-signing-key`, finding
type `inngest_signing_key`.

## Role and blast radius

An Inngest signing key (`INNGEST_SIGNING_KEY`, with the rotation fallback
`INNGEST_SIGNING_KEY_FALLBACK`) does two jobs:

- it authenticates the app to Inngest's REST API;
- it signs every request between Inngest and the app's serve endpoint.

A leaked key lets anyone invoke, cancel or replay the environment's functions
and forge requests to the app. The SDK sends a derived form,
`signkey-<env>-` + SHA-256 hex of the key bytes, as `Authorization: Bearer`.
That derived form is itself accepted as the API credential, and it has the
same lexical shape as the raw key.

## Supported shape

Sources:

- inngest/inngest provider code at
  [`dabb03f`](https://github.com/inngest/inngest/blob/dabb03f9e093672aaef2ee77eb7accdf0cd00ca3/pkg/authn/signing_key_strategy.go#L15-L25):
  the constants `SigningKeyPrefixTest = "signkey-test-"`,
  `SigningKeyPrefixBranch = "signkey-branch-"` and
  `SigningKeyPrefixProd = "signkey-prod-"`.
- The SDKs (JS `hashSigningKey`, Python `hash_signing_key`, Go `keyRegexp`)
  strip `^signkey-\w+-` and hex-decode the rest.
- `inngest start` rejects a key that is non-hex or of odd length.
- The self-hosting docs
  ([inngest.com/docs/self-hosting](https://www.inngest.com/docs/self-hosting))
  say "The signing key must be a valid hexadecimal string with an even number
  of characters". They generate it with `openssl rand -hex 32`, which gives
  64 lowercase hex.
- SDK test fixtures: every realistic fixture is `signkey-test-` or
  `signkey-prod-` + 64 lowercase hex.

**Re-checked 2026-09-28** (R5 hinges on the length):

- the three constants and `keyRegexp` are unchanged at `dabb03f`;
- the docs page still carries the hex sentence and `openssl rand -hex 32`;
- `inngest-js` `src/test/helpers.ts` at `197812b` still has three
  `signkey-test-` fixtures of exactly 64 lowercase hex, plus one 5-byte
  placeholder.

| Part | Grammar | Provenance | Tier |
| --- | --- | --- | --- |
| Prefix | `signkey-prod-`, `signkey-test-` or `signkey-branch-` | provider code constants; `signkey-prod-` also in a docs curl example | T1 |
| Body | exactly 64 | docs generation command + provider SDK test fixtures (R5, 2026-09-28) | T1 |
| Alphabet | lowercase hex `[0-9a-f]` | provider code (hex decode, `must be hex string`) + docs; lowercase from the generation command and fixtures | T1 |
| Separators / checksum | the `-` after the environment label | provider code | T1 |

Total length 77 (`prod`, `test`) or 79 (`branch`). One finding type covers
the raw key, the fallback and the hashed wire form. They are lexically
identical, and each authenticates.

## Excluded shapes

| Shape | Why excluded |
| --- | --- |
| Other environment labels (`signkey-<x>-`, which `\w+` would admit) | only the three labels are provider constants; a future label is an accepted false negative |
| Self-hosted bare hex key (no prefix) | 64-hex digest shape; not attributable. Generic context still covers `INNGEST_SIGNING_KEY=` (see coverage) |
| Event key (`INNGEST_EVENT_KEY`, URL path `/e/<key>`) | no shape documented; self-hosted event keys are arbitrary strings |
| Uppercase-hex body | the decoder accepts it, but the generator and fixtures never produce it |
| Placeholders `signkey-prod-<YOUR-SIGNING-KEY>`, `signkey-test-12345`, `signkey-prod-000000` | fail the exact-64 body |

## Overlap and output policy

- **Existing detectors.** None claims `signkey-`. Measured on `main`:
  - `INNGEST_SIGNING_KEY=` (plain and `export`) gives `contextual_secret` at
    **medium / warn** only. `signing_key` is in the ambiguous name bucket, so
    today a prefixed signing key in `.env` is warned and not redacted.
  - `X-API-Key`, JSON `api_key` and the SDK keyword argument give
    `contextual_secret`, high, redact.
  - Bearer gives `bearer_token`, high.
  - Bare, chat and JSON `"token"` are missed.
- **New output.** Provider type, `Confidence::High`, in
  `ALWAYS_REDACT_TYPES`. Overlap resolution then reports the provider
  finding (high/redact) over the medium generic one, which closes the
  env-file warn gap.
- **`generic-token` deferral.** `inngest` is **not** added to
  `DEDICATED_PROVIDER_SEGMENTS`: deferring would silence the bare-hex
  self-hosted key under `INNGEST_SIGNING_KEY=`, which only generic context
  can see.

## Implementation notes

Use `KnownFormatProviderDetector` with three
`PrefixShape::exact(prefix, 64, pattern::is_lower_hex, …)` shapes and the
`[A-Za-z0-9_-]` boundary. The prefixes share `signkey-`, and the existing
longest-prefix-wins pass handles them.

Signals: `inngest-code-constant-prefix`, `inngest-hex-body-length`.

## Test axes

**Positives:**

- every context in the re-rank's probe list;
- `INNGEST_SIGNING_KEY=` and `INNGEST_SIGNING_KEY_FALLBACK=` in `.env`;
- `new Inngest({ signingKey: "…" })`;
- a curl line `Authorization: Bearer signkey-prod-…` (the hashed form);
- a Vercel/Netlify env export listing;
- all three labels.

**Near-miss twins:**

- body of 63 or 65;
- one uppercase hex byte;
- one `g`;
- `signkey-preview-` (unknown label);
- `signkey_prod_`;
- `SIGNKEY-prod-`;
- a leading glue byte and a trailing glue byte.

**Benign:**

- the docs and SDK placeholders listed above;
- `INNGEST_SIGNING_KEY=${INNGEST_SIGNING_KEY}`;
- a bare 64-hex SHA-256;
- `INNGEST_EVENT_KEY=local`;
- the `NO_EVENT_KEY_SET` sentinel.

## False-positive / false-negative boundary

- **Accepted false negatives:**
  - self-hosted bare-hex keys outside named contexts;
  - unknown environment labels;
  - uppercased copies;
  - any cloud key that is not 64 hex. No source suggests one exists; the
    optional issuance check below confirms it.
- **Accepted false positives:** `signkey-<label>-` + exactly 64 lowercase hex
  that is not an Inngest key. None is known.

## Issuance checklist (optional confirmation; structure only)

From the Inngest Cloud dashboard, for one production and one branch
environment signing key, record:

- total length;
- the label;
- body length (expect 64);
- alphabet classes (expect lowercase hex);
- whether custom environments use a label other than `prod`/`test`/`branch`;
- `rawValueRetained: false`.

Signing keys rotate rather than revoke, so record whether the key was
rotated after inspection.
