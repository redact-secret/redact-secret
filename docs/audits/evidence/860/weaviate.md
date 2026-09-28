# #860 handoff: `weaviate:cloud-api-key`

[#860 handoff index](README.md) ·
[Research table #15](https://github.com/redact-secret/redact-secret/issues/860#issuecomment-5852386571)

**Readiness: ISSUANCE-GATED.** **Route:** new detector
`weaviate-cloud-api-key`, finding type `weaviate_cloud_api_key`, after the
issuance check.

## Role and blast radius

A Weaviate Cloud (WCD) API key (`WEAVIATE_API_KEY`, `Authorization: Bearer`)
authenticates to a vector database cluster with a role (admin, viewer or
custom). An admin key reads and writes every collection, including embedded
source documents that RAG agents retrieve.

## Proposed shape (not frozen)

Source: the Weaviate server's generator,
`usecases/auth/authentication/apikey/keys/key_generation.go`. **Re-checked
2026-09-28:** last changed 2026-01-02
([`b2b5023`](https://github.com/weaviate/weaviate/blob/b2b5023894e5abbb278c56ac184873e43ff39181/usecases/auth/authentication/apikey/keys/key_generation.go)).
`DynUserIdentifier = "v200"`, 16-byte and 44-byte Base64 lengths, unchanged.

The key is standard Base64 of `<16-byte b64 user id>` + `_` +
`<44-byte b64 random key>` + `_` + `v200`. The 66-byte inner string encodes
to exactly 88 bytes with no padding, and the last 6 inner bytes (`=_v200`)
always encode to the literal suffix `PV92MjAw`.

| Part | Grammar | Provenance | Tier |
| --- | --- | --- | --- |
| Length | exactly 88 | provider code (R1), derived exactly | T1 (generator) |
| Alphabet | standard Base64 `[A-Za-z0-9+/]`, no `=` | provider code (R1) | T1 (generator) |
| Fixed suffix | `PV92MjAw` | provider code (R1), derived exactly | T1 (generator) |
| Inner structure | decodes to 16 + `_` + 44 + `_v200`, with both parts in the Base64 alphabet | provider code (R1) | T1 (generator) |
| Prefix / separators | none in the encoded form | — | — |

## Why it is gated

The generator is the open-source server's (it serves dynamic database users,
v1.29+). That the closed WCD console issues keys with this generator is
supported only by a provider-authored notebook's printed output and by
empirical sightings next to `*.weaviate.cloud` hosts (ruling R1 covers the
code, not the link to WCD). A future `vNNN` marker would also change the
suffix. The step-2 selection required an issued WCD key to confirm the shape.

## Excluded shapes

| Shape | Why excluded |
| --- | --- |
| Legacy WCD keys: 36 alphanumerics (known only from a docs sample) | generic, UUID-length. Named contexts cover it |
| Self-hosted static keys (`AUTHENTICATION_APIKEY_ALLOWED_KEYS`) | any non-empty string |
| Imported or weak dynamic-user keys (OpenAPI `DBUserCredential`) | not generated, so no shape |
| Cluster URLs, user IDs, `apiKeyFirstLetters` (3 bytes) | non-secret |

## Overlap and output policy

- **Existing detectors.** None claims this shape. A generic high-entropy
  Base64 rule would fire under credential names (`contextual_secret`) and in
  Bearer (`bearer_token`), which is what the probe on `main` shows. Bare, chat
  and JSON `"token"` are missed.
- **Planned output.** Provider type, high confidence, always redact.

## Implementation notes (after the gate)

A bespoke suffix-anchored scan in `detectors::weaviate`:

1. find the literal `PV92MjAw`;
2. require the 80 bytes before it to be `[A-Za-z0-9+/]`;
3. require the byte before those 80 not to be `[A-Za-z0-9+/_-]`, and the byte
   after the suffix not to be `[A-Za-z0-9+/=_-]`;
4. post check: Base64-decode the 88 bytes and confirm the `_` at inner offsets
   16 and 61, the `_v200` tail, and Base64-alphabet bytes in both parts.

The decode is 66 bytes and constant per candidate. It needs no dependency:
`detectors::discord` already decodes an unpadded base64url segment in place
(`decodes_to_ascii_digits`), and the same pattern with the standard alphabet
fits here.
The scan is linear, since each suffix hit checks a fixed 80-byte window.
Signals: `weaviate-generator-suffix`, `weaviate-generator-structure`.

## Test axes

**Positives** (built by the same construction at test time, from seeded
random Base64 parts):

- every index context;
- the Python client's `connect_to_weaviate_cloud` call with the key wrapped in
  `Auth.api_key`;
- `WEAVIATE_API_KEY=`;
- a `.env` beside a `WEAVIATE_URL`.

**Near-miss twins:**

- an 87- or 89-byte run;
- a changed suffix byte;
- a `v201` marker (valid Base64, wrong suffix);
- a `-` or `_` (URL-safe alphabet) in the body;
- `=` padding appended;
- a correct suffix whose decoded inner structure fails (wrong `_` position);
- a leading or trailing Base64 glue byte.

**Benign:**

- generic 88-byte Base64 blobs without the suffix;
- the `sAmPleKEY…` 36-byte docs placeholder (not claimed by this detector);
- cluster hostnames;
- `WEAVIATE_API_KEY=${…}`.

## False-positive / false-negative boundary

- **False negatives:**
  - legacy 36-byte keys and self-hosted static keys outside named contexts;
  - a future version marker;
  - a key split across lines.
- **False positives:** effectively none. The fixed suffix plus the decoded
  structure is a 48-bit-plus structural check.

## Issuance checklist — gate (structure only)

1. In WCD, create one Admin and one Viewer key on a current cluster.
2. Record for each: total length (expect 88), whether it ends with the
   literal `PV92MjAw`, alphabet classes (expect `[A-Za-z0-9+/]` with no `=`),
   `rawValueRetained: false`, revoked.
3. Do not decode or record inner parts. The suffix check is enough to link WCD
   to the generator.
4. Optionally note whether an older cluster still shows a 36-byte key (length
   only).
