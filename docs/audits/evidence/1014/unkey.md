# #1014 handoff: `unkey:root-key`

[#1014 index](README.md) · rank 15 ·
[Research table #24](https://github.com/redact-secret/redact-secret/issues/1014#issuecomment-5900447282)

**Readiness: READY for the two current root-key grammars (version 1 and the
dashboard `3Z` form); BLOCKED for customer-prefixed version 1 keys (needs
ruling Q10) and for root keys older than the current generators (nothing to
cite).** **Route:** new detector `unkey-root-key`, finding type
`unkey_root_key`; `unkey_api_key` only after Q10.

The step-1 claim of a single window `unkey_[Base58]{21,24}` is superseded. The
derivation below found that the Go 21 to 22 form is not minted for users by
current code, and that a third, fixed-width, scanner-oriented format (version 1)
is now the root-key generator. The index row keeps the step-1 text, which is
frozen; this file is the current contract.

## Role and blast radius

An Unkey root key authorizes the Unkey management API for a workspace: create,
update and delete keys, read key metadata, manage permissions and APIs. It is
admin access to the workspace's key infrastructure. A leak lets an attacker mint
keys for the victim's products or revoke real ones. Root keys live in `.env`
files (`UNKEY_ROOT_KEY`), server configs and CI secrets.

## Discovery (broad first, source classes labelled afterwards)

Searched the open web 2026-09-30 (prefix and format queries, Stack
Overflow-style and forum phrasing), then scanner rule sets, then provider docs
and code.

- **Forums and issue trackers.** No post states a grammar or discloses a key.
  The search engine returned only the Unkey docs page on GitHub scanning.
- **Third-party scanner rule sets (T2).** betterleaks `c4c0ffd`
  (`cmd/generate/config/rules/unkey.go`): `unkey_[A-Za-z0-9]{20,32}` with the
  keyword `unkey_` and a validation call to `keys.verifyKey`; Kingfisher
  `7433793` imports it. gitleaks `b58d3f1`, trufflehog `19f011a`, noseyparker
  `2e6e7f3` and osv-scalibr `1e9b16c` have no rule. The betterleaks window
  misses the version 1 form (57 body characters) and accepts base58-illegal
  characters; it is looser and is not used.
- **Partner list.** `unkey_root_key` is a GitHub secret-scanning partner
  pattern with validity check; Unkey's docs say only that root keys "all start
  with `unkey_`" and the pattern itself is not published in docs (source class:
  provider docs, prefix only).
- **Provider design document and code (T1).** RFC 0017 and the generators in
  `unkeyed/unkey`, below.

## Supported shape

Sources, re-checked 2026-09-30 at `unkeyed/unkey`
[`6c9bc65`](https://github.com/unkeyed/unkey/tree/6c9bc65125dd2c8b5038ac80a11e173767dc9e52)
(the step-1 commit) and tip
[`20378e8`](https://github.com/unkeyed/unkey/commit/20378e892035dad8ca3590765651cd25c964f78e)
(2026-09-30):

1. **Version 1 plaintext format, the current generator.**
   - `docs/engineering/architecture/rfcs/0017-api-key-plaintext-format.mdx`
     (RFC 2026-08-17, merged 2026-08-28; provider design document): "one
     plaintext format for all Unkey-generated API keys, including customer API
     keys and Unkey root keys", shape
     `{prefix[1-16]}_{random[8]}unkeyv1{random[36]}{checksum[6]}`, random
     characters from the Bitcoin base58 alphabet, checksum "Fixed-width Base58
     CRC-32C", and a stated GitHub regex
     `[A-Za-z0-9_]{0,15}[A-Za-z0-9]_[1-9A-HJ-NP-Za-km-z]{8}unkeyv1[1-9A-HJ-NP-Za-km-z]{42}`.
     The RFC states it exists so the keys can be detected in source control.
   - `internal/services/keys/create_v1.go`
     ([generator](https://github.com/unkeyed/unkey/blob/20378e892035dad8ca3590765651cd25c964f78e/internal/services/keys/create_v1.go),
     added 2026-09-02, `e0232a1`; provider code, R1 and R9): constants
     `keyV1RandomLength = 44`, `keyV1RandomHead = 8`, `keyV1ChecksumLength = 6`,
     marker `unkeyv1`; 44 uniformly random base58 characters; checksum is
     CRC-32C (Castagnoli) of the unsigned key, big-endian, base58, left-padded
     with `1` to 6.
   - Root-key issuance: `svc/api/routes/v2_root_keys_create_key/handler.go`
     (commit `c36ffcf`, 2026-09-30, "rootKeys.createKey") calls
     `CreateKeyV1` with `Prefix: "unkey"`, and its test asserts
     `^unkey_[base58]{8}unkeyv1[base58]{42}$`. `v2_root_keys_reroll_key` reuses
     the source prefix. So new root keys are `unkey_` + 57, total 63.
   - Verification of the checksum rule: a line-by-line port (CRC-32C, base58,
     `1` padding) reproduces the provider's own known-vector test
     (`TestFormatKeyV1_KnownVector`) exactly, which confirms the algorithm and
     the total of 63.
2. **Dashboard root keys (TS `KeyV1`).** `web/apps/dashboard/lib/trpc/routers/key/createRootKey.ts`
   ([L56–L59](https://github.com/unkeyed/unkey/blob/6c9bc65125dd2c8b5038ac80a11e173767dc9e52/web/apps/dashboard/lib/trpc/routers/key/createRootKey.ts#L56-L59),
   last path commit 2026-09-02, unchanged at tip) calls
   `newKey({ prefix: "unkey", byteLength: 16 })`, and
   `web/internal/keys/src/v1.ts`
   ([L1–L80](https://github.com/unkeyed/unkey/blob/6c9bc65125dd2c8b5038ac80a11e173767dc9e52/web/internal/keys/src/v1.ts#L1-L80);
   the generator dates from 2023-11-22 in the current history) encodes
   `[0x01, 0x10, 16 random bytes]` as base58 (Bitcoin alphabet) and joins with
   `_`. Derivation over this input (scratch script): 18 bytes whose leading two
   bytes are fixed give exactly 24 base58 characters, always beginning `3Z`,
   and the third character lies between `F` and `o` in alphabet order
   (computed at the two extreme random values; 300,000 random samples all had
   length 24 and a `3Z` lead, 33 distinct three-character leads). This is the
   form the step-1 table noted as "verified empirically".

| Key | Grammar | Provenance | Tier |
| --- | --- | --- | --- |
| Root key, version 1 | `unkey_` + `[1-9A-HJ-NP-Za-km-z]{8}` + `unkeyv1` + `[1-9A-HJ-NP-Za-km-z]{42}` (63 total; the last 6 are the CRC-32C) | RFC 0017 and generator and handler test (R1, R9), two independent provider artifacts | T1 |
| Root key, dashboard form | `unkey_3Z` + `[1-9A-HJ-NP-Za-km-z]{22}` (30 total) | generator code (R1, R9); width and lead derived | T1 |

## Excluded shapes

| Shape | Why excluded |
| --- | --- |
| Customer API keys in version 1 (`<any prefix>_…unkeyv1…`) | credentials for the customer's own product, with a customer-chosen prefix 1 to 16 bytes, not Unkey root keys. Unkey's own GitHub scanning deliberately covers root keys only. Needs ruling Q10 (below) |
| Go `CreateKey` output (`unkey_` + 21 or 22 base58, from a 16-byte encode) | the function is marked "Deprecated" and is called for root keys only by the development seed (`cmd/dev/seed/local.go`); the production callers are the v2 customer-key routes with customer prefixes. Not a root-key shape users receive. Kept out until an issued-key check says otherwise |
| Root keys from before the current generators, and imported keys | no provider source states their grammar (RFC 0003 and 0002 are historical proposals with `unkey_[a-zA-Z0-9]+`, not shipped grammars). Needs a maintainer-issued or dated-source check |
| `unkey_` followed by `_` or other non-base58 characters, `unkey_<word>` identifiers | not root keys; base58 has no `_`, `0`, `O`, `I` or `l` |
| Key ids (`key_…`), API ids (`api_…`) | public identifiers |

## Tier rationale

T1. The version 1 grammar is stated by the provider's own design document
(including the regex) and produced by the provider's generator, and a handler
test asserts the exact shape. The dashboard form is T1 by R1 and R9 from
generator code, with the width and the `3Z` lead derived, not stated; the
derivation is exact (the lead is fixed by the leading two bytes). Both are
dated (2026-09-02, 2026-09-30) and current at tip.

## Overlap and output policy

- **Existing detectors.** None claims `unkey_` or `unkeyv1` (checked against
  the detector sources at `main` `cfa87360`). `UNKEY_ROOT_KEY=` is missed as a
  credential name by `contextual_secret` today (step-1 probe); `API_KEY=` is
  found. A dedicated detector closes the bare, chat and JSON `"token"` gap.
- **Checksum (ruling Q1).** Version 1 is offline-verifiable (CRC-32C over the
  whole key before the checksum). Lexical grammar is the contract; a post-check
  that only rejects waits for Q1. The dashboard form has no checksum.
- **New output.** One provider type `unkey_root_key`, high confidence, always
  redact. The version 1 shape already makes the marker a stable scanner anchor.

## Implementation notes

`KnownFormatProviderDetector`, two shapes: `unkey_` then exact 57 base58
(validate positions 9 to 15 of the body equal `unkeyv1`), and `unkey_3Z` then
exact 22 base58. Boundary `[A-Za-z0-9_-]`; the base58 alphabet predicate
excludes `0`, `O`, `I`, `l` and `_`. Signals: `unkey-rfc0017-marker`,
`unkey-generator-prefix`. Version 1 shape must not be shortened to the
betterleaks window.

## Test axes

**Positives:** every #860 index context; `UNKEY_ROOT_KEY=` in `.env`;
`Authorization: Bearer`; `new Unkey({ rootKey })`; the two shapes; values
built at run time (random base58, marker inserted, real CRC-32C), never a
captured key.

**Near-miss twins:** version 1 with a body of 56 or 58; a body where the marker
is `unkeyv2` or sits at another offset; a `0`, `O`, `I`, `l` or `_` in a random
part; the dashboard form with a `3Y` lead or 21 and 23 trailing characters;
`UNKEY_` uppercase; a leading and a trailing glue byte.

**Benign:** `unkey_root_key`, `unkey_mutations`, `unkey_api_id`-style
identifiers; `unkey_` + 24 lowercase letters; `key_` ids; placeholders
`unkey_xxxxxxxxxxxxxxxxxxxxxxxx`.

## False-positive / false-negative boundary

- **Accepted false negatives:** customer-prefixed version 1 keys (until Q10),
  pre-2023 and imported root keys, the Go 21 to 22 form, keys split by
  whitespace.
- **Accepted false positives:** a base58 run with `unkey_3Z` + 22 that is not
  a key; none known (the `3Z` lead is a 1-in-3,000 coincidence for a random
  base58 run, which with the prefix is negligible).

## What is missing

Not a blocker for the two READY shapes. For the rest:

- **Q10 ruling (customer-prefixed version 1 keys).** See the index Q list (new  question Q10).
- **Older root keys:** a maintainer-issued or dated public-source check of a
  pre-2023-11 root key's length and alphabet.

## Issuance checklist (optional confirmation; structure only)

For one root key created in the dashboard and one created through the v2 API:
prefix and total length (expect 30 and 63), the marker position and the `3Z`
lead, alphabet classes, whether the CRC-32C verifies (v2 key only);
`rawValueRetained: false` and revoked.
