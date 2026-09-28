# #860 handoff: `clickhouse-cloud:api-key`

[#860 handoff index](README.md) ·
[Research table #42](https://github.com/redact-secret/redact-secret/issues/860#issuecomment-5852387097) ·
[Issuance research](issuance-research/clickhouse-cloud.md)

**Readiness: READY** (closed by research under the existing rulings,
2026-09-28; was ISSUANCE-GATED). **Route:** new detector
`clickhouse-cloud-api-secret`, finding type `clickhouse_cloud_api_secret`.
The key ID stays unclaimed. Scheduled for Beta.12; no detector code merges
to `main` until `0.1.0-beta.11` is released.

## Role and blast radius

A ClickHouse Cloud API key is a key-ID / key-secret pair, used as HTTP Basic
credentials against the Cloud control-plane API
(`CLICKHOUSE_CLOUD_API_KEY` / `CLICKHOUSE_CLOUD_API_SECRET`). An admin key can
create, scale and delete services and manage members. Only the secret carries
a detectable marker.

## Supported shape

Sources:

- the `4b1d` prefix, stated by a ClickHouse employee in
  [gitleaks PR #1826](https://github.com/gitleaks/gitleaks/pull/1826)
  (merged 2025-04-16): "we specifically choose a prefix (4b1d...)". T1 under
  R3, **as of 2025-04**;
- the same author's rule `4b1d[A-Za-z0-9]{38}`;
- `4b1d` + 38 mixed-case alphanumeric example values in the provider-owned
  Terraform provider examples since 2023-05.

**Re-checked 2026-09-28:** PR #1826 is merged (2025-04-16). No newer provider
statement was found. The live OpenAPI spec still has no pattern, length or
example for `keySecret`.

| Part | Grammar | Provenance | Tier |
| --- | --- | --- | --- |
| Prefix | `4b1d` | provider staff (R3, 2025-04) + provider examples | T1 as of 2025-04 |
| Body | exactly 38 | staff-authored regex (R2, R3) + provider Terraform examples and a unit-test fixture | T1 as of 2025-04-16 (the 2023 39-byte KB example is older, so R3 date order sets it aside) |
| Alphabet | `[A-Za-z0-9]`, mixed case | staff-authored regex + examples | T1 as of 2025-04 |
| Separators / checksum | none | — | — |

Total 42.

**Re-checked again 2026-09-28** ([issuance research](issuance-research/clickhouse-cloud.md)):
the gitleaks rule file is unchanged at HEAD; a second, distinct 42-byte
sample exists in the provider's Terraform unit tests (added 2024-07); the
39-byte value is the only such instance in the ClickHouse org.

## Why it is READY

Step 3 gated the contract on one contradiction: a provider-authored
knowledge-base Terraform example has a **39-byte** `4b1d` secret (35 after
the prefix), against 42 everywhere else.

The [issuance research](issuance-research/clickhouse-cloud.md) resolved it
under R3's date ordering. The 39-byte example dates from 2023-09-02 and is a
single hand-written docs sample. The staff statement and regex (2025-04-16)
are newer, and every other provider sample (Terraform examples since 2023-05,
a unit-test fixture from 2024-07) is 42. The maintainer accepted this on
2026-09-28 ([issuecomment-5880547337](https://github.com/redact-secret/redact-secret/issues/860#issuecomment-5880547337)):
`4b1d` + 38 `[A-Za-z0-9]`, T1 as of 2025-04-16.

The research also found that the API accepts a caller-supplied pre-hashed
key (`hashData`), so a secret chosen that way has no fixed shape; that is an
accepted false negative.

## Excluded shapes

| Shape | Why excluded |
| --- | --- |
| Key ID (Basic-auth username; no prefix; 17 or 20 alphanumerics, unresolved) | non-marker, and overlaps generic ids. Named contexts cover it |
| `4b1d` inside a UUID (`…-4b1d-…`) or hex strings | `-` stops the run, and hex fails the proposed mixed-case check |
| Secrets supplied through `hashData` (caller-chosen, any shape) | no shape to detect; the provider CLI documents the pre-hashed route |
| Database user passwords, ClickStack/HyperDX keys | separate credentials, not researched |

## Overlap and output policy

- **Existing detectors.** None claims `4b1d`. Basic-auth `keyId:secret` pairs
  in URLs or headers can overlap `connection_string_password` and
  `authorization_credential`; the provider type wins the secret's span.
  Measured on `main`: named contexts `contextual_secret`, Bearer
  `bearer_token`; bare, chat and JSON `"token"` are missed.
- **Planned output.** Provider type, high confidence, always redact.

## Implementation notes

`PrefixShape::exact("4b1d", 38, is_alnum, …)` with a post check, as project
policy, that the body contains at least one uppercase letter. The examples and staff regex
are mixed case. P(no uppercase in 38 random alphanumerics) = (36/62)^38 ≈
1e-9. The check removes every hex digest and lowercase id that happens to
start with `4b1d`. Boundary `[A-Za-z0-9_-]`.

The leading boundary matters: `4b1d` is valid hex, so a longer hex or base64
run containing `4b1d` must not match mid-run.

## Test axes

**Positives:**

- every index context;
- the Terraform `token_secret = "…"` form;
- `--user $KEY_ID:<secret>` curl Basic auth;
- `CLICKHOUSE_CLOUD_API_SECRET=`.

**Near-miss twins:**

- body of 37 or 39 (the 39-byte total KB shape, 35 after the prefix, stays
  unclaimed);
- an all-lowercase or all-hex body;
- `4B1D`;
- `4b1c`;
- a leading glue byte (`a4b1d…`) and a trailing glue byte;
- a `-` in the body.

**Benign:**

- UUIDs containing `-4b1d-`;
- 40/64-hex digests starting `4b1d`;
- the key ID alone;
- the docs' `mykeysecret` / `mykeyid` placeholders under `KEY_SECRET` / `KEY_ID`.

## False-positive / false-negative boundary

- **False negatives:**
  - a second live width, if one exists (no newer source shows one);
  - secrets supplied through `hashData`;
  - an all-lowercase body (about 1e-9);
  - key IDs outside named contexts.
- **False positives:** a mixed-case alphanumeric run of exactly 42 bytes
  starting `4b1d` at a boundary. This is rare.

## Issuance checklist (optional confirmation; structure only)

1. Create one API key in the ClickHouse Cloud console.
2. Record for the **secret**: total length (expect 42; a match moves the
   "as of" date to the issuance date),
   whether it starts with the literal `4b1d`, alphabet classes (upper, lower,
   digits, any punctuation).
3. Record for the **key ID**: length and alphabet classes. This settles the
   17-vs-20 question but does not make the ID detectable.
4. Optionally, the same for a query-endpoint key (the provider CLI docs say
   query endpoints use ordinary org API keys).
5. `rawValueRetained: false`, revoked.
