# #860 handoff: `clickhouse-cloud:api-key`

[#860 handoff index](README.md) ·
[Research table #42](https://github.com/redact-secret/redact-secret/issues/860#issuecomment-5852387097)

**Readiness: ISSUANCE-GATED.** **Route:** new detector
`clickhouse-cloud-api-secret`, finding type `clickhouse_cloud_api_secret`,
after the issuance check. The key ID stays unclaimed.

## Role and blast radius

A ClickHouse Cloud API key is a key-ID / key-secret pair, used as HTTP Basic
credentials against the Cloud control-plane API
(`CLICKHOUSE_CLOUD_API_KEY` / `CLICKHOUSE_CLOUD_API_SECRET`). An admin key can
create, scale and delete services and manage members. Only the secret carries
a detectable marker.

## Proposed shape (not frozen)

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
| Body | 38 | staff-authored regex (R3) + provider Terraform examples | T1 as of 2025-04, **contradicted** |
| Alphabet | `[A-Za-z0-9]`, mixed case | staff-authored regex + examples | T1 as of 2025-04 |
| Separators / checksum | none | — | — |

Total 42.

## Why it is gated

A provider-authored knowledge-base Terraform example has a **39-byte**
`4b1d` secret (35 after the prefix), against 42 everywhere else. It could be
an older shape, a hand-edited sample, or a second live width. The staff
statement is 17 months old, so R3's date rule applies: an issued key must
confirm the current length before freezing.

## Excluded shapes

| Shape | Why excluded |
| --- | --- |
| Key ID (Basic-auth username; no prefix; 17 or 20 alphanumerics, unresolved) | non-marker, and overlaps generic ids. Named contexts cover it |
| `4b1d` inside a UUID (`…-4b1d-…`) or hex strings | `-` stops the run, and hex fails the proposed mixed-case check |
| Query-endpoint keys (`QUERY_KEY_ID`/`QUERY_KEY_SECRET`) | whether they carry `4b1d` is not verified |
| Database user passwords, ClickStack/HyperDX keys | separate credentials, not researched |

## Overlap and output policy

- **Existing detectors.** None claims `4b1d`. Basic-auth `keyId:secret` pairs
  in URLs or headers can overlap `connection_string_password` and
  `authorization_credential`; the provider type wins the secret's span.
  Measured on `main`: named contexts `contextual_secret`, Bearer
  `bearer_token`; bare, chat and JSON `"token"` are missed.
- **Planned output.** Provider type, high confidence, always redact.

## Implementation notes (after the gate)

`PrefixShape::exact("4b1d", <confirmed>, is_alnum, …)` with a post check that
the body contains at least one uppercase letter. The examples and staff regex
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

- body one byte shorter or longer than the confirmed width;
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
  - a second live width, if one exists (the gate decides);
  - an all-lowercase body (about 1e-9);
  - key IDs outside named contexts.
- **False positives:** a mixed-case alphanumeric run of exactly the confirmed
  width starting `4b1d`. This is rare.

## Issuance checklist — gate (structure only)

1. Create one API key in the ClickHouse Cloud console.
2. Record for the **secret**: total length (**42 or 39 decides the gate**),
   whether it starts with the literal `4b1d`, alphabet classes (upper, lower,
   digits, any punctuation).
3. Record for the **key ID**: length and alphabet classes. This settles the
   17-vs-20 question but does not make the ID detectable.
4. Optionally, the same for a query-endpoint key.
5. `rawValueRetained: false`, revoked.
