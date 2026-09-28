# #860 handoff: `daytona:api-key`

[#860 handoff index](README.md) ·
[Research table #32](https://github.com/redact-secret/redact-secret/issues/860#issuecomment-5852386808) ·
[Issuance research](issuance-research/daytona.md)

**Readiness: READY** (ruling R9, 2026-09-28; was ISSUANCE-GATED).
**Route:** new detector `daytona-api-key`, finding type `daytona_api_key`.
Scheduled for Beta.12; no detector code merges to `main` until
`0.1.0-beta.11` is released.

## Role and blast radius

A Daytona API key (`DAYTONA_API_KEY`, `Authorization: Bearer`) creates and
controls agent sandboxes for an organization. The same generator also mints
region proxy, SSH-gateway and runner keys, which are lexically identical.

## Supported shape

Source: daytonaio/daytona provider code, last public at v0.190.0
([`01c502b`](https://github.com/daytonaio/daytona/blob/01c502bb1f1ff8f2885d0cd490e043736083dca8/apps/api/src/common/utils/api-key.ts#L8-L18)):
`generateApiKeyValue()` returns `dtn_` + `crypto.randomBytes(32).toString('hex')`.
The same inline form has existed since
[`5271af9`](https://github.com/daytonaio/daytona/blob/5271af9f13fd/apps/api/src/api-key/api-key.service.ts#L27)
(2025-04-28). The docs show `DAYTONA_API_KEY=dtn_***` (prefix only).

| Part | Grammar | Provenance | Tier |
| --- | --- | --- | --- |
| Prefix | `dtn_` | provider docs + code | T1 |
| Body | exactly 64 | provider generator (R1), public up to 2026-06-23 | T1 as of v0.190.0 (R9) |
| Alphabet | lowercase hex `[0-9a-f]` | provider generator (R1), same date | T1 as of v0.190.0 (R9) |
| Separators / checksum | none | — | — |

Total length 68.

## Why it is READY (ruling R9)

The generator is T1 under R1, but core development moved to a private
codebase in June 2026, so nothing public shows whether the live cloud still
issues `dtn_` + 64 lowercase hex. Step 2 therefore gated the contract on an
issued key.

The 2026-09-28 [issuance research](issuance-research/daytona.md) found no
newer provider source: every post-v0.190.0 source (the new `daytona/clients`
OpenAPI and CLI, helm-charts scripts, SDK 0.218.0, the docs dump) is prefix
only, and none contradicts the generator. Ruling R9
([issuecomment-5880547337](https://github.com/redact-secret/redact-secret/issues/860#issuecomment-5880547337))
extends R3's date rule to provider code: a generator counts as T1 as of its
date until a newer provider source contradicts it. The contract is frozen as
of v0.190.0 (2026-06-23). The research also confirmed that self-provisioned
runner keys are unprefixed 64 hex (`openssl rand -hex 32`), which stays
excluded.

## Excluded shapes

| Shape | Why excluded |
| --- | --- |
| `dtn_secret_<random>` | a Secrets-feature placeholder handed to sandboxes, not a credential. `s` is not hex, so it fails by construction |
| `dtn_artifact_…` stdout markers | not a credential |
| Legacy self-hosted keys (2024 Go server): unprefixed base64 of a UUID string, 48 bytes | no prefix; not attributable |
| Caller-supplied `apiKeyValue` / runner `apiKey` values | internal provisioning may use any string |
| `DAYTONA_JWT_TOKEN` / OAuth access tokens | JWTs; the `jwt` detector keeps them |
| Snapshot-manager password (32 hex, no prefix) | not attributable |

## Overlap and output policy

- **Existing detectors.** None claims `dtn_`. Without the prefix, the body is
  SHA-256 hex (including Daytona's own stored key hash), so the prefix is
  load-bearing. Measured on `main`: named contexts `contextual_secret`,
  Bearer `bearer_token`; bare, chat and JSON `"token"` are missed.
- **Planned output.** Provider type, high confidence, always redact.

## Implementation notes

`PrefixShape::exact("dtn_", 64, is_lower_hex, …)` with the `[A-Za-z0-9_-]`
boundary. Signals: `daytona-documented-prefix`, `daytona-generator-length`.

## Test axes

**Positives:**

- every index context;
- `Daytona(DaytonaConfig(api_key=…))`;
- `DAYTONA_API_KEY=`;
- a Terraform provider variable.

**Near-miss twins:**

- body of 63 or 65;
- an uppercase hex byte;
- a non-hex letter;
- `DTN_`;
- `dtn-`;
- a leading glue byte and a trailing glue byte.

**Benign:**

- `dtn_secret_<random>`, `dtn_***`, `dtn_...`, `dtn_1234567890` (OpenAPI
  example; too short);
- a bare 64-hex SHA-256;
- `dtn_artifact_` markers.

## False-positive / false-negative boundary

- **False negatives:**
  - any post-v0.190.0 format change (accepted under R9; an issuance check
    would detect it);
  - legacy self-hosted keys;
  - custom-provisioned values.
- **False positives:** `dtn_` + exactly 64 lowercase hex that is not a key.
  None is known.

## Issuance checklist (optional confirmation; structure only)

1. Issue one organization API key at app.daytona.io today.
2. Record: total length (expect 68), body length (expect 64), alphabet
   classes (expect lowercase hex only), whether any separator appears,
   `rawValueRetained: false`, revoked.
3. If it matches, move the contract's "as of" to the issuance date. If it
   differs, record the observed structure; under R9 that newer source
   supersedes v0.190.0 and the contract re-opens for the new shape.
