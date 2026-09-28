# #860 handoff: `trigger-dev:secret-api-key`

[#860 handoff index](README.md) ·
[Research table #20](https://github.com/redact-secret/redact-secret/issues/860#issuecomment-5852386687)

**Readiness: READY.** **Route:** new detector `trigger-dev-token` with two
finding types.

## Role and blast radius

A Trigger.dev environment secret key triggers and manages background and agent
jobs in one project environment (`dev`, `stg`, `prod`, `preview`), and those
jobs run with that environment's secrets. Since 2026-08-25 an environment can
hold a root key and additional keys. A personal access token (`tr_pat_`) acts
for a user across projects.

| Prefix | Finding type | Role |
| --- | --- | --- |
| `tr_<env>_sk_` (additional) and `tr_<env>_` (root) | `trigger_dev_secret_api_key` | environment secret key |
| `tr_pat_` | `trigger_dev_personal_access_token` | user personal access token |

Root and additional keys are one type: the provider documents both as the
environment's secret key, with the same scope, and differing only in how many
may exist. The PAT gets its own type because its scope is the user, not an
environment (GitHub precedent, as in [doppler.md](doppler.md)).

## Supported shapes

Sources, all provider code at
[`c2b7a72`](https://github.com/triggerdotdev/trigger.dev/tree/c2b7a72180bbb2dcbc31caa8539e0ca8f8e9e9b8)
unless noted:

- `ADDITIONAL_API_KEY_PATTERN` in the published SDK core
  (`packages/core/src/v3/apiKeys.ts`);
- the webapp generator (`apps/webapp/app/utils/apiKeys.ts`), a
  `customAlphabet` of `[0-9a-zA-Z]` with length 24;
- the legacy root generator (20) at tag `trigger.dev@4.0.0`
  ([`0b35cc3`](https://github.com/triggerdotdev/trigger.dev/blob/0b35cc35e053bc4a38cbe80ff4d7d543e8cca7d3/apps/webapp/app/models/api-key.server.ts));
- the PAT generator (`apps/webapp/app/services/personalAccessToken.server.ts`);
- the provider docs for prefixes.

**Re-checked 2026-09-28:** the SDK pattern file was last changed 2026-07-27
([`efd0ee8`](https://github.com/triggerdotdev/trigger.dev/commit/efd0ee8d74a2548e125d22ba801647a1b0f458cd)),
and the generator was last changed 2026-07-29
([`a81ad49`](https://github.com/triggerdotdev/trigger.dev/commit/a81ad4949cb6d0f8a02ea3c5bc11b616edefb582)).
The pattern, the 24-byte alphanumeric alphabet and the four env prefixes are
unchanged.

| Shape | Prefix | Body | Alphabet | Provenance | Tier |
| --- | --- | --- | --- | --- | --- |
| Additional secret key | `tr_` + (`dev` \| `stg` \| `prod` \| `preview`) + `_sk_` | exactly 24 | `[0-9A-Za-z]` | published SDK regex + generator | T1 |
| Root secret key (current) | `tr_` + env + `_` | exactly 24 | `[0-9A-Za-z]` | generator (R1) + docs prefix | T1 |
| Root secret key (legacy, ≤ v4.0.0) | `tr_` + env + `_` | exactly 20 | `[0-9A-Za-z]` | generator at tag (R1) | T1 |
| Personal access token | `tr_pat_` | exactly 40 | `[1-9a-km-z]` (lowercase, no `0`, no `l`) | generator (R1) + docs prefix | T1 |

Separators: `_` only, at the fixed positions shown. No checksum.

Legacy 20-byte roots are kept because lookup is by value, and the research
found no statement that they stopped authenticating after the 2026-08 change.

## Excluded shapes

| Shape | Why excluded |
| --- | --- |
| `pk_<env>_` + 20 public key | public by design: the server classifies `pk_` as public. It must stay **benign** |
| `tr_oat_` organization access token | secret, but no generator was found, so length and alphabet are unknown (T0) |
| `tr_uat_` + JWT | short-lived delegated JWT; the `jwt` detector keeps the JWT part |
| Public access tokens (bare HS256 JWT) | the `jwt` detector keeps them |
| `tr_proj_…` project refs | non-secret identifiers |
| Env slugs outside the four (`tr_test_`, `tr_staging_`) | not in the provider's `EnvSlug` union |

## Tier rationale

All four supported shapes are T1: the additional-key grammar is a regex in
published SDK code, and the root and PAT grammars are provider generator code
accepted under R1. Docs corroborate the prefixes.

## Overlap and output policy

- **Existing detectors.** No provider detector claims `tr_`. Stripe's contract
  is `sk_live_`/`sk_test_`/`rk_…`/`sk_org_`, and ElevenLabs' is `sk_` + 48
  lowercase hex. `tr_<env>_sk_` contains `sk_`, but the byte before `sk_` is
  `_`, which both detectors' `[A-Za-z0-9_-]` leading boundary rejects. The body
  rules it out as well: it has no `_`, so `live_`/`test_`/`org_` never follow,
  and it is 24 bytes, not ElevenLabs' 48 lowercase hex. A registry test pins
  that neither fires on a Trigger.dev key. Measured on `main`: `contextual_secret`
  and `bearer_token` cover the named and header contexts; bare, chat and JSON
  `"token"` are missed.
- **New output.** Two provider types, high confidence, always redact; the
  provider finding wins its overlaps.
- **Root vs additional.** The root alphabet excludes `_`, so an additional key
  can never be read as a root key whose body starts `sk_`. Longest prefix wins
  at a shared position, so `tr_prod_sk_` is tried before `tr_prod_`. An
  additional key with a short body (`tr_prod_sk_` + 21) matches neither shape.

## Implementation notes

The shared `KnownFormatProviderDetector`:

- eight exact-24 shapes for `tr_<env>_sk_`;
- four `OneOf([24, 20])` shapes for `tr_<env>_`;
- one exact-40 shape for `tr_pat_`, with a `[1-9a-km-z]` alphabet function.

Boundary `[A-Za-z0-9_-]`. Two types means either two table detectors under one
id, or one table plus a per-shape type (the GitHub detector's model).
Signals: `trigger-dev-documented-prefix`, `trigger-dev-generator-length`.

## Test axes

**Positives:**

- all four env slugs × additional/root-24/root-20;
- a PAT;
- every index context plus `TRIGGER_SECRET_KEY=` in `.env`, a
  `configure({ secretKey })` SDK call, and a GitHub Actions `env:` block.

**Near-miss twins:**

- body of 23/25 (additional), 19/21/22/23/25 (root), 39/41 (PAT);
- an unknown env slug;
- a `-` or `_` inside the body;
- a PAT containing `0` or `l`, or uppercase;
- `tr_prod_sk_` + 21;
- a leading glue byte (`str_prod_…`, `xtr_dev_…`) and a trailing glue byte;
- uppercase `TR_PROD_`.

**Benign** (unclaimed by the new detector):

- `pk_dev_`/`pk_prod_` + 20 public keys, bare and under `TRIGGER_PUBLIC_KEY`;
- `tr_dev_sk_xxxxxxxxxx`, `tr_dev_…` placeholders;
- `tr_proj_…` refs;
- JWT public access tokens (these stay `jwt`);
- identifiers such as `tr_dev_mode`.

## False-positive / false-negative boundary

- **Accepted false negatives:**
  - `tr_oat_` tokens;
  - root keys of any width other than 20 or 24;
  - self-hosted instances with changed generators;
  - any future env slug.
- **Accepted false positives:** an unrelated identifier of exactly
  `tr_<env>_` + 20 or 24 alphanumerics with no separator. Code identifiers
  with this shape normally contain further `_`, which the alphabet rejects.
  The residual risk is low.

## Issuance checklist (optional confirmation; structure only)

- For one root key and one additional key: total length, body length,
  alphabet classes.
- For a PAT: body length, and confirm there is no `0` or `l`.
- For an organization access token (`tr_oat_`): total and body length and
  alphabet classes. This would let a later change add it.
- `rawValueRetained: false` and revoked.
