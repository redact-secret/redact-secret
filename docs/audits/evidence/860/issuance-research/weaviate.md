# #860 issuance research: `weaviate:cloud-api-key`

[Issuance research index](README.md) ·
[Handoff](../weaviate.md) ·
[Rulings R9–R10](https://github.com/redact-secret/redact-secret/issues/860#issuecomment-5880547337)

Frozen 2026-09-28. Desk research only: no key was issued, and no issued or
leaked credential is evidence.

**Gated property:** that keys issued by the WCD console (closed source) are
produced by the OSS dynamic-user generator, that is, 88-character standard
Base64 ending `PV92MjAw`.

**Research verdict: STILL GATED (slightly narrowed).** New provider docs
establish at T1 that every WCD cluster runs with dynamic database users and
RBAC enabled, and WCD's key lifecycle matches the database-user API. No T1
source says the console's keys are created through that generator, and no
provider example with the suffix exists beyond the already-known notebook.
**Maintainer disposition (2026-09-28): still gated;** the docs, code comments
and notebook example together were not accepted as proof of the console
issuance path.

## Sources

| # | Source | Date | Class | Ruling | Statement |
|---|---|---|---|---|---|
| 1 | [weaviate/weaviate `usecases/auth/authentication/apikey/keys/key_generation.go` @ b2b5023](https://github.com/weaviate/weaviate/blob/b2b5023894e5abbb278c56ac184873e43ff39181/usecases/auth/authentication/apikey/keys/key_generation.go) | 2026-01-02 | provider server code | R1 T1 | the generator shape (already in the handoff); unchanged at HEAD 5fe1880 (2026-09-28) |
| 2 | [weaviate/docs `docs/cloud/manage-clusters/default-settings.mdx` L76 @ fa7094c](https://github.com/weaviate/docs/blob/fa7094c3ce83685a4bc694350ffbe25be23f2fe8/docs/cloud/manage-clusters/default-settings.mdx#L76) (page added 2025-12-29) | 2025-12-29 | provider WCD docs | T1 statement of the WCD configuration | "`AUTHENTICATION_DB_USERS_ENABLED` \| true" under "User management & permissions … not user configurable", with `AUTHORIZATION_RBAC_ENABLED` true |
| 3 | [weaviate/docs `docs/cloud/manage-clusters/authentication.mdx` L8-L10, L59 @ fa7094c](https://github.com/weaviate/docs/blob/fa7094c3ce83685a4bc694350ffbe25be23f2fe8/docs/cloud/manage-clusters/authentication.mdx#L8-L10) | 2026-09-28 | provider WCD docs | T1 for the lifecycle only | "WCD uses RBAC … to manage authentication"; keys can be created, role-edited, **rotated**, deleted and shown once: the same verbs as the OSS database-user API (`/users/db/{id}`, `rotate-key`). No format is stated |
| 4 | weaviate/weaviate [`usecases/auth/authentication/apikey/db_users.go` near L191](https://github.com/weaviate/weaviate/blob/5fe18801455acf7a4cdf81cad4460fcfde9cb8e2/usecases/auth/authentication/apikey/db_users.go#L191) and [`usecases/auth/authorization/rbac/model.go` near L228](https://github.com/weaviate/weaviate/blob/5fe18801455acf7a4cdf81cad4460fcfde9cb8e2/usecases/auth/authorization/rbac/model.go#L228) | 2026-09-28 | provider server code **comments** | R6 = T2 | "This information is not terribly important (besides WCD UX)"; "temporary to enable import of existing keys to WCD (Admin + readonly)". This links the database-user store to WCD, and says legacy WCD keys were **imported** (so they keep their old shape) |
| 5 | [weaviate/weaviate-cloud](https://github.com/weaviate/weaviate-cloud) (`wcloud` CLI, created 2026-09-11, HEAD b38ab69) | 2026-09-25 | provider CLI | R1/R5 | cluster create returns a one-time `api_key.value`; no format; fixtures are word placeholders. Shows a second issuance path (the management plane at cluster create) whose generator is not visible |
| 6 | WCD console bundle (console.weaviate.cloud, public chunks) | 2026-09-28 | provider dashboard code | — | the public chunks hold only the IdP access-key widget (`/v1/mgmt/accesskey/…`); the cluster-key pages are behind login |
| 7 | weaviate/docs, the Python client, weaviate-cli, weaviate-cloud | 2026-09 | provider repos | — | no 88-character run ending `PV92MjAw`; weaviate-cli and the Python client do no key-shape checks |
| 8 | Weaviate community forum, "API keys length and complexity" (thread 21656) | 2025-07-14 | community answer (not staff) | not T1 | describes OSS dynamic keys as Base64; says nothing about WCD |
| 9 | GitHub secret-scanning partner list | 2026-09-28 | — | — | Weaviate is not a partner |

## Contract

Not closed. The proposed shape is unchanged (88 standard Base64 characters,
suffix `PV92MjAw`, decoding to 16 + `_` + 44 + `_v200`), T1 for OSS-generated
dynamic-user keys. The WCD link rests on T1 docs that WCD runs database users
and RBAC (#2, #3), T2 server comments naming WCD (#4), and the provider
notebook output (in the handoff, R5 example weight). The maintainer did not
accept that combination.

## Residual risk

- **False negatives:** legacy WCD keys imported into the database-user store
  keep their 36-character shape (#4 confirms the import path); cluster-create
  keys from the management plane (#5), if they use another generator; a
  future `vNNN` marker.
- **False positives:** effectively none (the suffix and decoded structure).
- One issued WCD key (length and suffix only) remains the gate.
