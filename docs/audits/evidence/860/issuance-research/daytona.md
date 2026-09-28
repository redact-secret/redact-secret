# #860 issuance research: `daytona:api-key`

[Issuance research index](README.md) ·
[Handoff](../daytona.md) ·
[Rulings R9–R10](https://github.com/redact-secret/redact-secret/issues/860#issuecomment-5880547337)

Frozen 2026-09-28. Desk research only: no key was issued, and no issued or
leaked credential is evidence.

**Gated property:** whether the live cloud still issues `dtn_` + 64 lowercase
hex (body length and alphabet) after the provider code went private at
v0.190.0 (2026-06-23).

**Research verdict: STILL GATED.** The prefix `dtn_` is re-confirmed as
current (2026-09). No public source dated after v0.190.0 states or executes
the body length or alphabet.

**After ruling R9 (dated code): READY.** R9 extends R3's date rule to
provider code: the v0.190.0 generator is T1 as of 2026-06-23 until a newer
provider source contradicts it. None does (sources 3–11 below are all prefix
only). Contract: `dtn_` + exactly 64 `[0-9a-f]`.

## Sources checked

| # | Source | Date | Class | Ruling | Statement |
|---|---|---|---|---|---|
| 1 | [daytonaio/daytona `apps/api/src/common/utils/api-key.ts` L12-14 @ v0.190.0](https://github.com/daytonaio/daytona/blob/v0.190.0/apps/api/src/common/utils/api-key.ts#L12-L14) | 2026-06-23 | provider server code | R1 T1; R9 as of v0.190.0 | `` return `dtn_${generateRandomString(32)}` `` (`randomBytes(32).toString('hex')`) |
| 2 | [daytonaio/daytona README @ ec4c21b](https://github.com/daytonaio/daytona/blob/ec4c21b2d597091ac09ecc278f3bcc172575a987/README.md) | 2026-06-25 | provider notice | context | "As of June 2026, Daytona's core development has moved to a private codebase." |
| 3 | [daytona/clients (new public org) `openapi-specs/api.json` L12919 @ e008136](https://github.com/daytona/clients/blob/e00813650039a18064e418fd134195ca9e26810e/openapi-specs/api.json#L12919) and the live `https://www.daytona.io/docs/openapi.json` (Last-Modified 2026-09-26) | 2026-09-28 | provider OpenAPI | R4 placeholder, prefix only | the runner `apiKey` example is a short `dtn_` + ten digits placeholder; the `ApiKeyResponse.value` example is a legacy `bb_sk_` placeholder, unchanged since the public code ([dto @ v0.190.0](https://github.com/daytonaio/daytona/blob/v0.190.0/apps/api/src/api-key/dto/api-key-response.dto.ts#L20)); no pattern or length |
| 4 | [daytona/clients `cli/apiclient/api_client_test.go` L93 @ e008136](https://github.com/daytona/clients/blob/e00813650039a18064e418fd134195ca9e26810e/cli/apiclient/api_client_test.go#L93) | 2026-09-28 | provider CLI unit-test fixture | R5 example-shape weight | a non-hex word fixture after `dtn_`; shows the CLI does no format validation. No length evidence |
| 5 | [daytonaio/helm-charts `scripts/aws-setup/test/repro.sh` L173 @ 084c2a4](https://github.com/daytonaio/helm-charts/blob/084c2a4eece610837480f1e37c455818478f0935/scripts/aws-setup/test/repro.sh#L173) | 2026-09-24 | provider tooling (error text, not a check) | R6 comment-like text, T2; prefix only | "2. The key starts with 'dtn_'." (printed after a 401/403; no `startsWith` is executed) |
| 6 | [daytonaio/helm-charts `scripts/azure-setup/README.md` L101 @ 084c2a4](https://github.com/daytonaio/helm-charts/blob/084c2a4eece610837480f1e37c455818478f0935/scripts/azure-setup/README.md#L101) | 2026-09-24 | provider docs | prefix only | the org key and the runner-manager key "Both look identical (`dtn_...`" |
| 7 | [daytonaio/helm-charts `runner/install.sh` L380 @ 084c2a4](https://github.com/daytonaio/helm-charts/blob/084c2a4eece610837480f1e37c455818478f0935/runner/install.sh#L380) | 2026-09-24 | provider install script | R1 (executing) | `RUNNER_API_KEY=${RUNNER_API_KEY:-$(openssl rand -hex 32)}`: a self-provisioned runner key is **unprefixed** 64 hex. This confirms the "custom-provisioned" exclusion; it is not the `dtn_` generator |
| 8 | npm `@daytonaio/sdk`, `@daytonaio/api-client`, `@daytonaio/toolbox-api-client` 0.218.0 | 2026-09-25 | provider SDK | — | no key format or validation; only the `dtn_secret_<id>` Secrets placeholder |
| 9 | Docker Hub `daytonaio/daytona-api` | last tag v0.189.0, 2026-06-19 | provider server image | — | no post-privatization API image is published, so the compiled generator cannot be inspected. The `daytonaio/daytona-runner-manager:v0.207.0` (2026-08-25) binary contains no `dtn_` string |
| 10 | `https://www.daytona.io/docs/llms-full.txt` (full docs dump) | 2026-09-28 | provider docs | R4 | only `dtn_` placeholders and `dtn_secret_…`; no length or alphabet statement |
| 11 | daytona/{guides,skills,integrations}, daytonaio/{docs,terraform-modules,homebrew-cli} | 2026-08..09 | provider repos | — | prefix-only placeholders |

## Contract

Research left the proposed shape unchanged: `dtn_` + exactly 64 `[0-9a-f]`,
T1 as of v0.190.0 (2026-06-23); the prefix `dtn_` is T1 as of 2026-09-24.
R9 accepts it as the frozen contract. See the [handoff](../daytona.md).

## Residual risk

- **False negatives:** any post-v0.190.0 change to body length or alphabet
  (what an issuance check would still rule out); unprefixed self-provisioned
  runner keys (source 7); legacy self-hosted keys.
- **False positives:** `dtn_` + exactly 64 lowercase hex that is not a key.
  None is known.
- Research cannot close it further: the only T1 carrier (the API server
  source and image) stopped being public. R9 makes the dated generator
  sufficient.
