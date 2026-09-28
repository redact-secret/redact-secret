# #860 handoff: `convex:deployment-key`

[Tier B re-rank](tier-b-rerank.md) ·
[Research table #48](https://github.com/redact-secret/redact-secret/issues/860#issuecomment-5852387196)

**Readiness: split.**

- **READY:** hex-body keys. These are self-hosted admin and system keys, the
  dashboard admin key, and typed deploy keys that carry the version-1
  encrypted hex body.
- **ISSUANCE-GATED:** the current cloud deploy-key body, which begins
  `eyJ2`. Its alphabet, padding and length need a structure-only check
  (maintainer ruling R4).

**Route:** new detector `convex-deployment-key`, one finding type
`convex_deployment_key`. The hex-body shapes can land now. The cloud shape is
added to the same detector after the issuance check.

**Priority.** Convex is the only Tier B candidate that is missed in almost
every context today, including its own documented environment variables (see
below).

## Role and blast radius

A Convex deploy key (`CONVEX_DEPLOY_KEY`) lets CI or an agent push functions
and schema to a deployment and run admin operations on it. A project token
(`project:` type) has "total control over a project". An admin key
(`CONVEX_SELF_HOSTED_ADMIN_KEY`, or the dashboard admin key) is full admin
access to one deployment. Keys are sent as `Authorization: Convex <key>`.

## How keys are built (provider code)

Provider code is `get-convex/convex-backend` at
[`032e81e`](https://github.com/get-convex/convex-backend/tree/032e81e264a8b23b8d566d8f83f773d2bfbedb88),
which is also `main` on 2026-09-28. Its Apache-2.0 backend is the issuer for
self-hosted deployments.

- `crates/common/src/types/admin_key.rs`: `format_admin_key` builds
  `{deployment_name}|{encrypted_part}`, and `split_admin_key` splits on the
  first `|`. An optional `<type>:` lead is "superficial", added by the
  dashboard. The type is `prod`, `dev`, `preview` or `project`, and
  `remove_type_prefix` handles all four.
- `crates/keybroker/src/broker.rs`: `ADMIN_KEY_VERSION: u8 = 1`. `issue_key`
  encrypts an `AdminKey` proto with `instance_name: None`, `issued_s = now`,
  an identity (a `member_id` or `system`) and `is_read_only`.
- `crates/keybroker/src/encryptor.rs`: `encrypt_proto` writes the version
  byte, a 12-byte nonce, the AES-128-GCM-SIV ciphertext and a 16-byte tag,
  then applies `const_hex::encode`. The result is lowercase hex starting `01`.
- `npm-packages/convex/src/cli/lib/deployment.ts`: `isDeploymentKey` is
  `/^(dev|prod):.*\|/` and `isProjectKey` is `/^project:.*\|/`. A preview
  deploy key has three colon parts before the `|`.
- `npm-packages/convex/src/cli/lib/extractDeploymentNameForWorkOS.ts`: the
  cloud deployment name is `/^[a-z]+-[a-z]+-\d+$/`.
- `self-hosted/docker-build/read_credentials.sh`: the default self-hosted
  instance name is `convex-self-hosted`.

**Hex body length, derived from the code above.** These are derived facts,
not stated ones.

- The proto always carries `issued_s`: tag plus a 5-byte varint for any time
  between 2^28 and 2^35 seconds, so 6 bytes.
- It always carries an identity: `system` takes 2 bytes, and `member_id`
  takes 2 to 11 bytes.
- `is_read_only` adds 0 or 2 bytes, and `instance_name` is never set.
- Envelope and proto together come to 37–48 bytes, which is **74 to 96 hex
  characters**, always even.
- Whatever the proto holds, the envelope alone (version + nonce + tag) is
  29 bytes = 58 hex.

**Re-checked 2026-09-28** (R4 and R1 both hinge on these):

- `encryptor.rs` last changed 2026-08-25, and `admin_key.rs` last changed
  2026-05-13. The hex encoding, version byte and `|` join are unchanged at
  `032e81e`.
- The docs page
  [Deploy key types](https://docs.convex.dev/cli/deploy-key-types) still
  shows every typed key as `<type>:<name-or-slugs>|eyJ2...0=`, truncated. It
  shows the dashboard admin key as `<name>|01…`, also truncated.

## Supported shapes (READY)

| Part | Grammar | Provenance | Tier |
| --- | --- | --- | --- |
| Type lead (optional) | `prod:` or `dev:` + a cloud name; or `preview:` / `project:` + `<team-slug>:<project-slug>` | CLI regexes + backend `remove_type_prefix` + docs | T1 |
| Cloud name | `[a-z]+-[a-z]+-[0-9]+` | CLI name regex | T1 |
| Self-hosted instance name (untyped keys only) | `[a-z0-9][a-z0-9-]{0,62}` | default `convex-self-hosted` is provider code; the class and bound are project policy (the name is not secret) | T1 default, policy bound |
| Separator | exactly one `\|` | backend `format_admin_key` / `split_admin_key` | T1 |
| Body version lead | `01` | `ADMIN_KEY_VERSION = 1`, first byte | T1 (R1) |
| Body alphabet | lowercase hex `[0-9a-f]` | `const_hex::encode` | T1 (R1) |
| Body length | 74–96 hex, even | derived from the generator (above) | T1-derived (R1) |

**Finding span.** The whole key, from the type lead (or, for an untyped key,
the name) through the last hex byte. The name part is public, but it is part
of the one string the CLI consumes. Redacting it too means the key cannot be
reassembled from a partial redaction. Doppler's environment segment is
handled the same way.

**Slug grammar for `preview:` / `project:`.** No source states the team or
project slug grammar. The contract uses `[a-z0-9][a-z0-9-]{0,62}` for each
slug (project policy, bounded). A key whose slug falls outside it is an
accepted false negative.

## Gated shape (ISSUANCE-GATED)

| Part | What is known | Tier |
| --- | --- | --- |
| Type lead + name/slugs + `\|` | as above | T1 |
| Body lead | `eyJ2` (a truncated docs example; R4 fixes the visible prefix only) | T1 prefix only |
| Body alphabet | unknown: standard (`+/`) or URL-safe (`-_`) Base64; whether `=` padding appears (the docs example ends `0=`, but R4 does not extend to a suffix) | not T1 |
| Body length | unknown; it may vary with scope (`deployment:deploy` permissions) | not T1 |

Why it is gated: maintainer ruling R4
([2026-09-28](https://github.com/redact-secret/redact-secret/issues/860#issuecomment-5871306275))
names #48's cloud body explicitly. A truncated example establishes the
prefix only, and length and alphabet need another T1 source or a
structure-only issuance check. The cloud issuer is closed-source, so no code
source exists.

## Excluded shapes

| Shape | Why excluded |
| --- | --- |
| `CONVEX_DEPLOYMENT=dev:<name>` / `prod:<name>` (no `\|`) | public deployment selector, not a credential. There is no `\|`, so it never matches |
| `https://<name>.convex.cloud`, `.convex.site`, a bare deployment name | public |
| Pre-0.16.0 bare legacy key (no `<name>\|`) | no anchor; the generic paths keep it |
| Team access and OAuth tokens (`ey…=` Base64, `Bearer`) | no prefix and no stated shape; `bearer-token` covers the header form |
| CLI device token ("an encoded UUID") and login access token | shape undocumented |
| Placeholders: `prod:your-deployment-name\|your-admin-key`, `prod:adjective-animal-123\|super-secret-key`, `sa67asd6a5da6d5:sd6f5…` (backend comment) | the body fails the `01` + 74–96 hex grammar |
| Hex body shorter than 74, odd-length, or containing uppercase | cannot come from the generator |
| An `eyJ2…` body (until the gate clears) | alphabet and length not T1 |

## Current coverage on `main` (synthetic probe, 2026-09-28)

Method as in the [Tier B re-rank](tier-b-rerank.md#current-coverage-on-main).
The CLI was built from `main`
[`9ab0fa0`](https://github.com/redact-secret/redact-secret/commit/9ab0fa02f2aeeda16a2c99e04862ebb0f0e9b5e7).

| Context | typed `eyJ2` body (prod, dev, preview, project) | typed legacy hex body | self-hosted `convex-self-hosted\|01…` |
| --- | --- | --- | --- |
| bare, chat, JSON `"token"` | none | none | none |
| `CONVEX_DEPLOY_KEY=` / `CONVEX_SELF_HOSTED_ADMIN_KEY=` (plain and `export`) | **none** | **none** | **none** |
| `Authorization: Bearer` | none | none | **`bearer_token` over the name only (18 of 93 bytes); the secret hex stays in clear** |
| `Authorization: Convex` (the provider's own scheme) | none | none | none |
| `X-API-Key`, JSON `api_key`, SDK keyword argument | `contextual_secret`, high, full span | same | same |

The environment-variable miss is caused by the **name**, not the value.
`generic-token` has no vocabulary entry for a bare `*_KEY` suffix. The
high-signal names are `api_key`, `secret_key`, `private_key` and the like,
and `signing_key` is ambiguous. So `CONVEX_DEPLOY_KEY`, `DEPLOY_KEY`,
`CONVEX_ADMIN_KEY` and `CONVEX_SELF_HOSTED_ADMIN_KEY` produce nothing, even
for a neutral 32-byte random value. The same Convex value under `API_KEY=` is
redacted in full. The Bearer partial span is a generic exact-span defect,
recorded in the re-rank as an out-of-scope observation.

## Overlap and output policy

- **Existing detectors:**
  - No detector claims the anchor `…|01<hex>`.
  - `jwt` does not claim an `eyJ2…` body, because it has no `.` segments.
  - `bearer-token` currently claims the name before `|` (the defect above).
    Once the provider finding exists, overlap resolution prefers the
    provider type over the whole span, so the partial `bearer_token` span is
    superseded.
- **`generic-token` deferral:** `convex` is **not** added to
  `DEDICATED_PROVIDER_SEGMENTS`. It would change nothing today, because the
  names already miss, and it would silence a future generic fix for the
  gated `eyJ2` shape. The Tier A shared rule applies.
- **New output:** `Specificity::Provider`, `Confidence::High`, listed in
  `ALWAYS_REDACT_TYPES` (default `redact`). No `block`.

## Implementation notes

This is not a `PrefixShape` family, because the anchor is the `|` separator
plus the body, not a leading literal. Implement it as a small dedicated
detector:

1. Find each `|01` whose `|` is preceded by a name byte.
2. Read the maximal `[0-9a-f]` run after the `|`. Require even length 74–96,
   the leading `01`, and a trailing boundary: the next byte is not
   `[A-Za-z0-9_-]`.
3. Walk left from the `|` over the name.
   - Cloud grammar: `[a-z]+-[a-z]+-[0-9]+`.
   - Otherwise, for an untyped key, the bounded instance-name class.
   - Then optionally over `prod:` / `dev:`. For `preview:` / `project:`, walk
     over `<slug>:<slug>` and the type word.
   - The start must follow a non-`[A-Za-z0-9_:-]` byte or the input start.
   - If no candidate walk reaches a valid start, there is no finding.
4. Emit one finding over the whole key.

Signals: `convex-documented-separator`, `convex-generator-hex-envelope`, and
`convex-typed-lead` when present.

**Cost.** One `memchr`-style scan for `|` plus bounded left and right walks.
The left walk is at most 8 + 64 + 1 + 64 bytes. The right walk is at most 96.
Linear, with no per-line state, so incremental and WASM parity hold within
the engine's existing token window.

After the gate: add the `eyJ2` body branch to step 2 with the alphabet and
length the issuance check records. For that branch, require a typed lead,
because the untyped form is admin-key-only and hex.

## Test axes

**Positives (hex body):**

- every context in the re-rank's probe list;
- `CONVEX_DEPLOY_KEY=prod:<name>|01<hex>` in `.env`;
- `CONVEX_SELF_HOSTED_ADMIN_KEY=convex-self-hosted|01<hex>` in a Docker
  Compose `environment:` block;
- `Authorization: Convex <key>` in a curl line;
- `npx convex deploy` with the key in a GitHub Actions `env:` map;
- an MCP server `env` block;
- body lengths 74, 76 and 96, which cover the system, small-member and
  maximal-member proto sizes.

**Near-miss twins (one property each):**

- body of 72 or 98 hex;
- odd hex length;
- leading `02` instead of `01`;
- one uppercase hex byte;
- one `g`;
- `||` double separator;
- `prod;` for `prod:`;
- name `bold_hyena_681` (underscore);
- a glue byte before the type lead;
- a glue byte after the body.

**Benign:**

- `CONVEX_DEPLOYMENT=dev:<name>` and `prod:<name>`;
- `CONVEX_URL=https://<name>.convex.cloud`;
- the docs placeholders listed above;
- `prod:<name>|${CONVEX_BODY}`;
- a Markdown table cell separator `| 01…` with a space;
- a 74-hex digest after `|` with no `01` lead;
- `prod:<name>|eyJ2…` (the gated shape: stays unclaimed until the gate
  clears, and is recorded as such, not as a benign rule).

## False-positive / false-negative boundary

- **Accepted false negatives:**
  - every `eyJ2…` cloud key until the gate clears (status quo);
  - pre-0.16.0 bare keys;
  - a self-hosted instance name or preview/project slug outside the bounded
    class (uppercase, `_`, longer than 63 bytes);
  - uppercase hex copies;
  - any future `ADMIN_KEY_VERSION`.
- **Accepted false positives:** a non-Convex string of
  `<name>|01<74–96 lowercase hex>` with clean boundaries. None is known. The
  `|01` + even-length hex window is specific.

## Issuance checklist — gate for the cloud body (structure only)

Follow the Tier A protocol (structure only, `rawValueRetained: false`,
revoke after). For one **production deploy key** and one **preview deploy
key** created in the dashboard today, record:

1. the type lead and the number of `:` parts before `|`;
2. body length after `|`;
3. whether the body starts `eyJ2`;
4. alphabet classes present in the body: upper, lower, digit, `+`, `/`, `-`,
   `_`;
5. the count of trailing `=`;
6. whether a second key with narrower permissions (`deployment:deploy` only)
   has the same body length;
7. `rawValueRetained: false`, revoked.

Optionally, record the same for one dashboard admin key, to confirm whether
the cloud still issues `<name>|01<hex>`.

**Outcome.**

- A fixed or bounded length plus one Base64 alphabet freezes the `eyJ2`
  branch with those facts, as of the issuance date.
- A length that varies with scope freezes the observed range, and the range
  is widened only by a later observation.
