# Issue #524: database-SaaS credential assessment and the Neon API key contract

[Audit archive](../../README.md) ·
[Issue #524](https://github.com/redact-secret/redact-secret/issues/524) ·
[Spec: detector families](../../../specs/detector-families.md)

Written 2026-09-24. This record implements Neon and records a ranked,
evidence-backed assessment of MongoDB Atlas, PlanetScale and CockroachDB
Cloud, so that a follow-up issue does not have to redo the analysis. It holds
synthetic values only.

## Verdict

`neon-api-key` (`neon_api_key`, provider pack, always redacted) reports
`napi_` followed by at least 64 `[A-Za-z0-9]` bytes. The prefix is T1 and
the body is T2. The other three families are not implemented here. Each has a
stronger lexical contract than Neon's body, and each is ranked below as a
follow-up.

## Neon

| property | evidence | tier |
| --- | --- | --- |
| `napi_` prefix | Neon changelog 2025-01-31: "Newly created Neon API keys are now prefixed with `napi_` ... secret scanning mechanisms that rely on identifiable markers" (`neondatabase/website` `content/changelog/2025-01-31.md`, observed 2026-09-24) | T1 |
| body length and alphabet | betterleaks `neon-api-key`: `napi_[A-Za-z0-9]{64}`. mask-go `neon-api-key`: the same alphabet, 64 as a floor. Neon's API-keys page calls a key "a randomly-generated 64-bit token", and its only written example (`napi_examplekey...`) is not a shape. | T2 |
| partner scanning | GitHub secret scanning lists `neon_api_key` and `neon_connection_uri` (expressions not published) | corroborates the prefix only |
| pinned peers | gitleaks 8.30.1 and trufflehog 3.97.4 have no Neon rule | none |

**Grammar.** `napi_` plus at least 64 `[A-Za-z0-9]` bytes, read to the end
of the run. A run joined to `_` or `-` is rejected, and so is a body that is
one repeated character. Detection is bare and high confidence.

**Connection-string overlap.** A Neon connection URI's password
(`postgresql://user:<password>@ep-...neon.tech/...`) stays with
`connection-string`. A `napi_` key never sits in the password position, so
`neon-api-key` and `connection-string` never report the same span. Fixture
`neon-api-key-overlap-connection-uri` pins this. `NEON` joins
`generic-token`'s dedicated-provider name segments, so a placeholder or near
miss under `NEON_API_KEY=` stays silent.

**False-positive and false-negative trade-off.**

- **False negatives.** A key body shorter than 64 bytes is missed entirely;
  the floor rests on one scanner rule and one library pattern. Legacy
  unprefixed keys are missed.
- **False positives.** Any `napi_` plus 64-alphanumeric run is reported. That
  is the intended reading of a prefix Neon introduced for secret scanning.

**Fixtures.** 20 `neon-api-key-*` fixtures in
`conformance/fixtures/synchronous-corpus.json`:

- 8 positives: dotenv, JSON, YAML, shell, a TypeScript SDK client, log text,
  a longer body, and CRLF with a Unicode prefix;
- 6 negative controls: project id, branch and endpoint ids, a pooled
  hostname with a database name, a placeholder, filler, and an env reference;
- 3 malformed boundaries;
- 2 overlaps, with `connection-string` and `bearer-token`;
- 1 dense adversarial line.

## Ranked assessment of the other three

Ranked by lexical evidence first, as #523 ranks CI providers. None is
implemented in this issue.

| rank | family | shape | evidence | recommendation |
| --- | --- | --- | --- | --- |
| 1 | PlanetScale service token, database password, OAuth token | `pscale_tkn_`, `pscale_pw_`, `pscale_oauth_` + 32–64 `[\w=.-]` (betterleaks). trufflehog 3.97.4 `planetscale`/`planetscaledb`: `pscale_tkn_`/`pscale_pw_` + 43 `[A-Za-z0-9_]` | Three distinct prefixes. GitHub partner patterns `planetscale_service_token`, `planetscale_database_password` and `planetscale_oauth_token`, all with push protection. The #651 record notes a provider-documented `pscale_pw_` source. | Next. Freeze the body width against provider docs; the two peers disagree (43 exact versus 32–64). |
| 2 | CockroachDB Cloud API key | `CCDB1_` + 22 `[A-Za-z0-9]` + `_` + 40 `[A-Za-z0-9]` (betterleaks) | A versioned prefix and a two-segment structure. GitHub partner pattern `ccdb_api_key` with push protection. No pinned-peer rule. | Strong lexical contract. Needs a provider-documentation check for the segment widths. |
| 3 | MongoDB Atlas service account secret | `mdb_sa_sk_` + 40 `[A-Za-z0-9_-]`, id `mdb_sa_id_` + 24 hex (betterleaks) | GitHub partner pattern `mongodb_atlas_service_account_secret` with push protection. Legacy programmatic API keys (8-character public key plus UUID private key) have no marker and would need context gating. | Implement the `mdb_sa_sk_` secret; keep legacy keys unsupported. The `mongodb+srv://` URI password is already covered by `connection-string`. |
