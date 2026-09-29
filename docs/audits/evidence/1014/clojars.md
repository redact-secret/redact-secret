# #1014 handoff: `clojars:deploy-token`

[#1014 index](README.md) · rank 5 ·
[Research table #23](https://github.com/redact-secret/redact-secret/issues/1014#issuecomment-5900447282)

**Readiness: READY.** **Route:** new detector `clojars-deploy-token`, finding
type `clojars_deploy_token`.

## Role and blast radius

A Clojars deploy token is the password for deploying artifacts to Clojars
(`CLOJARS_PASSWORD`, `~/.lein/credentials`, `deps.edn` tooling), optionally
scoped to a group or artifact. A leak is a supply-chain risk.

## Supported shape

Source: `clojars/clojars-web` `src/clojars/db.clj` at
[`442eb89`](https://github.com/clojars/clojars-web/blob/442eb895e7ab3449161848d8c368d4783c5f0067/src/clojars/db.clj#L799-L853)
(last changed 2026-09-16), re-checked 2026-09-29:

- `generate-deploy-token` returns `(str "CLOJARS_" (hexadecimalize
  (generate-secure-token 30)))`;
- `hexadecimalize` formats each byte as `%02X` and then lowercases the
  result;
- the server's own shape check `is-deploy-token?` is
  `#"^CLOJARS_[0-9a-f]{60}$"`.

| Part | Grammar | Provenance | Tier |
| --- | --- | --- | --- |
| Prefix | `CLOJARS_` (uppercase) | generator + validator (R1) | T1 |
| Body | exactly 60 | 30 bytes hex + validator (R1) | T1 |
| Alphabet | lowercase hex | `hexadecimalize` + validator (R1) | T1 |

Total length 68.

## Excluded shapes

| Shape | Why excluded |
| --- | --- |
| Account password (before deploy tokens were required) | no shape |
| `CLOJARS_USERNAME`, `CLOJARS_PASSWORD`, `CLOJARS_ENVIRONMENT` env names | identifiers; fail the 60-hex body |
| Uppercase-hex body | the validator rejects it |

## Tier rationale

T1 for every fact under R1: the generator and the server validator agree.
gitleaks's `(?i)CLOJARS_[a-z0-9]{60}` is looser and is not used.

## Overlap and output policy

- **Existing detectors.** None claims `CLOJARS_`. Measured on `main`
  `b9e9091`: `CLOJARS_PASSWORD=` gives `contextual_secret`; bare, chat and
  JSON `"token"` are missed.
- **New output.** Provider type, high confidence, always redact.

## Implementation notes

`KnownFormatProviderDetector` with `PrefixShape::exact("CLOJARS_", 60,
is_lower_hex, …)` and the `[A-Za-z0-9_-]` boundary. The prefix is
case-sensitive. Signals: `clojars-validator-shape`.

## Test axes

**Positives:** every #860 index context; `CLOJARS_PASSWORD=` in a CI `env:`
block; a Leiningen `:password "CLOJARS_…"` map; a `~/.m2/settings.xml`
`<password>` element.

**Near-miss twins:** body of 59 or 61; an uppercase hex byte; a `g` in the
body; `clojars_` lowercase prefix; a leading glue byte (`XCLOJARS_…`) and a
trailing glue byte.

**Benign:** `CLOJARS_USERNAME=alice`; `CLOJARS_PASSWORD=${CLOJARS_PASSWORD}`;
`CLOJARS_` + a 60-hex value with one uppercase byte.

## False-positive / false-negative boundary

- **Accepted false negatives:** an uppercased copy; a legacy password.
- **Accepted false positives:** none known for `CLOJARS_` + exactly 60
  lowercase hex.

## Issuance checklist (optional confirmation; structure only)

For one deploy token: total length (expect 68), body length (60), alphabet
(lowercase hex only), `rawValueRetained: false` and revoked.
