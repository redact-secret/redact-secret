# #1014 handoff: `sonarqube:token`

[#1014 index](README.md) · rank 3 ·
[Research table #15](https://github.com/redact-secret/redact-secret/issues/1014#issuecomment-5900447016)

**Readiness: READY.** **Route:** new detector `sonarqube-token`, finding
types `sonarqube_user_token` (`squ_`) and `sonarqube_analysis_token`
(`sqa_`, `sqp_`).

## Role and blast radius

SonarQube Server tokens (`SONAR_TOKEN`) authenticate API calls and analysis
uploads. A user token (`squ_`) acts as the user, including administration if
the user is an administrator. A global analysis token (`sqa_`) can submit
analysis for any project. A project analysis token (`sqp_`) is limited to one
project. Leaks are common in CI configs and in agent-generated scanner
commands (`sonar-scanner -Dsonar.token=…`).

## Supported shape

Sources: `SonarSource/sonarqube` server code at
[`9ec5e86`](https://github.com/SonarSource/sonarqube/tree/9ec5e86425011f6c1ffa0eb2db08880e3b347271),
re-checked 2026-09-29:

- `TokenGeneratorImpl.java`
  ([L29–L46](https://github.com/SonarSource/sonarqube/blob/9ec5e86425011f6c1ffa0eb2db08880e3b347271/server/sonar-webserver-auth/src/main/java/org/sonar/server/usertoken/TokenGeneratorImpl.java#L29-L46),
  last changed 2026-04-17): `SONARQUBE_TOKEN_PREFIX = "sq"`, then
  `tokenType.getIdentifier()`, then `_`, then `Hex.encodeHexString` of 20
  `SecureRandom` bytes;
- `TokenType.java`
  ([L24–L27](https://github.com/SonarSource/sonarqube/blob/9ec5e86425011f6c1ffa0eb2db08880e3b347271/server/sonar-db-dao/src/main/java/org/sonar/db/user/TokenType.java#L24-L27)):
  `u` user, `a` global analysis, `b` project badge, `p` project analysis.

| Part | Grammar | Provenance | Tier |
| --- | --- | --- | --- |
| Prefix | `squ_`, `sqa_`, `sqp_` | generator + enum (R1) | T1 |
| Body | exactly 40 | 20 bytes hex-encoded (R1) | T1 |
| Alphabet | lowercase hex (Commons Codec `encodeHexString` is lowercase) | generator (R1) | T1 |

Total length 44.

## Excluded shapes

| Shape | Why excluded |
| --- | --- |
| `sqb_` + 40 hex project badge token | read-only badge access, and published in README badge URLs by design (ruling Q5 in the index) |
| Unprefixed 40-hex legacy token (before SonarQube 9.5) | SHA-1/git-SHA shaped; generic context (`SONAR_TOKEN=`, `sonar.login=`) is the only safe signal |
| SonarQube Cloud `sqco_` token | a different product with no provider grammar found (trufflehog only); a separate candidate |
| Uppercase-hex body | never issued |

## Tier rationale

T1 for all facts under R1: prefix, type letters, length and alphabet come from
the provider's own server generator. gitleaks's keyword-gated
`(?:squ_|sqp_|sqa_)?[a-z0-9=_\-]{40}` is looser and is not used.

## Overlap and output policy

- **Existing detectors.** None claims `squ_`, `sqa_` or `sqp_`. The 40-hex
  body without the prefix is SHA-1 shaped, so the prefix is load-bearing.
  Measured on `main` `b9e9091`: `SONAR_TOKEN=` gives `contextual_secret`;
  bare, chat and JSON `"token"` are missed.
- **New output.** Two provider types, high confidence, always redact.

## Implementation notes

`KnownFormatProviderDetector` with three `PrefixShape::exact(prefix, 40,
is_lower_hex, …)` shapes and the `[A-Za-z0-9_-]` boundary. Signals:
`sonarqube-generator-prefix`, `sonarqube-generator-length`.

## Test axes

**Positives:** every #860 index context; `SONAR_TOKEN=` in `.env` and in a
GitHub Actions `env:` block; `sonar-scanner -Dsonar.token=…` and the legacy
`-Dsonar.login=…`; `sonar.token=` in `sonar-project.properties`; a Gradle
`systemProp.sonar.token=`.

**Near-miss twins:** body of 39 or 41; an uppercase hex byte; a `g` in the
body; `sqx_` (unknown type letter); `SQU_` uppercase prefix; a leading glue
byte (`xsqu_…`, `_squ_…`) and a trailing glue byte.

**Benign:** `sqb_` + 40 hex in a badge URL; a bare 40-hex git SHA;
`SONAR_TOKEN=${{ secrets.SONAR_TOKEN }}`; `squ_…` placeholders.

## False-positive / false-negative boundary

- **Accepted false negatives:** legacy unprefixed tokens outside named
  contexts; badge tokens; SonarQube Cloud tokens; an uppercased copy.
- **Accepted false positives:** an unrelated `squ_`/`sqa_`/`sqp_` + exactly 40
  lowercase hex, such as an identifier that suffixes a SHA-1. Rare.

## Issuance checklist (optional confirmation; structure only)

For one user token and one project analysis token on a current SonarQube
Server:

- total length (expect 44) and prefix;
- alphabet classes (expect lowercase hex only);
- `rawValueRetained: false` and revoked.
