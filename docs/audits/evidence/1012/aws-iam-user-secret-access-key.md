# #1012 research: `aws:iam-user-secret-access-key`

[Research index](README.md) ·
[Issue #1012](https://github.com/redact-secret/redact-secret/issues/1012) ·
[`ASIA` research](aws-sts-temporary-access-key.md)

Frozen 2026-09-29. Desk research only: no key was issued, and no issued or
leaked credential is evidence. Sources were accessed on 2026-09-29.

**Verdict: READY-T2, context-constrained only** (READY-T1 if the maintainer
applies R2 to AWS's own git-secrets and ferret-scan rules, #5 and #6).
Exactly 40 `[A-Za-z0-9/+]`, claimed only under a documented key name or
next to an `AKIA` ID. The value has no prefix, so a bare contract is not
possible; AWS's own detectors (Macie, git-secrets, ferret-scan) all require
context too. This fits the benchmarks `context-constrained-empirical`
profile.

## Current product behaviour

There is no AWS-specific detector for the secret half. `generic-token` lists
`aws_secret_access_key` among its high-signal names, so
`AWS_SECRET_ACCESS_KEY=<value>` gives `contextual_secret`, high, redact,
without a width or alphabet check. The synthetic probe on `main` (below)
shows two gaps: the CloudFormation and SDK JSON form
`"SecretAccessKey": "<value>"` gives **no finding**, and neither does the
bare value (expected).

## Sources

| # | Source | Date | Class | Ruling | Statement |
|---|---|---|---|---|---|
| 1 | [STS `GetAccessKeyInfo`](https://docs.aws.amazon.com/STS/latest/APIReference/API_GetAccessKeyInfo.html) | read 2026-09-29 | provider docs example | R5 (example shape) | "Access keys consist of two parts: an access key ID … and a secret access key"; the example secret is 40 characters of `[A-Za-z0-9/]` ending `EXAMPLEKEY` |
| 2 | [STS `AssumeRole` sample response](https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRole.html) | read 2026-09-29 | provider docs example | R5 | the temporary secret example is 41 characters (the same placeholder with one extra letter) |
| 3 | [IAM `AccessKey`](https://docs.aws.amazon.com/IAM/latest/APIReference/API_AccessKey.html), [STS `Credentials`](https://docs.aws.amazon.com/STS/latest/APIReference/API_Credentials.html) | read 2026-09-29 | provider docs | none | `SecretAccessKey`: "Type: String", no length or pattern |
| 4 | [Amazon Macie managed data identifiers, credentials](https://docs.aws.amazon.com/macie/latest/user/mdis-reference-credentials.html) | read 2026-09-29 | provider docs (AWS's own detector) | T1 for "context is required" | `AWS_CREDENTIALS`: "Keyword required: Yes. Keywords include: aws_secret_access_key, credentials, secret access key, secret key, set-awscredential" |
| 5 | [awslabs/git-secrets L242 @ 7d6b970](https://github.com/awslabs/git-secrets/blob/7d6b970cbd3c216353cb22b383b70c150140662e/git-secrets#L242) | 2015-12-10 (initial commit, written by an AWS principal engineer) | provider-authored scanner rule | R2 = T1 candidate | a key-name-gated value `[A-Za-z0-9/\+=]{40}` |
| 6 | [awslabs/ferret-scan `internal/validators/secrets/validator.go` L1434-L1444 @ c3b10fb](https://github.com/awslabs/ferret-scan/blob/c3b10fba90a5ed6178314ac646988546122afc60/internal/validators/secrets/validator.go#L1434-L1444) | 2026-07-21, `@amazon.com` author | provider-authored scanner rule | R2 = T1 candidate | `(^\|[^A-Za-z0-9/+])([A-Za-z0-9/+]{40})(=*)($\|[^A-Za-z0-9/+=])`, gated by a key name `(?i)(?:aws_?)?secret_?access_?key\|aws_?secret(?:_?key)?` or an `AKIA`/`ASIA` ID on the same or an adjacent line |
| 7 | [trufflehog `pkg/detectors/aws/common.go` L16 @ 48b58d3](https://github.com/trufflesecurity/trufflehog/blob/48b58d3bf3f02ba17bf23b87f095499bc80c6fd7/pkg/detectors/aws/common.go#L16) | HEAD | peer scanner rule | T2 | `[A-Za-z0-9+/]{40}` with boundaries, only paired with an ID |
| 8 | [betterleaks `aws.go` L77-L91 @ fa62e6a](https://github.com/betterleaks/betterleaks/blob/fa62e6aaad9de6da71de49e7114234700c84006e/cmd/generate/config/rules/aws.go#L77-L91) | HEAD | peer scanner rule (gitleaks lineage) | T2 | keyword-gated `[A-Za-z0-9/+=]{40}`, entropy above 4 |
| 9 | [noseyparker `rules/aws.yml` L30-L43 @ 2e6e7f3](https://github.com/praetorian-inc/noseyparker/blob/2e6e7f36ce36619852532bbe698d8cb7a26d2da7/crates/noseyparker/data/default/builtin/rules/aws.yml#L30-L43) | HEAD 2026-02-21 | peer scanner rule | T2 | key-name-gated `[a-z0-9/+=]{40}` under `(?i)` |
| 10 | [google/osv-scalibr `veles/secrets/awsaccesskey/detector.go` L25-L26 @ 5ab8022](https://github.com/google/osv-scalibr/blob/5ab8022c6d67ff99d91d9750f2456ed9549fe8cb/veles/secrets/awsaccesskey/detector.go#L25-L26) | 2026-01-29 | peer scanner rule | T2 | `\b[A-Za-z0-9+/]{40}\b` paired with an ID within 10 KiB |
| 11 | [Summit Route, "AWS security credential formats"](https://summitroute.com/blog/2018/06/20/aws_security_credential_formats/) | 2018-06-20 | independent research | summary | Base64 of 30 random bytes: 40 characters, only `+` and `/` beyond alphanumerics |

Searched, nothing further: no AWS page states "40 characters" in prose; the
CloudWatch Logs managed identifier `AwsSecretKey` does not say whether a
keyword is required. AWS-org code search was cut short by the shared quota.

## Corroboration count (T2 route)

References #1, #5, #6 (AWS), #7 (Truffle Security), #8 (betterleaks), #9
(Praetorian), #10 (Google). Owners: five. Classes: provider example and
provider code, plus peer scanner rule.

## Role and blast radius

The secret half of a long-term IAM user access key. With the `AKIA` ID it
signs any API call the user's policies allow, until rotated.

## Supported shape (context-constrained)

| Part | Grammar | Provenance | Tier |
| --- | --- | --- | --- |
| Value | exactly 40 `[A-Za-z0-9/+]` | AWS example (#1), AWS-owned rules (#5, #6), peers | T2 (T1 under R2) |
| Boundary | not `[A-Za-z0-9/+=]` on either side | #6 | T2 |
| Context (required) | a key name: `aws_secret_access_key`, `AWS_SECRET_ACCESS_KEY`, `SecretAccessKey`, `secret_access_key`, `aws_secret_key`, "secret access key"; or an `AKIA` ID on the same or an adjacent line | Macie (#4), #5, #6 | T1 that AWS requires context; the name list is T2 |

**Proposed type:** `aws_secret_access_key`, a new provider type from
`aws-access-key` (or a keyed branch of `generic-token` with a provider type).
High, always-redact.

## Excluded shapes

| Shape | Why excluded |
| --- | --- |
| A bare 40-character run with no context | not attributable; AWS itself does not detect it without a keyword |
| A 40-character value containing `=` | not a Base64 of 30 bytes; bounded out |
| Temporary (`ASIA`-paired) secrets | the only temporary example is 41 characters (#2); scoped out until checked. The generic key-name path still covers them |
| Session tokens | a different credential, no prefix, variable length |

## Overlap and output policy

- **Existing detectors.** `generic-token` covers the env and YAML name forms
  as `contextual_secret`; the provider type would win on the same span. The
  new coverage is `"SecretAccessKey": "…"` JSON and the AKIA-adjacent form.
- **Policy parts.** The name list and the adjacency window are policy; the
  width and alphabet are the contract.

## Test axes

Positives: `~/.aws/credentials` (`aws_secret_access_key = …`), env, JSON
`SecretAccessKey`, CloudFormation `Outputs`, `aws configure list` style,
next-line-after-`AKIA`. Twins: 39 and 41; a `=` inside; a `-` or `_` inside;
a glue byte. Benign: a 40-hex Git SHA under an unrelated name; a 40-character
Base64 under `sha256`/`etag` names; the `EXAMPLEKEY` docs value (claimed, per
the #867 placeholder precedent).

## False-positive / false-negative boundary

- **Accepted false negatives:** a bare secret with no name or ID; a 41-byte
  temporary secret if one exists.
- **Accepted false positives:** any 40-character Base64-alphabet value under
  an AWS secret key name.

## Contradictions

1. `=` inside the 40 (git-secrets, betterleaks, noseyparker) vs excluded
   (ferret-scan, trufflehog, veles, benchmarks' own validator). Bounded:
   `=` excluded, since 30 bytes encode to 40 characters without padding.
2. The 41-character temporary example (#2). Bounded by scoping to IAM-user
   keys; settled only by an issued temporary key.

## Issuance checklist (optional; structure only)

One `aws sts get-session-token` secret: total length (40 or 41?) and the
classes present. `rawValueRetained: false`; let it expire.
