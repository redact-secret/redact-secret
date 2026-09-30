# #1012 research: `aws:sts-temporary-access-key` (`ASIA`)

[Research index](README.md) ·
[Issue #1012](https://github.com/redact-secret/redact-secret/issues/1012) ·
[Companion: secret access key](aws-iam-user-secret-access-key.md) ·
[Other IAM prefixes](aws-other-iam-prefixes.md)

Frozen 2026-09-29. Desk research only: no key was issued, and no issued or
leaked credential is evidence. Sources were accessed on 2026-09-29.

**Verdict: READY-T2** (READY-T1 if the maintainer applies R2 to AWS's own
ferret-scan rule, #5). `ASIA` + exactly 16 `[A-Z0-9]` is corroborated by an
AWS docs example, two AWS-owned scanners and four peer scanners from
distinct owners. The prefix is T1 from AWS docs.

This is an **identifier**, not a secret on its own. AWS says an `ASIA` ID is
"unique only in combination with the secret access key and the session
token". Whether a bare ID is redacted stays a policy decision; the contract
below only fixes its grammar.

## Current product behaviour

`aws-access-key` (`crates/secret-scan-core/src/detectors/aws.rs`) already
matches `AKIA` or `ASIA` + exactly 16 `[A-Z0-9]`, boundary `[A-Za-z0-9]`, as
`aws_access_key_id`, high, always-redact. The benchmarks contract for
`aws-access-key` is `^AKIA[A-Z2-7]{16}$` (AKIA only) and scores a bare AWS
ID as `policy`, with the reason "Some legacy ASIA values also use digits
outside the base32 alphabet"
([`assessment.ts` @ 5380aa3](https://github.com/redact-secret/redact-secret-benchmarks/blob/5380aa3a421555883225a62358fa40f81dcd2baa/benchmarks/evaluation/domains/credential/assessment.ts#L749)).
No source for that reason was found (see contradictions).

So the gap is on the benchmarks side: the product claims `ASIA`, but no
contract covers it.

## Sources

| # | Source | Date | Class | Ruling | Statement |
|---|---|---|---|---|---|
| 1 | [IAM identifiers, prefixes](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_identifiers.html#identifiers-prefixes) | read 2026-09-29 | provider docs | T1 (prefix) | "ASIA — Temporary (AWS STS) access key IDs use this prefix, but are unique only in combination with the secret access key and the session token." Also: "Prefixes may vary based on when they were created." |
| 2 | [STS `GetAccessKeyInfo`](https://docs.aws.amazon.com/STS/latest/APIReference/API_GetAccessKeyInfo.html) | read 2026-09-29 | provider docs | T1 (wide) | "Access key IDs beginning with `ASIA` are temporary credentials"; AccessKeyId length 16–128, pattern `[\w]*` |
| 3 | [STS `AssumeRole` sample response](https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRole.html) | read 2026-09-29 | provider docs example | R5 (example shape) | an `ASIA` ID of 20 characters, uppercase and digits, ending `EXAMPLE`; "The size of the security token … is not fixed" |
| 4 | [awslabs/git-secrets `git-secrets` L239 @ 7d6b970](https://github.com/awslabs/git-secrets/blob/7d6b970cbd3c216353cb22b383b70c150140662e/git-secrets#L239) | 2018-10-05, merged 2018-10-24 by an AWS principal engineer (PR #89) | provider-repository scanner rule | R2 unclear: provider-merged, externally written | `(A3T[A-Z0-9]\|AKIA\|AGPA\|AIDA\|AROA\|AIPA\|ANPA\|ANVA\|ASIA)[A-Z0-9]{16}` |
| 5 | [awslabs/ferret-scan `internal/validators/secrets/validator.go` L1444 @ c3b10fb](https://github.com/awslabs/ferret-scan/blob/c3b10fba90a5ed6178314ac646988546122afc60/internal/validators/secrets/validator.go#L1444) | 2026-07-21 (5b599c1), author with an `@amazon.com` address | provider-authored scanner rule | R2 = T1 candidate | `\b(?:AKIA\|ASIA)[0-9A-Z]{16}\b` (used to pair a secret key with its ID) |
| 6 | [trufflehog `pkg/detectors/aws/session_keys/sessionkey.go` L74-L75 @ 48b58d3](https://github.com/trufflesecurity/trufflehog/blob/48b58d3bf3f02ba17bf23b87f095499bc80c6fd7/pkg/detectors/aws/session_keys/sessionkey.go#L74-L75) | 2024-11-20 | peer scanner rule | T2 | `\b((?:ASIA)[A-Z0-9]{16})\b` with a session token |
| 7 | [gitleaks `cmd/generate/config/rules/aws.go` L15-L24 @ b58d3f1](https://github.com/gitleaks/gitleaks/blob/b58d3f102cf3a2c84cb7f923d05c25c9b1aed84b/cmd/generate/config/rules/aws.go#L15-L24) | 2025-05-27 | peer scanner rule | T2 | `(?:A3T[A-Z0-9]\|AKIA\|ASIA\|ABIA\|ACCA)[A-Z2-7]{16}`; comment "current AWS tokens cannot contain [0,1,8,9]" (betterleaks carries the same rule; counted once) |
| 8 | [noseyparker `rules/aws.yml` L3-L6 @ 2e6e7f3](https://github.com/praetorian-inc/noseyparker/blob/2e6e7f36ce36619852532bbe698d8cb7a26d2da7/crates/noseyparker/data/default/builtin/rules/aws.yml#L3-L6) | HEAD 2026-02-21 | peer scanner rule | T2 | same prefix set as #4, `[A-Z0-9]{16}` |
| 9 | [google/osv-scalibr `veles/secrets/awsaccesskey/detector.go` L25-L26 @ 5ab8022](https://github.com/google/osv-scalibr/blob/5ab8022c6d67ff99d91d9750f2456ed9549fe8cb/veles/secrets/awsaccesskey/detector.go#L25-L26) | 2026-01-29 | peer scanner rule | T2 | `\b(AKIA[A-Z0-9]{16}\|ASIA[A-Z0-9]{16})\b` |
| 10 | [Summit Route, "AWS security credential formats"](https://summitroute.com/blog/2018/06/20/aws_security_credential_formats/) | 2018-06-20 | independent research | summary | characters "A-Z and 2-7"; "undocumented by AWS and therefore subject to change" |
| 11 | [Aidan Steele, "AWS Access Key ID formats"](https://awsteele.com/blog/2020/09/26/aws-access-key-format.html) | 2020-09-26 | independent research | summary | valid characters `A-Z2-7`; only 20-character IDs observed |

Searched, nothing further: AWS IAM `AccessKey` and STS `Credentials` API
pages (no exact length); GitHub code search in `awslabs` and `aws` for a
base32 statement (none); CredSweeper (no `ASIA` rule). The GitHub
secret-scanning list reports `aws_temporary_access_key_id` only as part of a
three-part set. `aws-samples` and `amzn` were not searched (code-search
quota).

## Corroboration count (T2 route)

References: #3 (AWS example), #4 and #5 (AWS-owned code), #6 (Truffle
Security), #7 (gitleaks), #8 (Praetorian), #9 (Google). Owners: five.
Classes other than summary: provider example / provider code, and peer
scanner rule. Both bars are met.

## Supported shape

| Part | Grammar | Provenance | Tier |
| --- | --- | --- | --- |
| Prefix | `ASIA` | AWS docs (#1, #2) | T1 |
| Body | exactly 16 `[A-Z0-9]` (20 in total) | AWS example (#3), AWS-owned rules (#4, #5), peers (#6, #8, #9) | T2 (T1 if #5 is accepted under R2) |
| Boundary | not `[A-Za-z0-9]` on either side | product rule | policy |
| Checksum | none | — | — |

**Proposed type:** `aws_access_key_id` (unchanged; the product already
claims it). The benchmarks side adds `aws:sts-temporary-access-key` as a
contract with the companion note that the ID needs a secret access key and a
session token to be usable.

## Excluded shapes

| Shape | Why excluded |
| --- | --- |
| IDs of 17 to 128 characters or with lowercase (the API allows them) | no example or rule; accepted false negative |
| `ABIA`, `ACCA` and resource IDs (`AIDA`, `AROA`, …) | identifiers, see [aws-other-iam-prefixes.md](aws-other-iam-prefixes.md) |
| The session token | no prefix; a separate question (see the companion file) |

## Overlap and output policy

- **Existing detectors.** `aws-access-key` claims it today. No change.
- **Policy parts.** The bare-ID severity is policy, not grammar. The product
  redacts it; benchmarks scores a bare ID as `policy`. This research does not
  change either.

## Test axes

Positives: bare, env (`AWS_ACCESS_KEY_ID=`), `~/.aws/credentials`, JSON from
`sts assume-role`, chat sentence. Twins: body of 15 and 17; a lowercase
byte; `ASIB`; glue bytes on either side. Benign: `AKIA` IDs (same type),
`AIDA`/`AROA` IDs (not claimed), an all-`A` identifier run.

## False-positive / false-negative boundary

- **Accepted false negatives:** non-20-character IDs.
- **Accepted false positives:** a 20-character uppercase identifier that
  happens to start `ASIA`; AWS docs examples ending `EXAMPLE` (the product
  already treats them per the #867 placeholder precedent).

## Contradictions

1. **Alphabet `[A-Z0-9]` vs `[A-Z2-7]`.** No AWS source settles which bytes
   are issued. Bounded: `[A-Z0-9]` is the wider class (R8 forbids narrowing
   from a third-party rule).
2. **Length 16–128 (API) vs exactly 20 (every example and rule).** Bounded:
   the contract claims 20 only.
3. **Benchmarks' "legacy ASIA values with digits outside base32".** Unsourced.
   It does not affect the `[A-Z0-9]` contract, which already admits them; the
   benchmarks reason should cite a source or be dropped.

## Issuance checklist (optional confirmation; structure only)

`aws sts get-session-token` once: total length (20?), whether the body holds
any of `0 1 8 9`, `rawValueRetained: false`. Temporary credentials expire;
no revocation step is needed beyond expiry.
