# #1012 research: `aws:sts-service-bearer-token` (`ABIA`) and `aws:context-specific-credential` (`ACCA`)

[Research index](README.md) ·
[Issue #1012](https://github.com/redact-secret/redact-secret/issues/1012) ·
[`ASIA` research](aws-sts-temporary-access-key.md)

Frozen 2026-09-29. Desk research only: no key was issued, and no issued or
leaked credential is evidence. Sources were accessed on 2026-09-29.

**Verdict: NOT-A-SECRET for both.** `ABIA` and `ACCA` prefix **identifiers**:
the access key ID that CloudTrail records for a service bearer token, and the
`ServiceSpecificCredentialId` of a service-specific credential. The secrets
they belong to carry no documented `ABIA` or `ACCA` prefix. Recommendation:
relabel both support-matrix rows as identifiers, not redaction targets. If an
identifier grammar is ever wanted, it is blocked (below).

## Current product behaviour

`aws-access-key` matches `AKIA` and `ASIA` only. Neither prefix is claimed.
Both support-matrix rows carry the same reason: "Documented in the same IAM
unique-identifier prefix table as AKIA/ASIA; not matched by the AKIA-only
pattern."

## Sources

| # | Source | Date | Class | Ruling | Statement |
|---|---|---|---|---|---|
| 1 | [IAM identifiers, prefixes](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_identifiers.html#identifiers-prefixes) | read 2026-09-29 | provider docs | T1 (prefix, role) | table rows "ABIA — AWS STS service bearer token" and "ACCA — Context-specific credential", among resource-ID prefixes (AGPA, AIDA, AIPA, ANPA, ANVA, APKA, AROA, ASCA). The page's unique-ID example is 21 characters |
| 2 | [Service bearer tokens](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_bearer.html) | read 2026-09-29 | provider docs | T1 (role) | "The token's access key ID begins with the `ABIA` prefix. This helps you to identify operations that were performed using service bearer tokens in your CloudTrail logs." The bearer token itself (for example CodeArtifact's) is described with no prefix or format |
| 3 | [API keys for AWS services](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_api_keys_for_aws_services.html) | read 2026-09-29 | provider docs example | R5 (example shape) | `--service-specific-credential-id "ACCA…"`: a 19-character `EXAMPLE` placeholder. So `ACCA` prefixes the credential **ID**; the secret is the service password or API key value (Bedrock `ABSK…` keys are already a product family) |
| 4 | [IAM `ServiceSpecificCredential`](https://docs.aws.amazon.com/IAM/latest/APIReference/API_ServiceSpecificCredential.html) | read 2026-09-29 | provider docs | T1 (wide) | `ServiceSpecificCredentialId`: "unique identifier", length 20–128, `[\w]+`; the secret fields `ServicePassword` and `ServiceCredentialSecret` have no constraint |
| 5 | [gitleaks `aws.go` L15-L24 @ b58d3f1](https://github.com/gitleaks/gitleaks/blob/b58d3f102cf3a2c84cb7f923d05c25c9b1aed84b/cmd/generate/config/rules/aws.go#L15-L24) | 2025-05-27 | peer scanner rule | T2 | `ABIA` and `ACCA` in the access-key rule, `[A-Z2-7]{16}` |
| 6 | [trufflehog `pkg/detectors/aws/access_keys/accesskey.go` L78 @ 48b58d3](https://github.com/trufflesecurity/trufflehog/blob/48b58d3bf3f02ba17bf23b87f095499bc80c6fd7/pkg/detectors/aws/access_keys/accesskey.go#L78) | 2024-11-20 | peer scanner rule | T2 | `(?:AKIA\|ABIA\|ACCA)[A-Z0-9]{16}`, verified only as a pair with a 40-character secret |
| 7 | [awslabs/git-secrets L239 @ 7d6b970](https://github.com/awslabs/git-secrets/blob/7d6b970cbd3c216353cb22b383b70c150140662e/git-secrets#L239) and [awslabs/ferret-scan `validator.go` L1444 @ c3b10fb](https://github.com/awslabs/ferret-scan/blob/c3b10fba90a5ed6178314ac646988546122afc60/internal/validators/secrets/validator.go#L1444) | 2018, 2026 | provider-owned scanners | negative | neither AWS-owned scanner includes `ABIA` or `ACCA` |

Searched, nothing further: web search for "ACCA context-specific credential"
and CodeArtifact token format (third-party prefix charts only, no body
grammar); no provider example of a full `ABIA` value anywhere.

## Why not a secret family

- `ABIA` is what CloudTrail shows; the credential a user could leak is the
  service bearer token, which has no documented prefix (#2).
- `ACCA` is the `ServiceSpecificCredentialId` (#3, #4). The secret half is
  the service password or API key value; the Bedrock API key form is already
  covered by `aws-bedrock-long-term-api-key`.
- The remaining table prefixes (AGPA, AIDA, AIPA, ANPA, ANVA, APKA, AROA,
  ASCA) are resource or public-key identifiers. Peer scanners that match
  them count as false-positive risk, not coverage.

## If an identifier grammar were wanted (blocked)

- **Exact missing evidence:** total length (the `ACCA` example is 19, the API
  minimum is 20, peers assume 20) and alphabet (`[A-Z2-7]` vs `[A-Z0-9]`). No
  provider example of a full `ABIA` value exists. Only one corroboration
  class (peer rules) exists, so T2 fails.
- **Structure-only check:** `aws iam create-service-specific-credential`
  (read the ID) and `aws codeartifact get-authorization-token` (read the
  CloudTrail `accessKeyId`). Record total length and whether the body holds
  any of `0 1 8 9`. Delete the credential afterwards.

## Residual risk

None for redaction: the leaked secrets are either unprefixed (bearer tokens,
service passwords, covered by context) or already a product family
(`ABSK…`).
