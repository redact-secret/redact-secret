# #1013 evidence: `github:fine-grained-personal-access-token`

[Index](README.md) ·
[Issue #1013](https://github.com/redact-secret/redact-secret/issues/1013) ·
[Spec: detector families](../../../specs/detector-families.md)

Frozen 2026-09-29. Desk research only: no token was issued, and no issued or
leaked credential is evidence. Shapes are given by prefix, length, alphabet
and separators only; provider examples are described, not reproduced.

**Contract under test (Beta.8 wave 1, #726):** `github_pat_` + 22
`[A-Za-z0-9]` + `_` + 59 `[A-Za-z0-9]`, 93 in total. No checksum, no fixed
leading digits.

**Matrix blocker (pin at `b9e90915`):** corroborated route 0 references,
0 owners, 0 classes (the benchmarks ledger has no record for this family).

**Verdict: READY-T2.** A READY-T1 reading exists but needs a maintainer
ruling (see the end).

## Sources

All read 2026-09-29. Dates are when the cited lines were introduced
(`git log -S` or first commit on the path), unless stated.

| # | Source | Date | Owner | Class | Statement (shape only) |
| --- | --- | --- | --- | --- | --- |
| 1 | docs.github.com, *About authentication to GitHub*, "GitHub's token formats" | live page | GitHub | provider docs | T1 for the prefix: fine-grained personal access token, `github_pat_`. No length |
| 2 | [community discussion 36441, reply 3951965](https://github.com/community/community/discussions/36441#discussioncomment-3951965) | 2022-10-24 | GitHub (user `hpsin`, profile "Product Manager for Identity", company @github) | provider staff statement (R3 candidate) | "purely a high-entropy string that's looked up on our backend … Your regex looks good though". The endorsed regex (2022-10-21, a community user) is `github_pat_` + 22 + `_` + 59 over a class that literally also admits `-` |
| 3 | [github/CopilotForXcode `TelemetryCleaner.swift#L65`](https://github.com/github/CopilotForXcode/blob/258d4577dcf8fba0e9131b514dbe45b5dbb8906c/Tool/Sources/TelemetryService/TelemetryCleaner.swift#L65) | 2025-02-12 (first commit of the file, "Release 0.30.0") | GitHub | provider-owned-code (redactor) | `github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59}` |
| 4 | [github/gh-aw-firewall `src/dlp.ts#L64-L65`](https://github.com/github/gh-aw-firewall/blob/8f9b21bf756e3a9a46819dc29118b92e96c1b7a8/src/dlp.ts#L64-L65) | 2026-03-13 | GitHub | provider-owned-code (DLP) | same 22/59 regex |
| 5 | [github/gh-aw-mcpg `internal/sanitize/sanitize.go#L44`](https://github.com/github/gh-aw-mcpg/blob/4576c3e06752aae7d50502883db294b468844dc5/internal/sanitize/sanitize.go#L44) | 2026-06-13 | GitHub | provider-owned-code | same 22/59 regex |
| 6 | [github/docs REST data `credentials.json#L29`](https://github.com/github/docs/blob/e4859a83ac13c5715b723b3d17e273beba5c4572/src/rest/data/fpt-2026-03-10/credentials.json#L29) ("Revoke a list of credentials" example) | file 2026-03-18; endpoint GA 2025-04-29 | GitHub | provider-example (R5) | one full-length value: 82 after the prefix, `_` at body offset 22, segments 22 and 59, alphanumeric; the body starts with two letters, not `11` |
| 7 | [google/osv-scalibr `veles/secrets/github/pat_finegrained_detector.go#L24-L26`](https://github.com/google/osv-scalibr/blob/5ab8022c6d67ff99d91d9750f2456ed9549fe8cb/veles/secrets/github/pat_finegrained_detector.go#L24-L26) | 2025-09-18 | Google | peer-scanner-rule | `github_pat_[A-Za-z0-9]{22}_[A-Za-z0-9]{59}` (its comment says 92 bytes, an off-by-one) |
| 8 | [aquasecurity/trivy `pkg/fanal/secret/builtin-rules.go#L171`](https://github.com/aquasecurity/trivy/blob/3a1b311e63a1b64ab3221bf52683581b77187198/pkg/fanal/secret/builtin-rules.go#L171) | 2023-12-07 | Aqua | peer-scanner-rule | same 22/59 regex |
| 9 | [gitleaks `cmd/generate/config/rules/github.go#L43`](https://github.com/gitleaks/gitleaks/blob/b58d3f102cf3a2c84cb7f923d05c25c9b1aed84b/cmd/generate/config/rules/github.go#L43) | 2022-11-09, current form 2024-09-18 | gitleaks | peer-scanner-rule | `github_pat_\w{82}` (superset) |
| 10 | [aws/eks-anywhere `pkg/git/providers/github/github.go#L23`](https://github.com/aws/eks-anywhere/blob/8758183b5623691a8d565521241d53ac25a6d676/pkg/git/providers/github/github.go#L23) (used at L120-L129) | 2023-05-04 | AWS | independent-implementation (rejects a non-matching token) | 22/59 anchored (the ungrouped alternation is a precedence bug; the fine-grained branch is exact) |
| 11 | [coderamp-labs/gitingest `git_utils.py#L26-L29`](https://github.com/coderamp-labs/gitingest/blob/4e259a02fe72115bee538271622f1234a81c8e1a/src/gitingest/utils/git_utils.py#L26-L29) (`fullmatch` at L395) | 2025-06-30 | coderamp-labs | independent-implementation (validator) | "22 alphanumerics + `_` + 59 alphanumerics" |
| 12 | [slint-ui/slint `tools/slintpad/src/github.ts#L26`](https://github.com/slint-ui/slint/blob/d1371e535a4197afa36efcb95aa155c372af0175/tools/slintpad/src/github.ts#L26) | 2023-03-29 | Slint | independent-implementation (validator) | 22/59 anchored |
| 13 | [electron/fiddle `src/constants.ts#L11-L15`](https://github.com/electron/fiddle/blob/a63225b53664fd750828c29aa35de4b4d0eb0b28/src/constants.ts#L11-L15) | 2026-06-03 | Electron | independent-implementation (sign-in validation) | 22/59 anchored |
| 14 | noseyparker [`github.yml#L125`](https://github.com/praetorian-inc/noseyparker/blob/2e6e7f36ce36619852532bbe698d8cb7a26d2da7/crates/noseyparker/data/default/builtin/rules/github.yml#L125); secretlint [`index.ts#L106`](https://github.com/secretlint/secretlint/blob/0001184f56165e7db7ab1b3adc1f957911c78f46/packages/@secretlint/secretlint-rule-github/src/index.ts#L106); trufflehog [`v2/github.go#L37`](https://github.com/trufflesecurity/trufflehog/blob/48b58d3bf3f02ba17bf23b87f095499bc80c6fd7/pkg/detectors/github/v2/github.go#L37) | 2023-01-27; 2022-10-31; — | Praetorian; secretlint; Truffle Security | peer-scanner-rule | `[0-9a-zA-Z_]{82}`, `[A-Za-z0-9_]{82}`, `[a-zA-Z0-9_]{36,255}`: supersets of the contract |
| 15 | cli/cli [`internal/gh/gh.go#L117`](https://github.com/cli/cli/blob/1863cb7c0f1d27e9479a95edb30ba97fcc6c01b1/internal/gh/gh.go#L117); github/github-mcp-server [`pkg/utils/token.go#L26`](https://github.com/github/github-mcp-server/blob/85598ba6e1256f7ebf4867b95d63b833c4549264/pkg/utils/token.go#L26) | — | GitHub | provider-owned-code | prefix only (`HasPrefix(token, "github_pat_")`) |

Not counted: Microsoft `security-utilities` (checked at `638ad20e`) has no
`github_pat_` pattern; the fine-grained PAT launch post (2022-10-18) and
GitGuardian's detector page state no format; org:octokit has no hit.

## Corroborated-route count

Counting only references that corroborate the full 22 + `_` + 59 shape:
#3–#6 (GitHub, one owner), #7 (Google), #8 (Aqua), #10 (AWS), #11
(coderamp-labs), #12 (Slint), #13 (Electron). That is 9 references, 6
owners and 3 non-summary classes (provider-owned-code, provider-example,
independent-implementation), plus peer-scanner-rule. The bar is 3 / 3 / 2.

## Contradictions

| Statement | Proposed status | Basis |
| --- | --- | --- |
| trufflehog (36–255), CredSweeper (80–255), `\w{82}` rules admit other widths or `_` anywhere | bounded | supersets; the contract claims only 22 + `_` + 59 and asserts nothing on other widths |
| A GitHub-owned skill file (`github/awesome-copilot`, [`secret-patterns.md#L27`](https://github.com/github/awesome-copilot/blob/997e95a6e42869c350f8ca6ec4c066287697c9f0/skills/security-review/references/secret-patterns.md#L27)) uses `github_pat_` + 82 alphanumerics, no `_` | settled by #3–#6 | community-authored content in a GitHub repo; it cannot match the provider example (#6) |
| The endorsed 2022 regex's class admits `-` | settled by #3–#6 | GitHub-owned code and the provider example are alphanumeric |
| A leading `11` is fixed; a body checksum exists (third-party README) | bounded | no provider source states either; #6 starts with letters; the staff statement (#2) reads against a checksum. The contract claims neither |

## Maintainer ruling that would make this T1

Q-GH: does #2 (a dated staff endorsement of the exact grammar, R3) or #3
(GitHub-owned code matching exactly this grammar since 2025-02-12, R1/R9)
count as a T1 grammar statement? #3 redacts; it does not generate or
validate. Without a ruling the family is T2 and already clears the
corroborated route.

## Out of scope

The matrix also lists non-evidence gates for this family (benign and twin
fixture counts, 5 unresolved critical mutation findings, `empirical.mode`,
`uncertainty`, `supportedContexts`). Those are benchmarks-ledger and fixture
work, not evidence gaps.
