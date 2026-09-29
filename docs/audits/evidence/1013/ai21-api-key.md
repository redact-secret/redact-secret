# #1013 evidence: `ai21:api-key`

[Index](README.md) ·
[Issue #1013](https://github.com/redact-secret/redact-secret/issues/1013) ·
[Spec: keyword-gated provider keys (#868)](../../../specs/detector-families.md#keyword-gated-provider-keys-868)

Frozen 2026-09-29. Desk research only: no key was issued, and no issued or
leaked credential is evidence. Shapes only.

**Contract under test (#868, context-constrained):** exactly 32
`[A-Za-z0-9]`, claimed only beside a same-line AI21 name or an
`AI21Client(...)` argument. Never bare.

**Status (pin at `b9e90915`):** pending, T0. #784 found no provider page,
SDK or scanner rule stating a shape.

**Verdict: READY-T2** (context-constrained), for the contract as it stands.
The corroborated route clears even without the provider-repository
literals (see the caveat).

## Sources

All read 2026-09-29.

| # | Source | Date | Owner | Class | Statement (shape only) |
| --- | --- | --- | --- | --- | --- |
| 1 | [AI21Labs/ai21-python `examples/studio/batches/batches.py#L6`](https://github.com/AI21Labs/ai21-python/blob/bbc422f6f955134c2e33a9473ec0f71d21611764/examples/studio/batches/batches.py#L6) | 2025-03-23 (AI21 SDK maintainer) | AI21 | provider-example | an `AI21Client(api_host=<staging host>, api_key=…)` literal: 32 characters, upper, lower and digits |
| 1b | Four more literals in the same repo: [`conversational_rag.py#L31`](https://github.com/AI21Labs/ai21-python/blob/fca372988e62c09e6ae03d6cc91ab83f62db2fd9/examples/studio/conversational_rag/conversational_rag.py#L31) (2024-08-07), [`chat_completions.py#L12`](https://github.com/AI21Labs/ai21-python/blob/b41b31af45308d6ae18f5cda43d03ad80f14a43d/examples/studio/chat/chat_completions.py#L12) (2024-08-19), [`chat_function_calling.py#L41`](https://github.com/AI21Labs/ai21-python/blob/fbb82672a50a63580846d0c7bc6c478d233f3701/examples/studio/chat/chat_function_calling.py#L41) (2024-08-20), [`chat_completions.py#L13`](https://github.com/AI21Labs/ai21-python/blob/52436959a8f5c6df98b06f2fe4d4df437801cad5/examples/studio/chat/chat_completions.py#L13) (2025-02-25) | as listed | AI21 | provider-example | each 32 `[A-Za-z0-9]`, mixed case and digits |
| 2 | [AI21Labs/Rick-and-Morty-episode-generator `PlotGenerator.jsx#L11`](https://github.com/AI21Labs/Rick-and-Morty-episode-generator/blob/732d4b05fac6ffbf5f4604c5a3c3fe9dfbd96a42/src/api/PlotGenerator.jsx#L11) | 2023-01-12 | AI21 | provider-example | a `Bearer` value sent to the AI21 Studio API: 32 alphanumerics |
| 3 | [Vulnetix/cli `internal/sast/rules/vnx-sec-315.rego#L25`](https://github.com/Vulnetix/cli/blob/c6e24fc9b0148dc0a227da70774300fba7f339ee/internal/sast/rules/vnx-sec-315.rego#L25) | 2026-06-14 | Vulnetix | peer-scanner-rule | `(?i)ai21[_-]?api[_-]?key\s*[:=]\s*['"]?([A-Za-z0-9]{32})['"]?` |
| 4 | [cunnymessiah/keychecker `main.py#L242`](https://github.com/cunnymessiah/keychecker/blob/122eadc6bdbbeec9f31e94878f98c4692d5b5718/main.py#L242) | 2023-12-16 | cunnymessiah | independent-implementation (regex filter, then a live AI21 check) | `ai21_and_mistral_regex = re.compile('[A-Za-z0-9]{32}')` |
| 5 | [MCERQUA/LLM-Runner-Router `BYOKManager.js#L287-L290`](https://github.com/MCERQUA/LLM-Runner-Router/blob/dc020cfeb6ae071d5582bed6ce3563eea64ae8fd/src/auth/BYOKManager.js#L287-L290) | 2025-08-26 | MCERQUA | independent-implementation | `ai21: { keyFormat: '[A-Za-z0-9]{32}', baseURL: 'https://api.ai21.com/studio/v1' }` |
| 6 | [Amal-David/keyleak-detector `app.py#L125`](https://github.com/Amal-David/keyleak-detector/blob/bfafac5adb7e9fe6cf696f65ca8e5b52ae004d75/app.py#L125) | 2025-11-01 | Amal-David | peer-scanner-rule | 32 or more: a floor only, not counted |
| 7 | mongodb/kingfisher `ai21.yml` [at introduction](https://github.com/mongodb/kingfisher/blob/8b2c79e70fbc04bc2ab5c58a80e6679aed717299/data/rules/ai21.yml#L1-L21) | 2025-07-18; deleted 2026-08-21 | MongoDB | peer-scanner-rule | `ai21` + a UUID (contradicts) |
| 8 | [bgauryy/octocode `patterns.rs#L1284`](https://github.com/bgauryy/octocode/blob/c265e3f9413161c900cbf4aa70d451b8e6b3920a/packages/octocode-engine/src/security/patterns.rs#L1284) | 2026-07-12 | bgauryy | peer-scanner-rule | `AI21_API_KEY` + 40–64 alphanumerics (contradicts) |

Searched with no shape statement: docs.ai21.com (`/reference/authentication`:
"Use your API key as the token"; `/docs/create-api-key`: only the last few
characters are shown later); every other non-fork AI21Labs repository (full
history; ai21-typescript has no 32-character literal, and no AI21 repository
has a UUID-shaped literal); langchain-ai21 (placeholders, no validation);
trufflehog, gitleaks, betterleaks, CredSweeper, osv-scalibr, noseyparker,
secretlint, detect-secrets, Microsoft security-utilities, semgrep-rules,
secrets-patterns-db and current Kingfisher (no AI21 rule); GitGuardian's
643 specific detectors (no AI21; a search hit was AI71); GitHub's
secret-scanning list (no AI21). Not reached: LlamaIndex, Reddit and Stack
Overflow beyond web search, Bedrock/SageMaker (AWS credentials, out of
scope).

## Corroborated-route count

- With the provider literals: #1/#1b/#2 (AI21), #3, #4, #5: 4 owners, 3
  non-summary classes (provider-example, peer-scanner-rule,
  independent-implementation).
- Without them: #3, #4, #5: 3 references, 3 owners, 2 classes. Still at the
  bar.

**Caveat on #1, #1b and #2.** These are key literals committed by AI21 staff
to public example code, several pointing at a staging host. Their validity
is unknown and was not tested. The folder's rule is that no issued or leaked
credential is evidence; whether a provider's own published literal counts as
a provider example (R5) or as a leak is a maintainer call (Q-AI). The
verdict does not depend on it, but the ledger should record the choice.
Values are not reproduced here.

## Contradictions

| Statement | Proposed status | Basis |
| --- | --- | --- |
| Kingfisher (2025-07 to 2026-08): AI21 key is a UUID | settled by #1/#1b/#2 if Q-AI accepts them; otherwise bounded | six provider literals (2023–2025) are 32 alphanumerics, none a UUID; Kingfisher deleted the rule. Bound: the contract excludes UUIDs |
| octocode: 40–64 alphanumerics | settled or bounded as above | every provider literal is 32; the contract claims exactly 32 |

## Maintainer ruling needed

Q-AI: may provider-committed key literals of unknown validity (#1, #1b, #2)
count as provider-example evidence? Either answer leaves the family
READY-T2; the answer decides whether the two contradictions are settled or
bounded.

## Optional issuance check

One Studio key, structure only: length 32; `[A-Za-z0-9]` only; no fixed
prefix or segments; the masked suffix length shown afterwards. Not required
for READY-T2.
