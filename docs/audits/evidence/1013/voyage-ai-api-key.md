# #1013 evidence: `voyage-ai:api-key`

[Index](README.md) ·
[Issue #1013](https://github.com/redact-secret/redact-secret/issues/1013) ·
[Beta.10 research #785](https://github.com/redact-secret/redact-secret/issues/785)

Frozen 2026-09-29. Desk research only: no key was issued, and no issued or
leaked credential is evidence. Shapes only.

**Status (pin at `b9e90915`):** pending, no corpus. #785: one betterleaks
rule and community pages for the body; `pa-` and `al-` are common
two-letter prefixes.

**Verdict: STILL-BLOCKED**, with two ruling paths that would unblock part
of it:

- `al-` (unscoped Atlas key): READY-T1 by ruling Q-VO1 or Q-VO2, grammar
  `al-` + 43 `[A-Za-z0-9_-]`.
- `pa-` (standalone dashboard key): READY-T1 only by Q-VO2; otherwise
  hands-on issuance.
- `al-eu-` (and any other region-scoped key): hands-on issuance only.

## Sources

All read 2026-09-29.

| # | Source | Date | Owner | Class | Statement (shape only) |
| --- | --- | --- | --- | --- | --- |
| 1 | [mongodb/openapi `openapi/v2.yaml#L1781-L1798`](https://github.com/mongodb/openapi/blob/5e6f651422c9ac9efd2ad21eba8a4256c38af864/openapi/v2.yaml#L1781-L1798), schema `AiModelApiKeyResponse` (Atlas Admin API) | 2026-07-14 (first commit with the schema) | MongoDB (owns Voyage AI) | provider-example (R5) | `secret`: "The full API key secret used for interacting with the embedding / reranking service"; example: one full-length value, `al-` + 43 alphanumerics (46 in total). `maskedSecret`: `al-` + `****` + 4. **New** |
| 2 | same file, `name` | same | MongoDB | provider docs | `name: maxLength: 250`: the "250 characters" limit applies to the key's **name**, not the key |
| 3 | [mongodb/docs `content/voyageai/source/management/api-keys.txt#L119-L121`](https://github.com/mongodb/docs/blob/2fdb2535da7d5595a9974569f1e7b981b797cd45/content/voyageai/source/management/api-keys.txt#L119-L121) (rendered on mongodb.com/docs/voyageai/management/api-keys) | 2026-09-01 ("EU Scoped Tokens") | MongoDB | provider docs | T1 for the `al-eu-` prefix: "The key prefix encodes the scope. For example, a key scoped to Europe begins with `al-eu-`." No `al-us-` prefix is documented |
| 4 | [voyage-ai/voyageai-python `voyageai/util.py#L99-L103`](https://github.com/voyage-ai/voyageai-python/blob/9aca465efd0011c478031f6d584b70a3a4393a7c/voyageai/util.py#L99-L103) | 2025-12-15 (MongoDB author) | Voyage/MongoDB | provider-owned-code (routing) | T1 for prefix routing: keys starting `al-` go to `ai.mongodb.com`, others to `api.voyageai.com`. No length; no `al-eu-` routing |
| 5 | [mongodb-labs/ai-ml-pipeline-testing `.evergreen/utils.sh#L134-L146`](https://github.com/mongodb-labs/ai-ml-pipeline-testing/blob/dce1cd9ec156d602b7af040678bcb022bbbf1159/.evergreen/utils.sh#L134-L146) | 2026-09-11 | MongoDB | provider-owned-code (validates the prefix) | T1 for both prefixes: "Keys from voyageai.com begin with 'pa-' … keys from mongodb.com begin with 'al-'" |
| 6 | mongodb/kingfisher `voyageai.yml` [at introduction](https://github.com/mongodb/kingfisher/blob/9eff41f4ff2dc6dd38174aab50b416cef9c2a416/data/rules/voyageai.yml#L5-L10) and [last native version](https://github.com/mongodb/kingfisher/blob/4666a2dd990edb34f7c5b6f9a9985c9a8b8c6752/crates/kingfisher-rules/data/rules/voyageai.yml#L5-L54) | `pa-` 2025-12-05; `al-` 2026-05-18; native file removed 2026-08-21 | MongoDB (author is MongoDB staff) | peer-scanner-rule written by provider staff | "Matches keys starting with 'pa-' followed by 43 URL-safe base64 characters"; `pa-` and `al-` each + 43 `[A-Za-z0-9_-]` |
| 7 | [betterleaks `cmd/generate/config/rules/voyageai.go#L14`](https://github.com/betterleaks/betterleaks/blob/fa62e6aaad9de6da71de49e7114234700c84006e/cmd/generate/config/rules/voyageai.go#L14), [PR #324](https://github.com/betterleaks/betterleaks/pull/324) | 2026-08-31 | betterleaks (author is MongoDB staff) | peer-scanner-rule and dated staff statement | `(?:pa\|al)-[A-Za-z0-9_-]{43}`, keyword `voyage`. PR body: "I work for MongoDB and personally authored this detector" |
| 8 | [sweepai/sweep `sweepai/cli.py#L289`](https://github.com/sweepai/sweep/blob/a8b8b67bda4f89faac9314d34e7c7d5a64f76046/sweepai/cli.py#L289); [julep-ai/steadytext `voyageai.py#L233-L235`](https://github.com/julep-ai/steadytext/blob/e4d877620a6801de9705e362eda8d3a4f80cc5d1/steadytext/providers/voyageai.py#L233-L235); [MadAppGang/mnemex `cli.ts#L2920-L2921`](https://github.com/MadAppGang/mnemex/blob/ec43ed87c9ec8ab9a7b325eb7e1682438432185a/src/cli.ts#L2920-L2921) | 2024-04-02; 2025-08-14; 2025-12-17 | three third parties | independent-implementation | `pa-` prefix checks only; no length |

Searched with no body statement: docs.voyageai.com (API key and FAQ pages);
mongodb.com/docs/voyageai/api-and-clients (routing by source and geography
only); every voyage-ai repository (python, typescript-sdk, docs, openapi,
recipes, langchain-voyageai; no `pa-`/`al-` literal of 20+ characters);
GitGuardian (no Voyage detector); GitHub secret scanning (no Voyage or Atlas
model-key pattern); trufflehog, gitleaks, CredSweeper, osv-scalibr,
noseyparker, secretlint, detect-secrets, Microsoft security-utilities,
semgrep-rules, secrets-patterns-db (none); LiteLLM (no validation). Not
reached: Reddit and the MongoDB community forum.

## Why the corroborated route does not clear

Every source that states the 43-character body traces to MongoDB: the
OpenAPI example (#1), and two scanner rules written by the same MongoDB
engineer (#6, #7). betterleaks is a distinct repository owner, but the rule
content is provider-staff authored, so it is one voice, not an independent
one. Third-party implementations (#8) check only the prefix. A third
independent owner for the body is missing.

## Maintainer rulings that would unblock part of it

- **Q-VO1 (R5 as grammar):** accept the Atlas Admin API example (#1) as the
  `al-` grammar. Result: `al-` + 43, alphabet `[A-Za-z0-9_-]` (#1 shows only
  alphanumerics, but R8 forbids narrowing on a single example when the
  staff-authored rule admits `_` and `-`).
- **Q-VO2 (R3 for staff-authored scanner rules):** accept #6/#7, dated
  statements by a MongoDB engineer who says he authored the detector, as a
  provider staff statement. Result: `pa-` and `al-` each + 43
  `[A-Za-z0-9_-]`, T1 as of 2025-12-05 (`pa-`) and 2026-05-18 (`al-`).

Neither ruling covers `al-eu-`: with a 43-character random part, an
`al-eu-` key is longer than an `al-` key, and a `al-` + 43 rule with a
boundary would miss it.

## Contradictions

| Statement | Proposed status | Basis |
| --- | --- | --- |
| "A model API key can't exceed 250 characters" read as a key-length ceiling | resolved | #2 and #3: the limit is on the key's name |
| Docs say geography-scoped keys route to `eu.ai.mongodb.com`; SDK v0.5.0 routes every `al-` key to `ai.mongodb.com` | open, not a shape conflict | a behaviour gap; does not block a grammar |

## Issuance checks

- `pa-` (needed unless Q-VO2): one dashboard key from dash.voyageai.com.
  Total length (46 expected); prefix `pa-`; whether the body contains `_`
  or `-`.
- `al-eu-` (needed in all cases): one EU-scoped Atlas model API key (a
  paid tier). Total length; whether 43 characters follow `al-eu-` or `al-`;
  alphabet.
- `al-` (only if both rulings are refused): one unscoped Atlas model API
  key. Total length; alphabet.

Revoke each key after the structural reading.
