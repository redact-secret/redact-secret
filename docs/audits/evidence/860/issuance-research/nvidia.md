# #860 issuance research: `nvidia:ngc-api-key`

[Issuance research index](README.md) ·
[Handoff](../nvidia.md) ·
[Rulings R9–R10](https://github.com/redact-secret/redact-secret/issues/860#issuecomment-5880547337)

Frozen 2026-09-28. Desk research only: no key was issued, and no issued or
leaked credential is evidence.

**Gated property:** the body length after `nvapi-` and its alphabet
(Personal, Service and build.nvidia.com keys).

**Research verdict: CLOSED as an open-ended grammar under R2.** The READY
rule says that where the provider's own grammar is open-ended, that grammar
is the T1 grammar and the contract adds only a bounded cap as project policy.
An exact width is still not T1.

**Maintainer disposition (2026-09-28): closed by research under the existing
rulings.** `nvapi-` + at least 60 `[A-Za-z0-9_-]`; the upper cap is project
policy.

## Sources

All sources are in NVIDIA-owned orgs and provider-authored; none is a
verbatim copy of a public scanner rule.

| # | Source | Date | Class | Ruling | Statement |
|---|---|---|---|---|---|
| 1 | [NVIDIA-NeMo/nemo-helix `…/agents-secure/resources/pii_scan.py` L229-L232 @ 689f785](https://github.com/NVIDIA-NeMo/nemo-helix/blob/689f7852611b0151cee2748ca2b68e8e163e3b65/plugins/nemo-agents/src/nemo_agents_plugin/skills/agents-secure/resources/pii_scan.py#L229-L232) | added 2026-05-21 (f20bd5a, "Open Source Release of nemo-platform", `philipmattingly`) | provider-authored secret-scanning regex | R2 = T1 | `name="nvidia_api_key", regex=re.compile(r"\bnvapi-[A-Za-z0-9_\-]{60,}\b")` |
| 2 | [NVIDIA/SkillEvaluator `src/skillevaluator/validators/secrets.py` L57-L60 @ a2636b2](https://github.com/NVIDIA/SkillEvaluator/blob/a2636b2f886235f974ed4329029f923a12d0328b/src/skillevaluator/validators/secrets.py#L57-L60) | file since 2026-07-26 (`chrisknvidia`) | provider-authored custom gitleaks `[[rules]]` | R2 = T1 | `id = "nvidia-api-key"`, `regex = '''nvapi-[A-Za-z0-9_-]{40,}'''` |
| 3 | same file L51-L54 | same | provider-authored rule (legacy key) | R2 = T1 | `id = "nvidia-ngc-api-key"`, `regex = '''\$oauthtoken:\S{84}'''` (legacy NGC key = 84 non-space characters) |
| 4 | [NVIDIA-NeMo/labs-OO-Agents `src/nooa/tracing/_secret_scrubber.py` L118 @ 3374cea](https://github.com/NVIDIA-NeMo/labs-OO-Agents/blob/3374ceae9f1ba13ddbaceca752d8886d1d9dff3b/src/nooa/tracing/_secret_scrubber.py#L118) | HEAD 2026-09 | provider redaction regex | R2 | `nvapi-[A-Za-z0-9_\-]{20,}` |
| 5 | NVIDIA/NemoClaw `src/lib/trace.ts` L75, `profile.ts` L82, `podman-inference-args.ts` L41, `credential-filter-boundary.cts` L10; NVIDIA-NeMo/Guardrails `tests/recorded/test_cassette_sanitization.py` L44; NVIDIA/nemoclaw-community `detect.py` L836; NVIDIA/enterprise-ras `make_validation_bundle.py` L59 | 2026 | provider redaction regexes | R2 | floors of 8–20, all `[A-Za-z0-9_-]` |
| 6 | NVIDIA-NeMo/nemo-helix `plugins/_temporary-scaled-evals/src/scaled_evals/api/redaction.py` L28 | 2026 | provider redaction regex | R2 | `nvapi-[A-Za-z0-9._-]{8,}`: the only NVIDIA rule that also allows `.` (a looser redaction superset) |
| 7 | ngcsdk 4.36.6 (PyPI) `ngcbase/constants.py:385`, `ngcbase/command/config.py:301` | 2026 | provider CLI code | R1/R6 | `SCOPED_KEY_PREFIX = "nvapi-"`; `startswith("nvapi-")` then server-side `validate_sak_key` (no lexical length check) |
| 8 | [NVIDIA/NemoClaw `src/lib/validation.ts` L255-L271 @ 6721c27](https://github.com/NVIDIA/NemoClaw/blob/6721c275ba9c30ea99c404872379110dfba5a99a/src/lib/validation.ts#L255-L271) | 2026 | provider code | R6 | `!key.startsWith("nvapi-")` gives "Must start with nvapi-" (prefix only) |
| 9 | NemoClaw test fixtures: `nvapi-` + a repeated single letter, 24 and 32 long | 2026 | provider test fixtures | R5 example weight | synthetic and short; they exercise the redactors' own floors, not the issuance shape, so they contradict nothing above 60 |

Searched with no length result: langchain-ai/langchain-nvidia (only
`nvapi-...` and a word placeholder), NeMo-Agent-Toolkit, NVIDIA-AI-Blueprints
(regexes `nvapi-[A-Za-z0-9_-]+`), the ngcsdk wheel (no regex), and the
docs.nvidia.com NeMo Retriever page ("typically start with nvapi-").

## Resulting contract

- **Prefix** `nvapi-` (T1: docs and the ngcsdk constant).
- **Alphabet** `[A-Za-z0-9_-]` (T1 via R2: every NVIDIA rule uses exactly
  this class, except the one looser redaction superset, #6).
- **Length:** at least 60 after the prefix (T1 floor, #1: the tightest
  NVIDIA-authored bound; #2's 40 and all others are looser, and none
  contradicts it). The upper cap is project policy. trufflehog's 64 and
  betterleaks' 60–70 are tool-only and fall inside.
- **Boundaries:** no `[A-Za-z0-9_-]` byte before `nvapi-` or after the body.
- **Legacy prefixless key:** 84 non-space characters after `$oauthtoken:`
  (T1 via #3). Context-anchored only, and out of scope for this detector.

See the [handoff](../nvidia.md).

## Residual risk

- **False positives:** `nvapi-` + 60 or more URL-safe characters is not
  produced by NVAPI SDK or crate names (the reason short floors were
  rejected). Low.
- **False negatives:** a key class shorter than 60 (none known; trufflehog
  verifies 64); keys with other characters (only #6 hints at `.`).
- **Caveat:** #1's `{60,}` floor matches the lower end of betterleaks'
  `{60,70}` (added 2026-02-25). It is not a verbatim copy (different form,
  case-sensitive, no cap) and sits in an NVIDIA-authored PII scanner, so R2
  applies; the possible influence is recorded here. An issuance check
  (Personal, Service, build key; body length) would convert the floor into an
  exact width.
