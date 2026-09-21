# Issue #566 — `docker-token`/`cloudflare-token` shape-1 provider-evidence review

[Audit archive](../../README.md) ·
[Docker exact-length freeze (#370)](../../../decisions/2026-09-17-freeze-docker-pat-oat-exact-length-grammar.md) ·
[Precision-contract freeze (#367)](../../../decisions/2026-09-17-freeze-precision-contracts-for-seven-provider-families.md) ·
[Cloudflare account-token prefix (#481)](../../../decisions/2026-09-20-adopt-cloudflare-account-token-prefix.md) ·
[Issue #566](https://github.com/redact-secret/redact-secret/issues/566) ·
[Epic #548](https://github.com/redact-secret/redact-secret/issues/548) ·
[Split from #552](https://github.com/redact-secret/redact-secret/issues/552) ·
[Prior evidence: #367](../367/README.md) · [Prior evidence: #407](../407/README.md) ·
[Prior evidence: #408](../408/README.md) · [Prior evidence: #552](../552/README.md)

Written 2026-09-21 against `main` at `8122a96c2200555f317006aeda05abf40063e2e6`,
on branch `workbench/566-docker-cloudflare-shape-1`.

## Summary

Issue #566 asks, before any fix, for provider evidence on two questions the
frozen `docker-token` and `cloudflare-token` contracts leave open:

1. Does Docker issue a 32-byte `dckr_pat_` personal access token (the
   `detector-coverage--docker-token-shape-1-*` fixtures' shape), against the
   frozen contract's 27-byte body (#370)?
2. Does Cloudflare issue a `cfut_` token whose 40-character body carries no
   checksum tail (the `detector-coverage--cloudflare-token-shape-1-*`
   fixtures' shape), against the frozen contract's 40-byte body plus an
   8-character checksum (#367/#373)?

**Neither is provider-documented. No new evidence surfaced for either
question, and none supports widening either frozen grammar.** Docker's own
docs publish no PAT/OAT length at all, at any width; Cloudflare's own
token-formats page states a checksum follows every prefixed token's body,
which directly contradicts a checksum-less form being an issued shape. Both
misses are the same benchmarks-side fixture-generator artifact #552, #407,
and #408 already identified: `redact-secret-benchmarks`' `detector-coverage.mjs`
builds `shape-1` for both families from one flat random-alphabet body length
per family, not from either provider's documented format. No detector or
contract change is warranted in this repository; the fixtures need
correcting on the benchmarks side.

| shape | fixture body | frozen contract | provider evidence for the fixture's shape |
| --- | --- | --- | --- |
| `docker-token` shape 1 (`dckr_pat_`) | 32 random alnum bytes | exactly 27 bytes (#370, T2: single-tool) | none — Docker publishes no PAT length |
| `cloudflare-token` shape 1 (`cfut_`) | 40 random alnum bytes, no checksum | 40-byte body + 8-hex checksum (#367, T1: body provider-documented, checksum existence provider-documented) | none — Cloudflare's own page says a checksum follows the body |

## Method

Both shape-1 fixture bodies were reproduced independently, not taken on
citation, using `redact-secret-benchmarks`' own seeded `synthetic()` generator
formula (the identical script #552's evidence document used):

```
$ python3 - <<'EOF'
import hashlib
DEFAULT = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
def synthetic(label, length, chars=DEFAULT):
    value, block = "", 0
    while len(value) < length:
        h = hashlib.sha256(f"secret-benchmark:never-issued:v2:{label}:{block}".encode()).digest()
        for b in h: value += chars[b % len(chars)]
        block += 1
    return value[:length]
docker_body = synthetic("detector-coverage:docker-token:dckr_pat_", 32)
cf_body = synthetic("detector-coverage:cloudflare-token:cfut_", 40)
print("dckr_pat_" + docker_body, len(docker_body))
print("cfut_" + cf_body, len(cf_body))
EOF
dckr_pat_ZByg3TZMUmABS7UvAuqZ7UGqTnUvdlUs 32
cfut_1OkcOTD0mHeGybnydBui9ySqykPTRevebwtIYj1P 40
```

Both reproduced values match issue #566's own reported shapes byte for byte.

Provider documentation was re-fetched live on 2026-09-21 (`WebFetch`, not
recalled from the #367/#407/#408/#481 citations) for every page those prior
reviews cite for these two families, plus two pages not previously consulted
(GitHub's supported-secret-scanning-patterns page and the Docker blog's
access-token tag), specifically to check whether either had been updated
since their last observation (2026-09-17 for Docker, 2026-09-17/2026-09-20
for Cloudflare) to publish the missing width.

## Docker: is a 32-byte `dckr_pat_` body issued?

| source | fetched | finding |
| --- | --- | --- |
| `docs.docker.com/security/access-tokens/` | 2026-09-21 | Documents that personal access tokens exist and replace passwords for CLI login. No `dckr_pat_` prefix, length, alphabet, or example value is published. Unchanged from the `docker-docs-pat` citation in `docs/audits/evidence/367/precision-contracts.json` (observed 2026-09-17). |
| `docs.docker.com/security/for-admins/access-tokens/` | 2026-09-21 | Documents organization access token scopes, per-plan creation limits, and password-manager handling. No `dckr_oat_` prefix, length, alphabet, or example value is published. Unchanged from the `docker-docs-oat` citation (observed 2026-09-17). |
| `docs.github.com/.../supported-secret-scanning-patterns` | 2026-09-21 | Lists "Docker Personal Access Token" and "Docker Organization Access Token" as partner types (existence only — the same fact `github-secret-scanning-patterns` already records). No regex, prefix, or length is published for either row. |
| `docker.com/blog/tag/access-tokens/` | 2026-09-21 | No blog post announcing a `dckr_pat_`/`dckr_oat_` scannable format, width, or example was found among the indexed posts. |

**Finding: no provider or provider-adjacent source documents any Docker
Hub access-token body length, at 27, 32, or any other width.** The
27-byte PAT / 32-byte OAT contract #370 froze remains sourced from
`trufflehog-3.97.4` alone (T2, "single-tool; adopted as support-policy"),
unchanged by this review. Since no source states a 32-byte `dckr_pat_` body
either, the fixture's shape (`dckr_pat_` + 32 bytes) is not an
evidence-backed candidate for widening — it is simply a different guess
than the one the contract already adopted, with the same (zero) provider
support. Recorded in
`docs/audits/evidence/367/precision-contracts.json`'s `docker-token`
`conflicts` entry.

## Cloudflare: is a checksum-less 40-character `cfut_` body issued?

| source | fetched | finding |
| --- | --- | --- |
| `developers.cloudflare.com/fundamentals/api/get-started/token-formats/` | 2026-09-21 | Still shows "last updated April 20, 2026" (unchanged from the `cloudflare-token-formats` citation, observed 2026-09-17/2026-09-20). States: *"Each credential type has a distinct prefix followed by 40 characters and a checksum."* Formats table: `cfk_[40 characters][checksum]`, `cfut_[40 characters][checksum]`, `cfat_[40 characters][checksum]`. Checksum width, alphabet, and algorithm remain unpublished. |
| `docs.github.com/.../supported-secret-scanning-patterns` | 2026-09-21 | Lists "Cloudflare User API Token", "Cloudflare Account API Token", and "Cloudflare Global User API Key" as partner types (existence only). No regex, width, or checksum detail is published for any row. |

**Finding: the provider's own page states a checksum follows the 40-character
body for every prefix, with no exception for `cfut_`.** A `cfut_` value whose
body is 40 bytes with nothing following it is therefore not a form the
provider describes as issuable — it is a truncation relative to the
provider's own stated structure, not an alternate valid shape. This is the
same conclusion `docs/audits/evidence/367/README.md` and
`docs/audits/evidence/408/README.md` already reached from the same page; this
review adds only that the page is unchanged nine months (2026-04-20 revision)
and four days (last observed 2026-09-17/09-20) later, with the checksum's
width and alphabet still unpublished by the provider. The 8-byte
lowercase-hex checksum shape the frozen contract enforces remains sourced
from `trufflehog-3.97.4` alone (T1 for the prefix and body length, which the
provider documents directly; the checksum's *existence* is T1, its width and
alphabet stay single-tool per the family's `excluded.non-hex-checksum`
entry). Recorded in `docs/audits/evidence/367/precision-contracts.json`'s
`cloudflare-token` `conflicts` entry.

## Why this is the same root cause #552, #407, and #408 already found

`redact-secret-benchmarks`' `fixtures/generated/detector-coverage.mjs` builds
every family's `shape-1`/`shape-2`/`shape-3` fixtures from one shared
"prefix + `synthetic(seed, length)`" formula, authored against beta.3's
permissive rules and never updated for the later per-prefix, evidence-tiered
freezes. `docs/audits/evidence/552/README.md`'s reproduction table already
names both of these exact rows:

> `docker-token` — `dckr_pat_` + 32 random alnum bytes — frozen contract
> `dckr_pat_` + exactly 27 bytes — wrong length for `dckr_pat_`
>
> `cloudflare-token` — `cfut_` + 40 random alnum bytes — frozen contract
> `cfut_` + 40-byte body + exactly 8-byte lowercase-hex checksum — missing
> checksum tail entirely

This document does not dispute that finding; it answers the one question
#552, #407, and #408 left open by design — whether the fixture's shape
might, on further provider evidence, turn out to be the *correct* one and the
frozen contract the thing that should widen. It does not: no source, old or
newly checked, documents either fixture's shape as an issued form. Both
misses stay dispositioned as fixture-generator artifacts, not coverage gaps,
under the same four-scanner-miss signal the issue itself observes (redact-secret,
gitleaks, trufflehog, and flare-redact all miss the same malformed shape for
the same reason: none of them accept a form no consulted source documents).

No code in `crates/secret-scan-core/src/detectors/additional_providers.rs`
(`DOCKER`) or `crates/secret-scan-core/src/detectors/cloudflare.rs`
(`CLOUDFLARE`) is changed by this review. Confirmed against this branch:

```
cargo test -p redact-secret detectors::
# 727 passed, 341 filtered out (20 suites)
```

## What this document does not claim

- It does not assert that Docker or Cloudflare will never issue a token of
  these shapes — only that no source available to this review, checked live
  on 2026-09-21, documents either shape today. Should either provider publish
  a grammar that includes it, the contract is re-reviewable, the same accepted
  cost both `decision-freeze-docker-pat-oat-exact-length-grammar` and
  `decision-adopt-cloudflare-account-token-prefix` already record.
- It does not perform the benchmarks-side fixture-generator correction:
  `detector-coverage.mjs`'s per-family flat-length formula needs a per-prefix
  width (27/32 for `docker-token`, 48-with-checksum for `cloudflare-token`)
  to stop generating out-of-contract `shape-1` bodies. That change belongs in
  `redact-secret-benchmarks`, a separate repository, and is recommended
  follow-up there rather than performed here, consistent with #407's and
  #408's own recommendation and this repository's `AGENTS.md` boundary.
- It does not reopen the `cfk_` (Cloudflare Global API Key) disposition —
  issue #486 already closed that as won't-fix on unrelated grounds (no tool
  corroborates any checksum shape for it at all); this review did not
  re-examine `cfk_`.
- It does not claim the fixed-corpus assessment (`assessment/fixtures/accuracy-corpus.json`)
  is affected: its one Docker fixture (`logs-additional-provider-tokens-one`,
  27-byte body) and its one Cloudflare fixture (`fixture-3`, 40-byte body +
  8-hex checksum) are already exactly in-contract, verified by direct
  inspection this review performed.

## Acceptance criteria disposition

- **Docker: a recorded finding on whether `dckr_pat_` + 32 is issued, with
  its source** — done. No source documents it; see "Docker" above and the
  updated `conflicts` entry in
  `docs/audits/evidence/367/precision-contracts.json`.
- **Cloudflare: a recorded finding on whether a checksum-less `cfut_` + 40 is
  issued, with its source** — done. The provider's own page states a
  checksum always follows the body; see "Cloudflare" above and the updated
  `conflicts` entry in the same file.
- **Each of the 6 misses resolves into either a detected positive under a
  widened, evidence-backed contract, or a corrected fixture — no silent
  misses remain** — resolved as a corrected fixture. Neither grammar widens;
  the disposition (fixture-generator artifact, not a coverage gap) is
  recorded here and in the precision-contracts conflicts entries. The
  benchmarks-side fixture correction itself is out of this repository's
  boundary and is recommended follow-up in `redact-secret-benchmarks`.
- **No frozen grammar is widened without a provider citation** — satisfied;
  neither `DOCKER` nor `CLOUDFLARE` is changed, and both `conflicts` entries
  now record the 2026-09-21 re-check that found no citation to widen on.
- **`docker-token` shape 2 and every other in-contract positive stay EXACT**
  — satisfied; no detector code changed. `cargo test -p redact-secret
  detectors::` (727 passed) confirms no behavior change anywhere in the
  workspace's detector suite.
- **Fixed corpus stays at 0 false positives** — satisfied; no detector code
  changed, and the fixed corpus's own Docker and Cloudflare fixtures are
  already in-contract (see "What this document does not claim").

## Authority

This document records evidence. It does not change detector behavior, select
a version, create a tag, publish a package, or authorize any release
operation. A release still requires the explicit approval `AGENTS.md`
mandates.
