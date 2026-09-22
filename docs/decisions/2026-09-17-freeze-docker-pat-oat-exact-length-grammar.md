---
decision_id: decision-freeze-docker-pat-oat-exact-length-grammar
status: accepted
scope: workspace
title: Freeze the Docker Hub access token grammar as two separately-sized exact-length prefixed shapes
decided_at: 2026-09-17
spec: detector-families
---

# Freeze the Docker Hub access token grammar as two separately-sized exact-length prefixed shapes

## Decision

Narrow the existing `docker-token` detector
(`crates/secret-scan-core/src/detectors/additional_providers.rs`, `DOCKER`)
for issue #370 from one shared 20-byte minimum under either prefix to two
independently validated exact-length shapes, both bounded on each side by a
byte outside `[A-Za-z0-9_-]` or the edge of input:

```
dckr_pat_<27 bytes from [A-Za-z0-9_-]>   (personal access token, 36 bytes total)
dckr_oat_<32 bytes from [A-Za-z0-9_-]>   (organization access token, 41 bytes total)
```

Each segment name carries its own length. A 26- or 28-byte suffix after
`dckr_pat_`, a 31- or 33-byte suffix after `dckr_oat_`, the personal-token
length under the organization prefix, and the organization-token length
under the personal prefix are all intentional false negatives, not fuzzy
matches, following the exact-length precedent `npm-token`, `google-api-key`,
`notion-token`, and `new-relic-user-api-key` already set in this registry.
Detector id, finding type (`docker_token`), confidence (`High`), specificity
(`Provider`), the default policy class (`always-redact`), and every public
interface are unchanged; there is no strict mode, option, or new detector.

Known unsupported forms, all deliberately out of scope:

- Any `dckr_pat_`/`dckr_oat_` value whose suffix is not exactly the
  documented length for its own segment name.
- An undocumented segment name (`dckr_tok_`, ...), as before.
- Legacy Docker Hub passwords and any unprefixed registry password: they
  carry no distinguishing prefix and are outside this provider rule; a
  value under a generic assignment key can still surface through
  `generic-token`'s contextual path, independently of this detector.
- A leading `-` immediately before the prefix. The reference pattern's `\b`
  would accept it; this registry's shared boundary alphabet treats it as a
  slice of a wider dashed identifier, the same stricter choice every other
  prefixed provider detector here already makes.

## Rationale

The published `@redact-secret/core@0.1.0-beta.4` package flags four
must-not-flag fixtures in the beta.4 common-formats benchmark
(`docker-token-pat-plain-twin`, `docker-token-pat-unicode-crlf-twin`,
`docker-token-oat-plain-twin`, `docker-token-oat-unicode-crlf-twin`): a
26-byte personal-token suffix and a 31-byte organization-token suffix, each
exactly one structural property away from its paired positive. Reproduced
against the published package before modification with the issue's
self-contained inputs: all four twins flagged, all four paired positives
matched at the recorded UTF-8 byte ranges. The old `RunLength::AtLeast(20)`
shared by both prefixes cannot express the distinguishing property at all.

Docker's own documentation describes personal and organization access
tokens and their `dckr_pat_`/`dckr_oat_` prefixes but does not publish a
suffix grammar. The reviewed contract evidence the issue pins is
trufflehog's `dockerhub` v2 detector at tag `v3.97.4`
(`pkg/detectors/dockerhub/v2/dockerhub.go`), whose access-token pattern is

```
\b(dckr_pat_[a-zA-Z0-9_-]{27}|dckr_oat_[a-zA-Z0-9_-]{32})(?:[^a-zA-Z0-9_-]|\z)
```

i.e. two exact lengths under one shared alphabet and one shared trailing
boundary. That single external source establishes the lengths and alphabet a
widely deployed scanner has converged on from real-world samples; it does
not prove issuance or liveness, and no live credential was verified. Because
the alphabet and boundary are identical for both segments, the audit called
for by the issue finds only the length differs between them, and the
detector encodes exactly that: `PrefixShape::exact("dckr_pat_", 27)` and
`PrefixShape::exact("dckr_oat_", 32)`.

To express per-prefix lengths, `pattern.rs` gains `PrefixShape` and
`scan_prefixed_shapes`; `scan_prefixed_runs` (used by every other
prefix-run detector) becomes a thin wrapper that repeats one length per
prefix, so no other detector's behavior changes. Every
`KnownFormatProviderDetector` constant now spells its prefixes as shapes,
which is the same shape the sibling precision fixes for
`OpenAI`/`DigitalOcean`/Linear (#368, #369, #374) will need.

Issue #367 (the contract-freeze prerequisite) is still open. This record
freezes only the Docker contract, from the evidence the issue itself pins,
and is the child #367 lists for Docker; it does not decide any other
provider family.

## Consequences

- **Corrected classifications, inputs untouched.** Seven existing
  `synchronous-corpus.json` fixtures and two `incremental-corpus.json`
  fixtures were authored to the retired 20-byte minimum with suffixes of 20,
  25, 36, or 11250 bytes. Their `input` bytes are unchanged; their
  expectations are corrected and each `note` names this record:
  `docker-positive-qualified`, `docker-positive-min-length`,
  `docker-positive-all-prefixes`, `docker-positive-doc-style-placeholder`
  (now `boundary`/`intentionally-unsupported`/`malformed`, no finding),
  `docker-boundary-below-min` (note only), `docker-adversarial-long-suffix`
  (`maxFindings` 1 to 0, no finding, still bounded), and
  `docker-overlap-context` (the 36-byte value under `access_token=` is now
  owned by `generic-token` as a `contextual_secret` and still redacted).
  In the incremental corpus, `additional-provider-families` and
  `docker-embedded-identifier-discriminating-boundary` keep their 36-byte
  Docker line as plain text at every partition. This is a classification
  correction, not a detector improvement, and is not scored as one.
- **Paired positives preserved and extended.** Every previously supported
  27-byte fixture (`docker-positive-dotenv`, `-json`, `-yaml`, `-log`,
  `-punctuation-adjacent`, `-crlf-unicode-prefix`, `-repeated-value`) is
  unchanged. Twenty-five new synchronous fixtures cover both exact shapes
  bare, quoted, in JSON, dotenv, YAML, log, and Markdown inline code, after
  Unicode/CRLF, repeated, adjacent to their twins, and under contextual
  assignment keys (overlap ownership), plus the one-byte-short, one-byte-long,
  cross-prefix-length, invalid-alphabet, and whitespace-insertion mutations.
  The `docker-token-exact-length` mutation family is reproduced byte-for-byte
  by `conformance/fixtures/docker-token-mutations.ts` and checked in
  `conformance/schema.test.ts`, the same pairing `github-classic` uses. One
  new incremental fixture (`docker-pat-oat-exact-length-partitions`)
  exercises every chunk split across both shapes and their twins.
- **Fixed-corpus assessment left as is.** The release-qualification
  accuracy corpus `assessment/fixtures/accuracy-corpus.json` (version 3,
  pinned by hash in `assessment/acceptance-criteria*.json`) contains one
  Docker value with a 26-byte suffix
  (`logs-additional-provider-tokens-one`). Its input, expectation, and hash
  are deliberately not rewritten here. Under the corrected rule the Rust
  adapter's fixed-corpus accuracy moves from 21 true positives / 5 false
  negatives to 20 / 6 on that one fixture; re-versioning that corpus and
  its pinned criteria is the beta.5 precision gate's decision (#376), so
  fixed-corpus and expanded-corpus results stay separate.
- `docs/coverage/detector-inventory.json`'s `docker_token` reconciliation
  trigger is now a 27-byte-suffix value; `inventory-report.json`,
  `coverage-declarations.json`, `coverage-report.md`, and
  `fp-fn-summary.json` are regenerated, and `fp-fn-summary-370.json`
  records this issue's Docker-only view.
- A value that is a real Docker Hub token of a length other than 27 or 32
  bytes, should Docker ever issue one, would go undetected by this detector
  until the contract is re-reviewed; that is the accepted cost of rejecting
  the near-miss twins, and it is bounded by the fact that the same lengths
  are what the reference scanner enforces.
