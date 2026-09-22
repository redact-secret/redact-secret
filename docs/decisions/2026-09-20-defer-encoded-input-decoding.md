---
decision_id: decision-defer-encoded-input-decoding
status: accepted
scope: workspace
title: Defer encoded-input decoding out of scope, with reasoning
decided_at: 2026-09-20
spec: engine
---

# Defer encoded-input decoding out of scope, with reasoning

## Context

Issue [#491](https://github.com/redact-secret/redact-secret/issues/491)
revisited the "does not decode" line in
`decision-normalize-invisible-characters-before-detection` and
`ARCHITECTURE.md:164`, which excluded base64/percent/backslash decoding as
one unexplained clause alongside the (unrelated) invisibility work. The issue
measured a real, realistic gap: a credential inside a base64-encoded block —
`GOOGLE_CREDENTIALS_BASE64=<base64 of a JSON service-account key>`, the
standard way such a key reaches CI — is undetected today, while the same
JSON in plaintext is caught at high confidence. It also measured that
Gitleaks 8.30.1 decodes by default and that flare-redact 1.6.1, the direct
runtime-redaction competitor, does not.

Its "Proposed sequencing" asked that six sub-questions (which encodings, the
span model, a depth bound, the `Obfuscation` interface change, a
false-positive corpus, and incremental behavior) be settled in a decision
record *before* any detection code, and stated explicitly that "if the
outcome is that decoding stays out of scope, that is a legitimate result and
the existing ADR should be amended to say so explicitly with this evidence,
rather than leaving it as an unexplained v1 exclusion." This record is that
amendment. It authorizes no implementation; it replaces one unexplained
exclusion with a reasoned, revisitable one.

### TruffleHog's decode behavior, verified by observation

The issue could not observe TruffleHog 3.97.4's documented
`--max-decode-depth=5` default because it returned zero findings on every
fixture it built, including a plaintext PEM, and treated that as
inconclusive rather than as evidence of anything.

Re-run in this session with the same pinned binary (`trufflehog 3.97.4`,
confirmed by `trufflehog --version`) against a freshly generated, unissued
RSA-2048 PEM (`openssl genpkey`, never used anywhere else) in four shapes —
bare plaintext, plaintext assigned to an env var, bare base64, and base64
assigned to an env var — all four fixtures returned zero findings under the
issue's invocation. The cause is not the decode path: TruffleHog 3.x's CLI
defaults `--results` to a set that excludes plain `unverified` findings, so
`--no-verification` alone (which the issue used) silently suppresses every
unverified result, including on the plaintext control. Passing
`--results=verified,unknown,unverified,filtered_unverified` reproduces
findings on all four fixtures, with the `PrivateKey` detector's
`DecoderName` reported as `PLAIN` on the plaintext fixtures and `BASE64` on
both base64 fixtures. **TruffleHog does decode base64 by default**, as its
`--help` text claims; the issue's measurement methodology, not the claim,
was the source of the "could not observe" result. (An initial attempt with a
minimal Ed25519 PEM also produced zero findings on the plaintext control
under the corrected flag, most likely because the detector's body-length
heuristics assume an RSA-sized key; the RSA-2048 fixture above is the one
that isolates the decode behavior from that unrelated confound.)

Gitleaks's behavior was independently reproduced in the same session: on the
base64-assigned RSA fixture, `StartColumn`/`EndColumn` bound exactly the
encoded block in the *original* file (columns 27–2298, immediately after
`GOOGLE_CREDENTIALS_BASE64=` through the end of the base64 run), while
`Match`/`Secret` carry the *decoded* PEM text. This confirms the issue's
central claim: both measured competitors that decode keep the reported range
a contiguous span of the encoded input and put decoded plaintext only in a
field this product's own security boundary forbids populate.

## Decision

No encoding — base64, base64url, percent-encoding, backslash escapes, hex,
or UTF-16 — is added to detection scope in this decision. The exclusion at
`ARCHITECTURE.md:164` and
`decision-normalize-invisible-characters-before-detection`'s v1-exclusions
list stands, now for the reasons below instead of as an unexplained line.
This is a decision to defer, not to reject permanently: the six questions
below are the reopening bar for a future proposal, not a closed door.

### Why defer rather than adopt Option A or B

The issue correctly narrows the field to two viable span models (A: detect
and warn, redact nothing; B: redact the whole encoded block) and rejects a
third (C: decode/substitute/re-encode) as incompatible with one-pass span
redaction. Both surviving options have a cost specific to this product that
the issue's comparison table does not fully price in:

- **Option A defeats the product's purpose in exactly the case that
  motivates it.** This is a *redaction* tool; its value proposition is that
  a secret does not reach the sanitized output. An encoded finding that is
  detected but never rewritten still contains the live secret — reconstructible
  by one decode step, and no harder to reverse than the redaction this tool
  already prevents for plaintext. Shipping "detect, warn only" as the
  answer for the CI-env-var scenario the issue opens with would be
  detection theater for that scenario: the log line the issue worries about
  leaking still leaks, now with a diagnostic attached.
- **Option B has no measured false-positive cost.** Every other detector in
  this crate reached its current grammar through a measured corpus (the
  dozens of `freeze-*-grammar` records under `docs/decisions/`, each citing
  specific competitor rules and specific corpus counts). Decoding turns
  *any* base64-shaped run of sufficient length into new detection surface
  for every existing detector's grammar, not just the ones with base64
  prefixes today — a JSON blob, an image, a compressed payload, or a
  hash digest can all decode into bytes that a generic-token or
  entropy-based rule matches. The issue names this risk (open question 5)
  but has no corpus to bound it, and adopting B without one would be the
  first grammar change in this project's history made without measured
  evidence.
- **The security boundary makes the two costs asymmetric, not just
  additive.** `AGENTS.md` forbids exposing plaintext secret values in
  findings or diagnostics. Gitleaks, TruffleHog's raw JSON, and any tool
  that decodes gets an escape hatch this product does not have: it can put
  the decoded plaintext in a `Match`/`Secret` field so a human can audit
  *why* a block was flagged. This product cannot show that, which means an
  Option B false positive (a legitimate base64 config blob or binary asset
  redacted because a byte sequence inside it matched a detector after
  decoding) is harder for a caller to diagnose here than in a competitor
  that decoded the same way, with no corresponding way to soften the
  cost by improving message quality.
- **This product already has a place for "detected but not authoritative":
  the client/server boundary, not the finding's action.** `AGENTS.md`
  states client-side scanning is preventive UX and server-side scanning is
  the authoritative enforcement boundary. A documented gap in a preventive
  tool — as long as it is documented, which this record does — is a
  defensible position for this product in a way it would not be for the
  server-side scanner that actually gates a release or a merge.

None of this rules the feature out permanently. It says the two-way choice
between A and B is not obviously resolvable in this product's favor yet, and
Option B — the one that would actually satisfy the tool's purpose — needs
evidence this project does not currently have.

### Reopening criteria

A future decision reopening this scope must resolve all of the following
before any detection code lands, matching this project's convention that an
architectural reversal gets its ADR first:

1. **Which encodings, named individually with reasoning per encoding** — not
   a bundled "decoding" scope. Base64/base64url first if any, since it is
   the only one with a measured undetected finding in issue #491; the
   others (percent-encoding, backslash escapes, hex, UTF-16) each need
   their own realistic undetected-case evidence, not inclusion by analogy.
2. **The span model resolved as A or B for each encoding**, with the
   asymmetry above priced in explicitly — in particular, whether Option A's
   "detected but not redacted" result is an acceptable product behavior, or
   whether B is required and gated on a false-positive corpus first.
3. **A depth bound**, counted against `DEFAULT_MAX_INPUT_BYTES` and
   `DEFAULT_MAX_FINDINGS`
   (`decision-bound-whole-input-operations-by-default`) so decoded bytes are
   not new unbounded input relative to those existing limits.
4. **A dedup rule** for a match that is both a direct textual hit and
   reachable by decoding (the issue's observed Gitleaks double-count of a
   plaintext PEM that is itself base64-shaped).
5. **The `Obfuscation` interface change specified across all five surfaces**
   (Rust, Node addon, WASM, Python, TypeScript) and the conformance schema,
   following the pattern `decision-normalize-invisible-characters-before-detection`
   used for its own `Obfuscation::InvisibleCharacters` variant — `Obfuscation`
   is already `#[non_exhaustive]` for exactly this kind of addition.
6. **A committed false-positive corpus** of base64-shaped (and, per
   encoding, shaped-for-that-encoding) runs that decode to noise, gated
   ahead of any detection change, sized comparably to this project's
   existing `freeze-*-grammar` precision work.
7. **Incremental behavior specified**, including the case where decoding is
   deliberately skipped — an encoded block split across a chunk boundary
   cannot be decoded from a prefix, and whether the retention-hint model can
   hold such a block open, or whether incremental mode simply never
   decodes, is itself a mode-dependent-divergence decision that needs its
   own reasoning.

Standing constraint, unaffected by whether this scope reopens: no finding or
diagnostic may expose a decoded plaintext value, matching the existing rule
for matched text in general.

## Consequences

`ARCHITECTURE.md:164` is updated in this same change to cite this record by
name instead of stating the decode/unescape exclusion as a bare, unreasoned
clause. `decision-normalize-invisible-characters-before-detection`'s v1
exclusions list gains a pointer to this record for the same reason. No code,
detector, fixture, or public interface changes as a result of this decision;
it is a record of *why not yet*, not an implementation. The next step, if
any, is a new issue proposing an encoding-scoped reopening that satisfies
every criterion above — most usefully starting from base64/base64url alone,
since that is the only encoding with measured, realistic undetected-finding
evidence behind it.
