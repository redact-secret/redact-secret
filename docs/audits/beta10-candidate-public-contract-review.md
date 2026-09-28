# Beta.10 candidate public-contract review

[Documentation home](../README.md) · [Audit archive](README.md)

- Issue: [#898](https://github.com/redact-secret/redact-secret/issues/898).
- Reviewed on: 2026-09-27.
- Previous published source: `v0.1.0-beta.9`,
  `f726f2ffb0fd854cc3eeb4c35798695fde3161d3`.
- Reviewed implementation baseline:
  `2e1bdcf0905f7a374c4c54b7caac41303cd7d88b`.
- Status: public API and compatibility review is complete for the baseline.
  Exact-SHA qualification, SAST, benchmark qualification, performance
  evaluation, and blind evaluation are **not** complete: they depend on
  [#579](https://github.com/redact-secret/redact-secret/issues/579)'s
  remaining runtime/profile/artifact-size and cross-domain qualification
  evidence and on
  [redact-secret-benchmarks#287](https://github.com/redact-secret/redact-secret-benchmarks/issues/287)
  (open) and
  [redact-secret-benchmarks#286](https://github.com/redact-secret/redact-secret-benchmarks/issues/286)
  (closed with no A/A, candidate, or size evidence recorded in its comment
  thread or its own closing PR). Explicit release approval remains pending
  and is gated on that evidence, not only on this document.

This review replaces the beta.9 document as the current review input to the
artifact inventory. An inventory binds this document's digest and its own
`sourceCommit` together. The immutable #898 review comments record the merged
source revision, the fresh evidence, and the remaining release authority.
Hashing this document alone is not a current API review.

## Public API and compatibility

Unlike beta.8-to-beta.9, this diff is not "no change": it adds the PII
activation surface (`#874`, `#875`-`#880`) additively across every binding,
and narrows one enforcement boundary (`#887`). No existing exported function,
type, error code, package export subpath, range unit, callback contract,
runtime requirement, or CLI argument was removed or had its meaning changed
for an existing caller; every addition is opt-in and off by default.

| Surface | Review result |
| --- | --- |
| Rust | Adds `pub use pii::PiiSelection`; `DetectorRegistry::with_built_in_and_pii`, `with_common_built_in_and_pii`, `with_built_in_and_pii_custom`, `with_common_built_in_and_pii_custom`, and `activation_identity()`. `SecretScanErrorCode` grows from 18 to 22 variants (`PiiSelectorInvalid`, `PiiSelectorUnsupported`, `PiiSelectorUnavailable`, `PiiActivationConflict`). Every existing `pub` item, the `core-public-api` manifest list, and external `public_api` tests remain aligned. |
| JavaScript | Adds an optional `InitializeOptions.pii` field to `initialize()` (existing zero-argument callers unaffected) and an exported `piiActivation()`. `SecretScanErrorCode` gains the same four `PII_*` codes. `initialize()`'s idempotency note is refined: equivalent PII selections still share one load; a different or conflicting concurrent selection now rejects with `PII_ACTIVATION_CONFLICT` instead of silently sharing the first caller's selection. The root, `common`, Node-stream, Web-stream, and `package.json` exports otherwise carry no removed or renamed symbol. Exact runtime dependency pins move together to beta.10. |
| Python | Adds `initialize(pii: Sequence[str] = ())` (existing no-argument callers unaffected), `pii_activation()`, and four new exception classes (`PiiSelectorInvalidError`, `PiiSelectorUnsupportedError`, `PiiSelectorUnavailableError`, `PiiActivationConflictError`), all subclasses of the existing `SecretScanError`. The import module, stub, callback shapes, range units, and incremental API are otherwise unchanged. The distribution version remains derived from Cargo (`0.1.0b10`). |
| CLI | Adds a repeatable `--pii <selector>` argument and a `--print-pii-activation` diagnostic mode, both opt-in; omitting `--pii` reproduces beta.9 behavior exactly. Existing commands, reports, exit codes, limits, and safe diagnostic contract are unchanged. |

Detection behavior also changes independently of the new PII surface. Six new
opt-in structured PII families (email, payment card, IPv4/IPv6, IBAN, US SSN,
constrained-context phone) are added but produce no finding unless a caller
opts in via `pii`/`--pii`; the shipped credential detector set additionally
gains new provider coverage (`elevenlabs-api-key`, `together-ai-api-key`,
`tavily-api-key`, `aws-bedrock-long-term-api-key`,
`aws-bedrock-short-term-api-key`, keyword-gated `mistral-api-key`,
`cohere-api-key`, `ai21-api-key`, `deepgram-api-key`) and reclassifies
`anthropic-token`/`openai-token` findings into privilege-specific `type`
strings (`anthropic_admin_api_key`, `anthropic_enterprise_api_key`,
`openai_admin_api_key`) alongside the narrowed `anthropic_api_key`/
`openai_api_key`. No finding `type` is a closed enum in any binding's public
type contract, so this is a value-level change, not a type-level one; a
consumer that asserts an exact finding set or an exact `type` string for
these prefixes can observe the change. See the dated `CHANGELOG.md` entries
for the complete list.

`redact()`'s `InvalidPlaceholder` enforcement is also stricter, not merely
additive (#887): a placeholder is now rejected if it reproduces *any*
finding's matched text, including a sibling `warn`/`allow` finding's, not
only a `redact`/`block` finding's. A caller with a custom formatter that
happened to rely on the old, narrower check could see a previously-accepted
placeholder now rejected with `InvalidPlaceholder`. This is a closed security
gap (a formatter could otherwise leak a non-redacted finding's matched value
through a redacted finding's placeholder), documented as a `SECURITY.md`
wording update in the same commit.

## Runtime, package, and security boundary

All version-bearing Cargo and npm manifests and lockfiles agree on
`0.1.0-beta.10` (`npm run rust:check`: 0 errors); the facade pins the
WebAssembly package and all ten native/facade npm packages at that exact
version. `docs/quickstart.md` and `docs/getting-started.md`'s pinned
install/expected-output versions (npm and PEP 440 spellings) move together.
The core still has an empty dependency allowlist and no runtime network,
filesystem, environment, telemetry, secret storage, or UI behavior. Detection
remains separate from policy enforcement; the new PII selection is orthogonal
to the existing `full`/`common` credential profiles and off by default;
findings and diagnostics remain input-free.

The reviewed artifact set is the same product surface as beta.9: the npm
facade, WebAssembly package, ten native/facade npm packages (including both
musl Linux addons), Rust core and CLI crates, six CLI binaries, eight abi3
wheels plus the Python sdist. Browser and Node compatibility remain covered
by the declared Chromium, Firefox, WebKit, and Node 20/22/24 lanes. Local
verification for this review: `cargo check --workspace --locked`,
`cargo test -p redact-secret --locked` (9 unit + 12 doc-tests, all passing),
`npm run js:typecheck`, and `npm run js:test` (174 tests across 17 files, all
passing) all pass at this baseline after the version bump.

## Baseline evidence and invalidation

Unlike beta.9's reviewed baseline, this baseline has **not** yet passed
exact-SHA artifact qualification or SAST as a CI run against this exact
commit, and the beta.10 PII cost/cross-domain qualification chain
(redact-secret-benchmarks#286, #287, tracked from redact-secret#579) has
produced no A/A, candidate, or distribution-size evidence. No blind
evaluation run exists for this baseline. This document records only the
public API and compatibility review; it must not be cited as evidence that
qualification, SAST, benchmark qualification, performance evaluation, or
blind evaluation are complete.

Any source change after the reviewed baseline invalidates even this
compatibility review. Such a change requires a fresh review before release
approval; this review must not be cited for a later source revision.

No review document, successful workflow, issue closure, or manifest version
authorizes a tag, release, publication, or deployment. Explicit release
approval remains a separate step after the fresh qualification, benchmark,
and blind evidence above is produced and reviewed, and after a final
changelog review pass for the source being released.
