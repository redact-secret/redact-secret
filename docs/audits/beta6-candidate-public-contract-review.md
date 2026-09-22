# Beta.6 candidate public-contract review

Reviewed on 2026-09-22 for release tracking issue
[#606](https://github.com/redact-secret/redact-secret/issues/606). The candidate
is `0.1.0-beta.6` (`0.1.0b6` on PyPI) on `rc/0.1.0-beta.6`, based on reviewed
`main` revision `8838b91e99d822420a644c0e487bdd3a217c904d` (PR #581), after the beta.6
release gate #572 closed. The exact
frozen candidate revision is recorded by the qualification inventory and
release manifest so that this document does not claim evidence for a later
source change.

## Public API and compatibility

Beta.6 has a public API diff from beta.5. The changes are recorded under the
dated `0.1.0-beta.6` changelog heading. In summary:

Breaking or compatibility-affecting:

- `github-token` reports one finding type per token family. `ghp_` keeps
  `github_token`; `gho_`, `ghu_`, `ghs_`, `ghr_`, and `github_pat_` move to
  five new types (#517). The detector id, spans, and action are unchanged.
  Beta.5 changed no existing detector's finding type; this one does, so
  callers that filter on `github_token` must add the new names.
- `SecretScanErrorCode` gains `InvalidRuleset` on an enum that is not
  `#[non_exhaustive]`, so an exhaustive Rust `match` needs a new arm; the
  TypeScript error-code union gains `INVALID_RULESET`.

Additive: declarative rulesets (`load_ruleset`, `RulesetError`,
`RulesetErrorClass` in Rust; `--ruleset` on the CLI; a `ruleset` argument on
the Node addon and `@redact-secret/wasm`; a `ruleset` option on
`@redact-secret/core`; a `ruleset` keyword and `InvalidRulesetError` in
Python). Four detector ids, all in the provider pack: `pulumi-access-token`,
`supabase-management-token`, `firebase-server-key`, and
`terraform-cloud-token`. Ten finding types: the five GitHub types above,
`pulumi_access_token`, `supabase_personal_access_token`,
`firebase_server_key`, `terraform_cloud_token`, and
`vendor_prefixed_credential`; every one is always-redact.

No detector id or finding type was removed. Range units, callback contracts,
initialization, incremental session behavior, placeholder formatting,
default whole-input limits, and the remaining error codes are unchanged.

## Default policy and detection

Additions: the four detectors above; `sk_org_` and `whsec_` on
`stripe-token`; `glsoat-` and `glffct-` on `gitlab-token`; a bare,
marker-less 48-byte `sk-`-family value on `generic-token` as
`vendor_prefixed_credential` (#552); and two `generic-token` Markdown
inline-code fixes (#552, #548).

Narrowings, each with its intentional false negatives in the cited decision
record:

- `slack-token`'s `xoxp-` and `xoxe`-rooted prefixes require Slack's
  documented section structure (#512). A value beta.5 caught on the old
  20-byte floor without those sections is no longer a `slack-token`
  finding.
- A glued `-`/`_` suffix at exactly the 21st body byte of `xapp-`, `xwfp-`,
  the `xoxe` rotation bodies, and `lin_oauth_` now rejects the value
  instead of absorbing the suffix (#551, #570). #570 caught and replaced an
  unreleased exact-length interim fix that had stopped every real-length
  token on those prefixes from matching; beta.6 does not ship that state.
- An `AIza` value inside a Firebase Web SDK client-config object (two or
  more config keys within 512 bytes) is exempt at the pipeline level
  (#520), so an unrestricted Google key pasted into such an object is now
  missed.

## Support matrix

`benchmarks/support-matrix.json`, `docs/support-matrix.md`, and the README
status line were re-measured and re-pinned from clean product and
benchmarks mains under #573 (PR #580). Artifact qualification's
`support-matrix-drift` job compares that pin with beta.5's and fails on an
unacknowledged regression out of `stable` (#511). This review cites no
figure from that matrix; the pinned file is the only source.

## Artifact set

Beta.6 publishes the same thirteen artifacts as beta.5: ten npm package
identities (the facade, `@redact-secret/wasm` including its `common`
subpath files, and eight `@redact-secret/node-<platform>` packages including
both musl lanes), two crates, and the Python distribution's eight wheels plus
sdist. The CLI still ships no musl binary and no GitHub Release.

## Changelog and blocker disposition

Candidate review on 2026-09-22 found the same class of gap beta.5's second
readiness pass found: nine merged PRs that changed detector behavior since
`v0.1.0-beta.5` had no changelog entry (#532, #533, #535, #537, #539, #543,
#547, #564, #571), the #551 entry described an exact-length state #571 had
already replaced, and the GitHub finding-type split was not recorded as a
compatibility change. All three were fixed on `rc/0.1.0-beta.6` before the
candidate was frozen, together with one wrong decision slug and the missing
#511 credit. They are recorded on #606.

Publication still depends on exact-revision Artifact qualification, Package
Release Rehearsal, and SAST at the frozen candidate SHA, and on explicit
release approval after that evidence is reviewed. Those runs, the artifact
inventory, registry observations, installed-consumer evidence, tag target,
and final manifest belong to the versioned durable release record.
