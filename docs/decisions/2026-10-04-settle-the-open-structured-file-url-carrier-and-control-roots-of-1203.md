---
decision_id: decision-settle-the-open-structured-file-url-carrier-and-control-roots-of-1203
status: accepted
scope: workspace
title: Settle the structured-file, URL-carrier and control root causes that #1203 collected
decided_at: 2026-10-04
spec: engine
---

# Settle the structured-file, URL-carrier and control root causes that #1203 collected

## Context

[#1203](https://github.com/redact-secret/redact-secret/issues/1203) collects
the credential-evidence `snapshot-2026.10.04.3` failures that
[#1199](https://github.com/redact-secret/redact-secret/issues/1199),
[#1200](https://github.com/redact-secret/redact-secret/issues/1200) and
[#1201](https://github.com/redact-secret/redact-secret/issues/1201) do not
classify. The benchmark triage of redact-secret-benchmarks#698 (PR #702)
leaves 82 root causes open. Replayed with the product API and CLI on each case
input, they are **24 base cases**: every `context.indent`,
`context.unicode-prefix` and `encoding.crlf` variant and every metamorphic,
mutation and differential assertion of one base case produced the same
findings, so a variant count is not a defect count.

Published `@redact-secret/core@0.1.0-beta.13` and `main` before this record
return identical findings on all 24 (UTF-8 byte ranges, actions and sanitized
output compared). None is a beta.13 regression. The tests are
`crates/secret-scan-core/tests/evidence_snapshot_2026_10_04_3_1203.rs`, which
pins every case id.

## Decision

Each base case gets one disposition. Three are in-contract false positives and
are fixed; eleven are families the product does not declare and stay
unsupported; two are fragments or encoded carriers already out of contract;
eight are expectations the evidence has to correct.

| Root cause | Base cases | Disposition |
| --- | --- | --- |
| Terraform's `(sensitive value)` marker read as a credential value | `authored-provider-neutral--terraform-apply-sensitive` | in-contract bug, **fixed**: the exact marker is a non-secret reference |
| `EXA_API_KEY=your_exa_api_key_here`: `exa` missing from the closed placeholder provider list | `exa--exa-api-key-your-key-here-placeholder` | in-contract bug, **fixed**: `exa` added, like `fal` and `convex` in #919 |
| Documented service-account template, a PEM frame whose body is the name `PRIVATE_KEY` | `structured-credential-files-authored--documented-template-placeholders` | in-contract bug, **fixed**: a PEM frame whose whole body is a credential variable name or instructional placeholder is a template |
| `netrc` `password <value>` (whitespace grammar, no `=`/`:` operator) | `netrc-single-line-entry`, `netrc-three-line-entry`, `netrc-quoted-password-with-spaces`, `netrc-two-machines-and-default` | unsupported family |
| kubeconfig `token:` under the bare `token` name | `kubeconfig-inline-bearer-token`, `kubeconfig-four-users-two-inline-secrets` | unsupported: the bare `token` name stays unmatched (`decision-redact-provider-named-credential-assignments`); the `password:` half of the second case is claimed exactly |
| kubeconfig `client-key-data` base64 PEM | `kubeconfig-client-key-data-encoded-pem` | encoded carrier, `decision-defer-encoded-input-decoding` |
| HTTP session cookie `session_id=` | `cookie-header-session-id-among-preferences`, `set-cookie-session-id-with-attributes` | unsupported family |
| Azure SAS `sig=`, S3 presigned `X-Amz-Signature`, GCS `X-Goog-Signature` | `sas-token-in-config-line`, `s3-presigned-url-in-prose`, `cloud-storage-signed-url-in-prose` | unsupported families |
| Basic token cut by a space | `basic-token-split-by-space` | fragment, `decision-define-fragmented-credentials-as-outside-the-raw-input-contract` |
| `Authorization: Basic` over base64 of `user:` or the RFC 7617 example | `basic-empty-password`, `basic-rfc-published-example` | expectation correction: the carrier is claimed without decoding, so "empty password" and "published example" cannot be told from a credential |
| Twilio API Key SID alone | `twilio-compound-credentials-authored--api-key-sid-alone` | expectation correction: the excluded identifier is `SK` + 32 lowercase hex (#746); the evidence value is not that shape |
| Low-entropy literal under a credential name: `FAKE_TOKEN = "test-token"` | `authored-provider-neutral--pytest-fake-fixtures` | expectation correction: `medium`, action `warn`, text unchanged, by the assignment contract |
| JSON-escaped `\n` after a PEM footer | `service-account-key-file-minified-json`, `service-account-key-file-pretty-json` | expectation correction: the block ends at its footer, as a raw PEM does |
| AWS access key id beside its secret | `aws-credentials-file-two-profiles` | expectation correction: the `aws-access-key` family redacts `AKIA`/`ASIA` ids; the three secret spans are exact in every variant |
| `x-api-key: <uuid>` on a non-Exa host | `exa--exa-api-key-other-host-twin` | expectation correction: the Exa gate does not fire off its host, the generic credential-named header assignment does |

### No new family is declared

The product declares no `netrc`, kubeconfig, session-cookie, Azure SAS,
S3-presigned or GCS-signed-URL family. A value there is claimed only when a
supported detector reads it independently: an assignment under a credential
name, an `Authorization` carrier, a PEM block, an AWS access key id. Those
claims are incidental and are not a claim to cover the file or URL. Rows in
`docs/support-matrix.md` and `docs/specs/detector-families.md` are the
declared families; their absence is the statement, and
redact-secret-benchmarks#622 owns the out-of-scope registry that records it.

The decision is to defer, not to reject. A proposal for one family names that
family alone and brings, before any code: provider or format documentation
for the exact grammar, the span the redaction must keep valid for the carrier
(a signed URL keeps its host and path; a `Set-Cookie` keeps its attributes),
a benign corpus sized like the other `freeze-*-grammar` records (cookie and
`sig` parameters are common in ordinary traffic, which is the main false
positive cost), and incremental-retention bounds. The cookie and `sig`
families carry the highest false-positive cost; `netrc` and a kubeconfig user
token have the clearest grammar and are the first candidates.

### Fixes

- **Terraform marker.** `(sensitive value)`, exactly, is a reference
  (`generic_token.rs`, `is_terraform_sensitive_marker`). The unquoted value scan
  returns the whole marker so the value is not cut at its space. `password =
  (sensitive value)Xq7...` and any other value are unchanged. FN cost: none.
- **`exa` placeholder.** `exa` joins `PLACEHOLDER_PROVIDER_WORDS`
  (`text.rs`): `EXA_API_KEY=your_exa_api_key_here` and the hyphen and upper
  forms are clean; a placeholder glued to random material, a real UUID key and
  an unlisted provider stay reported.
- **PEM placeholder frame.** `-----BEGIN <label>-----`, a body that is one
  `UPPER_SNAKE` credential variable name or an instructional placeholder (real
  or escaped line breaks removed), and `-----END <label>-----` is excluded
  (`is_pem_framed_placeholder`). A base64 body, a name with a leftover word and
  an unterminated frame stay reported. FN cost: a private key whose whole
  base64 body spells a name, which the encoding never produces.

### Evidence handoff

The product does not edit credential-evidence. Each correction above is a
change of expectation or of the case input, proposed in the #1203 comment with
the case id and the product evidence. The principle for the evidence: an
expectation of "no finding" on a value a supported family or the assignment
contract claims is a policy expectation, not a product defect, and a scored
span should be a family's own span (a PEM block ends at its footer, a secret
excludes the escaped line separator).

## Consequences

`docs/specs/engine.md` gains one row citing this record;
`docs/specs/contextual-detection.md` gains the two exclusion rows and the
extended provider list. CHANGELOG records the three fixes and the scope under
Unreleased. No public interface changes, no version change, and no release is
made by this record. The pins in the test file make a later reopening a visible
change: a family added for any row above must turn its `assert_clean` into a
positive in the same change.
