# Beta.9 candidate public-contract review

[Documentation home](../README.md) · [Audit archive](README.md)

- Issue: [#851](https://github.com/redact-secret/redact-secret/issues/851).
- Reviewed on: 2026-09-26.
- Previous published source: `v0.1.0-beta.8`,
  `5639a0ea02e0eefbd1533bea23a05c749b529bef`.
- Reviewed implementation baseline:
  `93ddf510a31563d58c7d4c202363ef65c4d92d55`.
- Status: public API and compatibility review complete for the baseline; release
  approval and fresh evidence for the source-changing release-contract fix are
  pending.

This review replaces the beta.6 document as the current review input to the
artifact inventory. An inventory binds this document's digest and its own
`sourceCommit` together. The final merged source revision is also recorded in
the immutable #851 review comment before release approval; hashing an older
review document alone is not a current API review.

## Public API and compatibility

The beta.8-to-beta.9 diff changes no exported function, type, error-code union,
package export subpath, range unit, callback contract, runtime requirement, or
CLI argument contract.

| Surface | Review result |
| --- | --- |
| Rust | The only crate-root structural addition is private `mod evidence`; every scorer item is `pub(crate)` or narrower. The `pub use` list, `core-public-api` manifest list, and external `public_api` tests remain aligned. |
| JavaScript | Public source changes only the shared version constant. The root, `common`, Node-stream, Web-stream, and `package.json` exports and all TypeScript contracts are unchanged. Exact runtime dependency pins move together to beta.9. |
| Python | The import module, stub, PyO3 exports, callback shapes, range units, and incremental API are unchanged. The distribution version remains derived from Cargo (`0.1.0b9`). |
| CLI | Commands, reports, exit codes, limits, and safe diagnostic contract are unchanged. |

Detection behavior does change. The dated changelog records the added
assignment, URL-parameter, authorization, RFC 8959, connection-userinfo, JWK,
and `db_pass` coverage, together with the narrowed non-secret reference cases.
Consumers that assert an exact finding set can therefore observe additions or
removals, while the structural API and enforcement boundary remain compatible.

The beta.9 evidence scorer is shadow-only. Public whole-input calls pass no
recording sink, production incremental builds call the legacy detector
pipeline directly, and the scorer exports no public field or function. It does
not change confidence, overlap resolution, policy, findings, or redaction.

## Runtime, package, and security boundary

All version-bearing Cargo and npm manifests and lockfiles agree on
`0.1.0-beta.9`; the facade pins the WebAssembly package and all eight native
packages at that exact version. The core still has an empty dependency
allowlist and no runtime network, filesystem, environment, telemetry, secret
storage, or UI behavior. Detection remains separate from policy enforcement,
and findings and diagnostics remain input-free.

The reviewed artifact set is the same product surface as beta.8: the npm
facade, WebAssembly package, eight native npm packages, Rust core and CLI
crates, six CLI binaries, eight abi3 wheels plus the Python sdist. Browser and
Node compatibility remain covered by the declared Chromium, Firefox, WebKit,
and Node 20/22/24 lanes.

## Baseline evidence and invalidation

The baseline passed:

- Artifact qualification
  [36233877397](https://github.com/redact-secret/redact-secret/actions/runs/36233877397):
  62 jobs completed with 58 successes and four intentional skips; the
  inventory recorded 49 artifact files, three clean-install lanes, one Node
  MCP golden-path lane, and `published: false`.
- SAST
  [36233877258](https://github.com/redact-secret/redact-secret/actions/runs/36233877258):
  the normalized OpenGrep report was enforced against the reviewed baseline.
- Local review probes: `npm run rust:check`, the Rust `public_api` integration
  test, JavaScript build/typecheck, changelog coverage, decision validation,
  and `git diff --check` passed.

The #851 fix changes the source revision after the blind evaluation and those
workflow runs. None of the evidence above qualifies the merged fix, and none
may be cited as if it did. Before beta.9 release approval, the merged `main`
SHA requires fresh exact-SHA Artifact qualification, SAST, benchmark
qualification, and a new blind evaluation under the benchmark protocol. The
new artifact inventory must name that SHA and pin this review's digest.

No review document, successful workflow, issue closure, or manifest version
authorizes a tag, release, publication, or deployment. Explicit release
approval remains a separate step after the fresh evidence and final changelog
review pass.
