# Beta.9 candidate public-contract review

[Documentation home](../README.md) · [Audit archive](README.md)

- Issue: [#851](https://github.com/redact-secret/redact-secret/issues/851).
- Reviewed on: 2026-09-26.
- Previous published source: `v0.1.0-beta.8`,
  `5639a0ea02e0eefbd1533bea23a05c749b529bef`.
- Reviewed implementation baseline:
  `09e1d7f85cd2ada9f387cc5c9beef3b29023d17d`.
- Status: public API and compatibility review, exact-SHA qualification, SAST,
  benchmark qualification, performance evaluation, and blind evaluation are
  complete for the baseline. Explicit release approval remains pending.

This review replaces the beta.6 document as the current review input to the
artifact inventory. An inventory binds this document's digest and its own
`sourceCommit` together. The immutable #851 review comments record the merged
source revision, the fresh evidence, and the remaining release authority.
Hashing this document alone is not a current API review.

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

The reviewed baseline passed:

- Artifact qualification
  [36243644354](https://github.com/redact-secret/redact-secret/actions/runs/36243644354):
  the inventory records beta.9 and the exact source revision.
- SAST
  [36243644250](https://github.com/redact-secret/redact-secret/actions/runs/36243644250):
  the normalized OpenGrep report was enforced against the same source.
- The immutable
  [final shadow/performance record](https://github.com/redact-secret/redact-secret-benchmarks/blob/3fb195818eb31c481aaebc0257384386d17b2d7c/evidence/767/09e1d7f8/README.md)
  binds the exact candidate, scoring and calibration identities, performance
  run, deterministic output, source-bound size acceptance, and fresh
  `beta9-e2` blind run. It qualifies only the non-enforcing shadow foundation;
  future-promotion Q4 fails.

Any source change after the reviewed baseline invalidates this exact-SHA
evidence. Such a change requires fresh qualification and review before release
approval; the evidence above must not be cited for a later source revision.

No review document, successful workflow, issue closure, or manifest version
authorizes a tag, release, publication, or deployment. Explicit release
approval remains a separate step after the fresh evidence and final changelog
review pass for the source being released.
