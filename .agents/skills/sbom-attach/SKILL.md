---
name: sbom-attach
description: Generate a CycloneDX SBOM for each of this repository's published artifacts (Rust crates, npm packages, the PyPI wheel) and validate it against the current release manifest's artifact set. Use when asked to generate, check, or attach an SBOM, before adding SBOM evidence to a release, or for "sbom-attach", "/sbom-attach". Generates files under the scratchpad only; never edits the release workflow.
---

# sbom-attach

Produce one CycloneDX SBOM per shipped artifact and check it against what the release process already records. This skill only generates and reports; it never edits `.github/workflows/release.yml`, `scripts/release-manifest.py`, or any other release-authority file — wiring generated SBOMs into the actual publish pipeline is a separate, reviewed change (`AGENTS.md` "Release authority").

## Why this repository, specifically

`scripts/release-manifest.py` already records `artifact_set` and, per artifact identity (e.g. `npm:@redact-secret/wasm`, `crate:redact-secret`, `pypi:redact-secret`), an `artifact_digests` block with `built`/`qualified`/`published` file digests. An SBOM is the natural next layer on the same identities: what each artifact is *made of*, not just what bytes it is. Generate SBOMs keyed the same way so a future integration can slot them into that existing structure instead of inventing a parallel one.

## Artifact set

Generate one SBOM per artifact identity currently in the release manifest's `artifact_set` (read a recent `release-manifest-<version>` if one is available, or `scripts/check-artifact-matrix.py`'s notion of the matrix if not):

| Identity | Source | Tool |
| --- | --- | --- |
| `crate:redact-secret` | `crates/secret-scan-core` | `cargo cyclonedx -p redact-secret --format json` |
| `crate:redact-secret-cli` | `crates/secret-scan-cli` | `cargo cyclonedx -p redact-secret-cli --format json` |
| `npm:@redact-secret/core` | `packages/javascript` | `npx @cyclonedx/cyclonedx-npm --output-format json --output-file <scratchpad>/sbom-npm-core.cdx.json` (run from `packages/javascript`) |
| `npm:@redact-secret/wasm` | `bindings/wasm`'s published package | same tool, run against that package's own `package.json`/lockfile |
| `npm:@redact-secret/node-<platform>` (×8) | `bindings/node`'s platform packages | same tool, once per platform package, or note if they are structurally identical modulo platform metadata and generate one representative plus a diff note |
| `pypi:redact-secret` | the built wheel from `bindings/python` | `cyclonedx-py environment` (or `cyclonedx-py requirements` against an empty requirement set, since `pyproject.toml` declares `dependencies = []`) — expect a near-empty component list and say so explicitly, do not treat that as a tool failure |

Record each tool's version. Write outputs under the session scratchpad as `sbom-<identity-with-colons-replaced-by-dashes>.cdx.json`, never into the repository tree, unless asked to stage them for commit.

## Validate

For each generated SBOM:

- It parses as valid CycloneDX (schema version noted).
- Its declared component name/version matches the artifact identity's actual published or locally-built name/version — catches a stale lockfile or a wrong working directory before it catches anything upstream.
- For the Rust crates: the dependency list matches what `cargo deny check` (see `dependency-audit`) already enumerated for that crate — a mismatch means the SBOM tool and the vulnerability scanner disagree about what's shipped, which is itself a finding.
- For `@redact-secret/core`: the component list should be exactly `@redact-secret/wasm` plus the optional `@redact-secret/node-*` set (no unexpected third-party runtime component) — if one appears, treat it as equivalent in severity to an unreviewed new runtime dependency landing in `package.json`.

## Output

| Artifact identity | SBOM path | Component count | Validation result | Note |
| --- | --- | --- | --- | --- |

Then a one-line proposal for where this would attach if adopted (e.g. "alongside the existing `qualification-inventory`/`artifact-inventory.json` upload in `release.yml`, keyed the same way `artifact_digests` is keyed") — a proposal only, not a diff to apply.

## Rules

- Do not modify `.github/workflows/*.yml`, `scripts/release-manifest.py`, or any release-gate script. Propose integration; do not wire it in.
- Do not commit generated SBOM files unless explicitly asked.
- If a generation tool needs registry or crates.io credentials to run, stop and say so rather than prompting for them.
