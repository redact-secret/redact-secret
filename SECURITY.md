# Security policy

## Supported versions

Redact Secret has public prereleases, listed in
[release status](docs/releases/status.md). Beta publication is not a stable-release
support guarantee. Security fixes target the latest beta; users of older betas
should upgrade. Backports and fixed response or remediation times are not
promised. Report suspected vulnerabilities in any version through the private
channel below. Release status also records registry and GitHub Release
evidence.

## Reporting a vulnerability

Do not include active credentials, private keys, access tokens, or other real
secrets in an issue, pull request, test fixture, log, screenshot, or proof of
concept.

Report vulnerabilities privately through the repository's
[GitHub security advisory form](https://github.com/redact-secret/redact-secret/security/advisories/new).
Use unmistakably synthetic or revoked examples and include:

- the affected API or detector;
- the expected and observed result, without plaintext secret values;
- a minimal deterministic reproduction;
- the relevant runtime and package version or commit; and
- the potential impact at the client or authoritative server boundary.

Do not publicly disclose the issue until a fix and disclosure timeline have
been coordinated with the maintainers.

## How reports are handled

The project has a small maintainer team ([GOVERNANCE.md](GOVERNANCE.md#roles)),
so the times below are targets, not guarantees.

1. **Acknowledge** the report in the advisory thread, targeting 7 days.
2. **Triage**: reproduce it with synthetic data, decide whether it is in
   scope under the [security model](#security-model), and assess severity
   (CVSS where it helps). The reporter is told the outcome. Reports judged
   out of scope are explained, and may be moved to a public issue with the
   reporter's agreement.
3. **Fix** in a private fork of the advisory. The fix carries a deterministic
   regression test, as every bug fix does ([CONTRIBUTION.md](CONTRIBUTION.md)).
4. **Release** the fix through the normal qualified release path
   ([release runbook](docs/releasing.md)) and request a CVE through the
   GitHub advisory when the issue affects a published version.
5. **Disclose** by publishing the GitHub security advisory and a `Security`
   entry in [CHANGELOG.md](CHANGELOG.md). The target is public disclosure
   within 90 days of the report, sooner once a fix is released, or later only
   by agreement with the reporter.

## Credit

Reporters are credited by name or handle in the published advisory and its
changelog entry unless they ask to stay anonymous. The advisory list on the
[security page](https://github.com/redact-secret/redact-secret/security/advisories)
records every credited report.

## Verifying releases

Releases are signed by the registries' keyless signing, not by a long-lived
project key, so there is no public key to download:

- **npm**: every `@redact-secret/*` package is published from the release
  workflow with an npm provenance attestation, signed through Sigstore with
  the workflow's GitHub OIDC identity. After installing, run
  `npm audit signatures`; it verifies the registry signatures and each
  package's provenance attestation. The package page on npmjs.com links the
  attestation to the exact workflow run and source commit.
- **PyPI**: `redact-secret` is uploaded with Trusted Publishing, which
  attaches PEP 740 attestations signed with the same workflow identity. They
  are shown on each file's page on pypi.org and can be checked with
  `pypi-attestations verify pypi --repository https://github.com/redact-secret/redact-secret <file-url>`.
- **crates.io and all registries**: the SHA-256 digests of every published
  artifact are recorded in each version's release manifest under
  [`docs/releases/`](docs/releases/status.md), alongside the annotated
  `v{version}` tag that names the exact source commit.

## Security model

The library detects and redacts likely credentials in untrusted text. It does
not validate whether credentials are live, store secrets, replace a vault, or
provide complete data-loss prevention. Client-side scanning is preventive UX;
security-sensitive applications must scan again at the server boundary.

The core is deterministic and performs no runtime network access, telemetry,
secret storage, or environment-dependent lookup. Findings and library errors
must contain classifications and original-input ranges only, never matched
plaintext.

## Extension and caller trust

Custom detectors, policies, and placeholder formatters are trusted in-process
code. Detectors receive plaintext and must not expose it through candidates,
logs, diagnostics, storage, or thrown errors. Policies and formatters receive
only immutable normalized metadata, but they can still access values captured
by application code; fixed library errors do not sandbox a malicious
extension. Use only reviewed implementations and never load extensions from
untrusted request content.

Findings supplied directly to `redact` are trusted caller assertions. The
library validates their metadata and ranges but does not verify that they came
from `scan` or that the selected action matches server policy. A placeholder is
rejected if it contains any finding's matched range that can fit within the
256-UTF-8-byte placeholder bound, including ranges shorter than four native
range units — this covers `warn`/`allow` findings' ranges as well as
`redact`/`block` ones, since a placeholder must not reproduce a value the
call has no license to reveal regardless of which finding it belongs to.
`warn` and `allow` findings deliberately leave the original text unchanged.

## Authoritative server limits

Whole-input scanning applies only the default bound of 64 MiB of input and
50,000 findings (`WholeInputLimits`), and fails closed when it is exceeded; it
has no built-in transport, candidate-count, output-size, or concurrency limit.
Before scanning,
servers should enforce transport-byte and decoded-input length limits, the
latter in each runtime's native range unit (UTF-8 bytes, UTF-16 code units, or Unicode
code points). Custom detectors should reject rather than truncate above a
declared per-request candidate limit; servers should additionally bound
accepted findings, sanitized output, and concurrent synchronous scans
according to measured latency and memory budgets.

Incremental scanning requires explicit total-input, retained-plaintext, token,
and multiline limits, but callers remain responsible for limiting accumulated
safe output. Limit failures and extension failures are fail-closed and
input-free. Reject oversized work without logging the raw body.

How long input text stays in process memory, and what is and is not erased, is
stated in [plaintext memory lifetime](docs/reference/plaintext-lifetime.md):
the core minimizes owned copies and bounds retention, and it does not zeroize.

## CI supply-chain review

CI grants no workflow-level permissions by default. The test job receives only
read access to repository contents, and checkout does not persist its GitHub
credential because no later step needs it. Action releases are pinned to full
commit SHAs; the adjacent version comments are labels for reviewers and are not
the executable references.

Dependency installation uses `npm ci --ignore-scripts`. The clean install
verifies the exact lockfile graph and its registry integrity metadata without
executing dependency lifecycle scripts. Review install-script declarations
without running them with:

```bash
jq -r '.packages | to_entries[] | select(.value.hasInstallScript == true) | [.key, .value.version] | @tsv' package-lock.json
```

At least monthly, and promptly after an upstream action or dependency security
notice, review the pinned action releases and lockfile. For each action, compare
the upstream release notes and source diff, verify that the release tag resolves
to the proposed commit, then update the SHA and version comment together in one
reviewed change. Validate dependency changes with:

```bash
npm ci --ignore-scripts
npm audit --package-lock-only
npm run ci
```

The publication path is narrower than CI. Every publishing job runs in the
`release` environment and only from `main`. In `release.yml` the publish jobs
hold `contents: read`; only `tag-release` holds `contents: write`, to create the
annotated version tag after publication and registry-install verification
succeed (`Reconcile Release` holds it for its reconcile and tag jobs).
`id-token: write` is granted only to the jobs that sign npm provenance or use
PyPI trusted publishing. npm and crates.io publishing still authenticate with
the `NPM_TOKEN` and `CARGO_REGISTRY_TOKEN` secrets of that environment; the
deferral of npm trusted publishing is recorded in
[docs/releasing.md](docs/releasing.md#npm-publish-authentication-trusted-publishing-deferred).
Provenance is kept with the artifacts: npm and PyPI attestations stay with the
published files, and every run, including a failed one, uploads a
`release-manifest-<version>` workflow artifact (source commit, version,
artifact set, registry state) with an explicit 90-day retention
([docs/releasing.md](docs/releasing.md)).

The Cargo supply chain is checked in CI by `cargo deny check --locked`, with
the policy in `deny.toml`. It allows only the crates.io index as a source,
denies unknown registries and Git sources, denies yanked crates, restricts
licenses to an allow-list, and denies wildcard dependencies. Multiple versions
of one crate only warn.

Pinning a SHA does not pin what the action resolves at run time. Review these
inputs with the action pins in `.github/workflows/python-wheels.yml`
(`PyO3/maturin-action`, issue #1273):

| Input | Pinned value | Resolved how |
|---|---|---|
| `maturin-version` | `v1.15.0` | the version the action resolved from `maturin>=1.10,<2` in `bindings/python/pyproject.toml` (run logs: `Installing 'maturin' from tag 'v1.15.0'`) |
| `container`, `x86_64-unknown-linux-gnu` | `quay.io/pypa/manylinux2014_x86_64@sha256:ffd6d1f11237599748657996b750db6b3a5b724fea5a81cd9ea65add4f45b6c9` | the action's default `:latest` image, by the index digest its run pulled |
| `container`, `aarch64-unknown-linux-gnu` | `quay.io/pypa/manylinux2014_aarch64@sha256:9026a55e05e76ad74d9a4e6be814a5abda26cde08b1baa659ea4f7ee16b246e3` | same |
| `container`, `x86_64-unknown-linux-musl` | `ghcr.io/rust-cross/rust-musl-cross@sha256:ce75e9174325d4fbb3de85c309e2d7ca29f7500169bc4b5d2c611ff7e86d549a` | same, from `:x86_64-musl` |
| `container`, `aarch64-unknown-linux-musl` | `ghcr.io/rust-cross/rust-musl-cross@sha256:ecae5dd62d1c938c14f8071d36c16fa699860aace03bfb5284fb1216474d2643` | same, from `:aarch64-musl` |
| `sccache` | `"true"`, accepted unpinned | the action installs `sccache>=0.10.0` itself (0.16.0 in the last run) and has no version input; it is a compiler cache and does not alter the compiled output |

Update the maturin version and the four image digests together at each review,
and record the new values here. Non-Linux targets build on the host and leave
`container` empty.

Inspect the resulting configuration and logs for permission expansion,
unexpected install-script exposure, publishing authority, and plaintext-secret
diagnostics. Never place credentials in workflow inputs or validation output.
