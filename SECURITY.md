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
rejected if it contains any replaced matched range that can fit within the
256-UTF-8-byte placeholder bound, including ranges shorter than four native
range units.
`warn` and `allow` findings deliberately leave the original text unchanged.

## Authoritative server limits

Whole-input scanning has no built-in request-size, candidate-count,
finding-count, output-size, or concurrency limit. Before scanning, servers
should enforce transport-byte and decoded-input length limits, the latter in
each runtime's native range unit (UTF-8 bytes, UTF-16 code units, or Unicode
code points). Custom detectors should reject rather than truncate above a
declared per-request candidate limit; servers should additionally bound
accepted findings, sanitized output, and concurrent synchronous scans
according to measured latency and memory budgets.

Incremental scanning requires explicit total-input, retained-plaintext, token,
and multiline limits, but callers remain responsible for limiting accumulated
safe output. Limit failures and extension failures are fail-closed and
input-free. Reject oversized work without logging the raw body.

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

Inspect the resulting configuration and logs for permission expansion,
unexpected install-script exposure, publishing authority, and plaintext-secret
diagnostics. Never place credentials in workflow inputs or validation output.
