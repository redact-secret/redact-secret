# Pinned adapter artifacts

This directory pins
[`redact-secret-adapters`](https://github.com/redact-secret/redact-secret-adapters)
packages that this repository consumes before they are published. Consumers
install them as publish-shaped artifacts: `npm pack` tarballs built from one
immutable adapters commit, never a workspace link, a copied source file, or a
branch. The pin is the same kind of product-owned record as
[`benchmarks/pin-source.json`](../benchmarks/README.md). Like the OpenGrep
binary in [`sast/opengrep.lock.json`](../sast/README.md), the artifacts are
not committed. They are built into the gitignored `.cache/adapters/<commit>/`
and verified against the pinned digest before anything installs them.

| File | What it is | Checked by | Changed by |
| --- | --- | --- | --- |
| `pin-source.json` | The exact 40-hex adapters `commit`, each pinned package's `name`, `version` and `contentDigest`, and the `consumers` that install them | `npm run adapter-pins:check` (offline, in `npm run ci`): the record is well formed and every consumer's `package.json` names exactly the pinned tarballs. `npm run adapter-pins:check:ancestry` (live, `adapter-pin-drift` CI job): the commit is on adapters `develop`. | `npm run adapter-pins:sync -- --ref <40-sha>` |

Pinned today: `@redact-secret/adapter`, `@redact-secret/adapter-ai-context`
and `@redact-secret/adapter-mcp` at adapters commit
[`f014a99`](https://github.com/redact-secret/redact-secret-adapters/commit/f014a996ebb9693fbe1c8cc14f144435f011c2b8),
the merge of redact-secret-adapters#25 (redact-secret-adapters#13). The
consumer is [`examples/mcp-redact`](../examples/mcp-redact/README.md), the
AI-context and MCP golden path. `@redact-secret/adapter` is pinned alongside
because `adapter-ai-context` uses its `walkStrict`, which the published
`@redact-secret/adapter@0.1.0` does not export, and `adapter-mcp` depends on
`adapter-ai-context`. `adapter-mcp`'s MCP SDKs are optional peers and are not
installed here: the example is duck-typed against them.

## How CI builds the artifacts

The `Node` test jobs in `.github/workflows/ci.yml` run
`npm run adapter-pins:install` before `npm run ci`. It uses the network, which
is why it is a separate step and not part of the offline `npm run ci`.
`scripts/adapter-pins.py install`:

1. fetches exactly the pinned commit (`git fetch --depth 1 <commit>`) and
   refuses a checkout whose `HEAD` is anything else;
2. runs `npm ci --ignore-scripts`, then builds and `npm pack`s each pinned
   workspace in the listed order (a dependency before its dependents) into
   `.cache/adapters/<commit>/`;
3. verifies each tarball's content digest against `pin-source.json`. A
   mismatch deletes the tarball and fails. A cached tarball is re-verified,
   never trusted;
4. installs every consumer from its `file:` tarball dependencies, offline,
   with no lockfile and no peer auto-install. A consumer's tests inject their
   core, so no registry package enters the tree;
5. re-verifies the installed tree against the same digests.

Inside `npm run ci`, a consumer's test command starts with
`python3 -B scripts/adapter-pins.py verify-installed`. It recomputes the
installed packages' digests offline and, if they are missing or stale, says
to run `npm run adapter-pins:install`.

The content digest is SHA-256 over the sorted `path NUL sha256(bytes) LF`
lines of the tarball's files. It identifies what npm installs, whatever the
gzip bytes, which differ across Node.js versions.

A GitHub fetch by SHA succeeds for a commit on any branch, including an
unmerged pull request branch. That is why the separate `adapter-pin-drift`
job requires the pinned commit to be an ancestor of adapters `develop`.

## Re-pinning, and adding a consumer

```bash
npm run adapter-pins:sync -- --ref <40-sha>   # builds at the new commit, records digests, rewrites consumers
npm run adapter-pins:install                  # installs what was just pinned
npm run adapter-pins:check                    # the same offline check `npm run ci` runs
```

`sync` keeps the listed packages and consumers. To pin another package, add
its `name` (any `version`, and `"contentDigest": "sha256:" + 64 zeros`) to
`packages` in dependency order, then `sync`. To consume the pinned packages
from another directory (a reference architecture, #611), add the directory
to `consumers`. Give it a `package.json` with `"private": true`, run `sync`
to write its `file:` dependencies, and start its test command with
`python3 -B scripts/adapter-pins.py verify-installed`.

A pinned package is unreleased by definition. Once it is published, a
consumer should move to the registry version and leave this pin.
