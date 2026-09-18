# Reproduce a local candidate benchmark

`npm run benchmark:candidate` builds the committed product source in a detached
temporary worktree and evaluates immutable npm tarballs at one exact
`redact-secret-benchmarks` commit:

```sh
npm run benchmark:candidate -- \
  --benchmark-ref <full-40-character-commit-sha>
```

Optional arguments are `--benchmark-repo <absolute-path>`, `--output-dir
<absolute-path>`, and `--filter <detector-id>`. Without a repository path the
runner uses a verified sibling checkout when present, otherwise a temporary
clone. It never checks out or resets the user's active benchmark branch.

The product worktree must be clean. Exploratory dirty-tree evidence is rejected;
formal evidence therefore always names the exact source commit that produced
the package. The runner builds the façade, current host N-API package, and Wasm
package using the same build and npm-pack shape as artifact qualification. It
records the façade tarball SHA-256 and every component hash.

The benchmark revision must be a lowercase full 40-character commit SHA. Tags,
branches, abbreviated revisions, and mismatched detached HEADs are rejected.
The runner verifies the benchmark repository identity, installs its committed
lockfile with `npm ci`, invokes its candidate-only entrypoint, validates the
result, and prints the absolute evidence path. Temporary worktrees and install
trees are removed; preserved tarballs and evidence remain under `--output-dir`
or the ignored `benchmark-evidence/` default.

`--filter` selects existing benchmark fixtures without changing their authored
truth. Filtered evidence is development-scoped and never represents full-suite
qualification. Candidate evidence is separate from the benchmark's pinned
published scanner and Evaluation Engine qualification suite.
