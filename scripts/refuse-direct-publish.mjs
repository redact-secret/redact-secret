#!/usr/bin/env node
/**
 * `npm run release` used to run `npm publish` on the JavaScript package, a
 * second publish entry beside the approved `Release` workflow. It now only
 * explains where publication happens and exits non-zero, so a local run can
 * never publish: it imports no process, network or filesystem API and holds no
 * credential. Publication, tags and recovery run through the workflows in
 * docs/releasing.md, after the explicit release approval AGENTS.md requires.
 */

const message = `redact-secret: publication is not a local command.

Publishing the npm packages, crates and Python files, and creating the
annotated version tag, happen only through the approved workflows, from main,
after explicit release approval:

  Release            .github/workflows/release.yml            publishes and tags
  Reconcile Release  .github/workflows/reconcile-release.yml  repairs a partial publication

Run the checks locally with \`npm run check:release\` and follow
docs/releasing.md ("Publish the approved revision") to dispatch the workflow.
Nothing was published.`;

process.stderr.write(`${message}\n`);
process.exit(1);
