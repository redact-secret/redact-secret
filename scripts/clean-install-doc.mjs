/**
 * Issue #586: reads the three clean-install scenarios out of
 * `docs/quickstart.md`, so the commands and files a reader copies are, by
 * construction, the commands and files `scripts/qualify-clean-install.mjs`
 * runs in CI -- there is no second copy to drift.
 *
 * A scenario block is an ordinary fenced code block whose info string carries
 * one `qualify=<lane>:<role>` attribute after the language, which Markdown
 * renderers ignore:
 *
 *   ```sh qualify=node:setup          shell run in the empty directory
 *   ```js qualify=node:file:<name>    a file the reader saves
 *   ```sh qualify=node:run            shell whose stdout is the result
 *   ```sh qualify=browser:serve       long-running server (browser only)
 *   ```text qualify=node:expect       the exact expected result
 */

export const LANES = Object.freeze(["node", "python", "browser"]);

/** The one synthetic, revoked-shaped value every scenario redacts. */
export const SYNTHETIC_INPUT = "API_KEY=SYNTHETIC_REVOKED_CONTEXT_VALUE";

const FENCE = /^```([^\n`]*)\n([\s\S]*?)^```[ \t]*$/gm;
const ATTRIBUTE = /(?:^|\s)qualify=([a-z]+):([a-z]+)(?::(\S+))?(?:\s|$)/;
const FILE_NAME = /^[A-Za-z0-9][A-Za-z0-9._-]*$/;

/**
 * Every `qualify=` block in `markdown`, grouped by lane, validated for shape.
 * Throws on anything a reader could not follow literally.
 */
export function parseQuickstart(markdown) {
  const scenarios = Object.fromEntries(
    LANES.map((lane) => [lane, { setup: undefined, files: [], run: undefined, serve: undefined, expect: undefined }]),
  );
  for (const match of markdown.matchAll(FENCE)) {
    const attribute = ATTRIBUTE.exec(match[1]);
    if (attribute === null) continue;
    const [, lane, role, name] = attribute;
    const body = match[2];
    const scenario = scenarios[lane];
    if (scenario === undefined) throw new Error(`quickstart: unknown lane ${lane}`);
    if (role === "file") {
      if (name === undefined || !FILE_NAME.test(name)) {
        throw new Error(`quickstart: ${lane} file block needs a plain file name`);
      }
      if (scenario.files.some((file) => file.name === name)) {
        throw new Error(`quickstart: ${lane} declares ${name} twice`);
      }
      scenario.files.push({ name, content: body });
      continue;
    }
    if (!["setup", "run", "serve", "expect"].includes(role) || name !== undefined) {
      throw new Error(`quickstart: invalid block qualify=${lane}:${role}`);
    }
    if (scenario[role] !== undefined) throw new Error(`quickstart: ${lane} declares ${role} twice`);
    scenario[role] = role === "expect" ? body.replace(/\n$/, "") : body;
  }

  for (const lane of LANES) {
    const scenario = scenarios[lane];
    for (const role of ["setup", "run", "expect"]) {
      if (scenario[role] === undefined) throw new Error(`quickstart: ${lane} has no ${role} block`);
    }
    if (scenario.files.length === 0) throw new Error(`quickstart: ${lane} has no file block`);
    if ((lane === "browser") !== (scenario.serve !== undefined)) {
      throw new Error(`quickstart: only the browser lane has a serve block (${lane})`);
    }
    if (!scenario.files.some((file) => file.content.includes(JSON.stringify(SYNTHETIC_INPUT)))) {
      throw new Error(`quickstart: ${lane} does not redact the synthetic input`);
    }
  }
  return scenarios;
}

/** The shell commands of one scenario, one per non-empty line, in order. */
export function scenarioCommands(scenario) {
  return [scenario.setup, scenario.run, scenario.serve]
    .filter((block) => block !== undefined)
    .flatMap((block) => block.split("\n"))
    .map((line) => line.trim())
    .filter((line) => line !== "");
}

/** The npm and PyPI spellings of the product version, e.g. 0.1.0-beta.6 / 0.1.0b6. */
export function versionSpellings(version) {
  const match = /^(\d+\.\d+\.\d+)(?:-beta\.(\d+))?$/.exec(version);
  if (match === null) throw new Error(`unsupported product version ${version}`);
  return { npm: version, python: match[2] === undefined ? match[1] : `${match[1]}b${match[2]}` };
}

/**
 * Every version the quickstart pins must be the product version under
 * qualification: the npm spec, the PyPI spec, and the expected output lines.
 * A release bump that forgets this page fails here, not in a reader's shell.
 */
export function requirePinnedVersion(scenarios, version) {
  const { npm, python } = versionSpellings(version);
  const errors = [];
  const pins = [
    ["node", scenarios.node.setup, `@redact-secret/core@${npm}`],
    ["browser", scenarios.browser.setup, `@redact-secret/core@${npm}`],
    ["python", scenarios.python.setup, `redact-secret==${python}`],
  ];
  for (const [lane, setup, pin] of pins) {
    const specs = setup.match(/@redact-secret\/core@\S+|redact-secret==\S+/g) ?? [];
    if (specs.length !== 1 || specs[0] !== pin) {
      errors.push(`${lane}: setup must install exactly ${pin}, found ${specs.join(", ") || "nothing"}`);
    }
  }
  for (const lane of LANES) {
    const first = scenarios[lane].expect.split("\n")[0];
    if (!first.startsWith(`redact-secret ${npm}`)) {
      errors.push(`${lane}: expected output must start with "redact-secret ${npm}"`);
    }
  }
  return errors;
}
