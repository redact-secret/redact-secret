/**
 * Shared canonical-corpus fixture lookup for the runtime artifact
 * qualification scripts (`qualify-node-addon.mjs`,
 * `qualify-browser-artifact.mjs`).
 *
 * Neither qualification script embeds a fixture input or a matched value in
 * its own source (the same rule the RB-1 corpus tests follow): both read from
 * `conformance/fixtures/synchronous-corpus.json`, the corpus shared across
 * every language binding.
 */

import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

export const REPO_ROOT_PATH = fileURLToPath(new URL("..", import.meta.url));

/**
 * The fixture both qualification scripts assert against: one supported,
 * single-finding, pure-ASCII entry. Pure ASCII means its UTF-8 byte offsets
 * (the corpus's `offsetUnit`) equal UTF-16 code unit offsets (`scan()`'s
 * contract on every JavaScript runtime), so the same fixture is usable
 * unmodified as `scan()` input without an offset conversion in the harness.
 */
export const CANONICAL_FIXTURE_ID = "host-dotenv-github";

export async function loadCanonicalFixture(id) {
  const corpus = JSON.parse(
    await readFile(join(REPO_ROOT_PATH, "conformance/fixtures/synchronous-corpus.json"), "utf8"),
  );
  if (corpus.offsetUnit !== "utf8-byte") {
    throw new Error(`conformance/fixtures/synchronous-corpus.json: unexpected offsetUnit ${corpus.offsetUnit}`);
  }
  const fixture = corpus.fixtures.find((entry) => entry.id === id);
  if (!fixture) {
    throw new Error(`conformance/fixtures/synchronous-corpus.json: no fixture with id ${id}`);
  }
  if (fixture.expected.length !== 1) {
    throw new Error(`fixture ${id} must have exactly one expected finding, found ${fixture.expected.length}`);
  }
  // eslint-disable-next-line no-control-regex -- ASCII range check, not a sanitizer.
  if (!/^[\x00-\x7f]*$/.test(fixture.input)) {
    throw new Error(`fixture ${id} must be pure ASCII to reuse its byte offsets as UTF-16 offsets`);
  }
  return fixture;
}

/** Throws with a diff if `finding` does not match `fixture`'s one expectation. */
export function assertMatchesFixture(finding, fixture) {
  const expected = fixture.expected[0];
  const mismatches = ["detector", "type", "confidence", "start", "end"]
    .filter((key) => finding?.[key] !== expected[key])
    .map((key) => `${key}: expected ${JSON.stringify(expected[key])}, got ${JSON.stringify(finding?.[key])}`);
  if (mismatches.length > 0) {
    throw new Error(`fixture ${fixture.id} mismatch:\n${mismatches.join("\n")}`);
  }
}

export async function packageVersion() {
  return JSON.parse(await readFile(join(REPO_ROOT_PATH, "package.json"), "utf8")).version;
}
