// The shared cases for `compareConfigurations` (issue #1254), as JavaScript
// runs them. The cases live in
// `conformance/fixtures/configuration-compare-v1.json` and are run by the Rust
// core against its own `compare_configurations` and, here, by every JavaScript
// surface against the artifact it loaded. No surface keeps a copy of the
// expectations: this module only turns a fixture case into the options the
// public function takes and projects its result onto what the fixture pins.

import { readFileSync } from "node:fs";

const FIXTURE_URL = new URL("./fixtures/configuration-compare-v1.json", import.meta.url);

/** The parsed fixture. */
export function loadConfigurationCompareFixture() {
  return JSON.parse(readFileSync(FIXTURE_URL, "utf8"));
}

/** The cases that apply to the `full` or `common` entry point. */
export function casesFor(fixture, profile) {
  return fixture.cases.filter((fixtureCase) => fixtureCase.profiles.includes(profile));
}

/** The `compareConfigurations` options of a fixture case. */
export function optionsFor(fixtureCase) {
  const configs = fixtureCase.sides.map((side) => {
    const config = { ...(side.config ?? {}) };
    if (side.ruleset !== undefined) config.ruleset = side.ruleset;
    if (side.actionPolicy !== undefined) config.actionPolicy = side.actionPolicy;
    return config;
  });
  const options = { configs };
  if (fixtureCase.actionPolicy !== undefined) options.actionPolicy = fixtureCase.actionPolicy;
  return options;
}

/**
 * The projection the fixture pins, with ranges converted from UTF-16 code
 * units to Unicode code points so one expectation serves every range unit.
 */
export function project(input, comparison) {
  const points = (units) => [...input.slice(0, units)].length;
  return {
    sides: comparison.results.map((result) => ({
      status: result.status,
      failure: result.failure,
      findings: result.findings.map((finding) => ({
        type: finding.type,
        detector: finding.detector,
        range: [points(finding.start), points(finding.end)],
      })),
    })),
    differences: comparison.differences.map((differences) =>
      differences === null
        ? null
        : {
            unchanged: differences.unchanged,
            entries: differences.entries.map((entry) => ({
              kind: entry.kind,
              correspondence: entry.correspondence,
              base: [...entry.base],
              other: [...entry.other],
              changes: [...entry.changes],
            })),
          },
    ),
  };
}
