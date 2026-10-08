// Tests of the detector scaffold (issue #1050): deterministic output, dry run,
// atomic refusal to overwrite, handoff validation against the published v1
// schema, and no secret-shaped output. Each test works on a temporary copy of
// the files the scaffold edits, so a moved repository anchor fails here.
import assert from "node:assert/strict";
import { cpSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import {
  fixtureStubs,
  MARKER,
  main,
  names,
  PLACEHOLDER_PREFIX,
  validateHandoff,
  validateSchema,
} from "../contrib-new-detector.mjs";

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");
const SCHEMA = "docs/contracts/contribution/implementation-ready-handoff-v1.schema.json";
const EXAMPLE = "docs/contracts/contribution/examples/ory-siblings.handoff.json";
const COPIED = [
  "crates/secret-scan-core/src/detectors/mod.rs",
  "crates/secret-scan-core/src/detectors/prefilter.rs",
  "crates/secret-scan-core/src/policy.rs",
  "docs/coverage/detector-inventory.json",
  "docs/coverage/detector-family-coverage-allowlist.json",
  "conformance/fixtures/synchronous-corpus.json",
  "scripts/measure-detector-cost.mjs",
  "docs/specs/detector-families.md",
  "CHANGELOG.md",
  SCHEMA,
  EXAMPLE,
];

const schema = JSON.parse(readFileSync(join(REPO_ROOT, SCHEMA), "utf8"));
const example = JSON.parse(readFileSync(join(REPO_ROOT, EXAMPLE), "utf8"));

function sandbox() {
  const root = mkdtempSync(join(tmpdir(), "contrib-new-detector-"));
  for (const path of COPIED) {
    mkdirSync(dirname(join(root, path)), { recursive: true });
    cpSync(join(REPO_ROOT, path), join(root, path));
  }
  return root;
}

function run(root, argv) {
  const out = [];
  const err = [];
  const code = main(["--root", root, ...argv], { out: (line) => out.push(line), err: (line) => err.push(line) });
  return { code, out: out.join("\n"), err: err.join("\n") };
}

function snapshot(root) {
  const files = new Map();
  for (const path of [...COPIED, "crates/secret-scan-core/src/detectors/demo_token.rs"]) {
    const file = join(root, path);
    if (existsSync(file)) files.set(path, readFileSync(file, "utf8"));
  }
  return files;
}

function withSandbox(body) {
  const root = sandbox();
  try {
    body(root);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
}

function writeHandoff(root, mutate) {
  const copy = structuredClone(example);
  mutate(copy);
  const file = join(root, "case.handoff.json");
  writeFileSync(file, JSON.stringify(copy));
  return file;
}

// The published example describes `ory-token`, which now exists in the tree and
// is refused as an overwrite. The scaffold tests use it under a demo identity.
const DEMO_IDENTITY = (handoff) => {
  handoff.identity.detector = "ory-demo";
  handoff.identity.findingTypes = ["ory_demo_session", "ory_demo_oauth2"];
  handoff.identity.family = "ory-demo:network-api-key";
};

test("the published handoff schema and example validate with no errors", () => {
  assert.deepEqual(validateHandoff(example, schema), []);
});

test("the validator refuses a schema keyword it does not implement", () => {
  assert.throws(() => validateSchema({ oneOf: [] }, {}), /unsupported keyword "oneOf"/);
});

test("dry run prints the plan and writes nothing", () => {
  withSandbox((root) => {
    const before = snapshot(root);
    const { code, out } = run(root, ["demo-token", "--dry-run"]);
    assert.equal(code, 0);
    assert.match(out, /dry run, nothing written/);
    assert.match(out, /create crates\/secret-scan-core\/src\/detectors\/demo_token\.rs/);
    assert.match(out, /TODO\(scaffold\)/);
    assert.deepEqual(snapshot(root), before);
  });
});

test("scaffolding accepts empty and populated unmeasured allowlists", () => {
  for (const unmeasured of [{}, { "alpha-token": "Existing pending arrival" }]) {
    withSandbox((root) => {
      const path = join(root, "docs/coverage/detector-family-coverage-allowlist.json");
      const before = JSON.parse(readFileSync(path, "utf8"));
      before.unmeasured = unmeasured;
      writeFileSync(path, `${JSON.stringify(before, null, 2)}\n`);
      const { code, err } = run(root, ["demo-token", "--issue", "4242"]);
      assert.equal(code, 0, err);
      const after = JSON.parse(readFileSync(path, "utf8"));
      assert.match(after.unmeasured["demo-token"], /#4242/);
      assert.deepEqual(after.stale, before.stale);
      for (const [id, reason] of Object.entries(unmeasured)) assert.equal(after.unmeasured[id], reason);
      assert.deepEqual(Object.keys(after.unmeasured), Object.keys(after.unmeasured).sort());
    });
  }
});

test("scaffolding writes the module and keeps every edited table consistent", () => {
  withSandbox((root) => {
    const { code, out } = run(root, [
      "demo-token",
      "--issue",
      "4242",
      "--finding-type",
      "demo_secret",
      "--group",
      "devtools",
    ]);
    assert.equal(code, 0, out);
    const module = readFileSync(join(root, "crates/secret-scan-core/src/detectors/demo_token.rs"), "utf8");
    assert.match(module, /pub\(super\) const ID: &str = "demo-token";/);
    assert.ok(module.includes(MARKER));

    const mod = readFileSync(join(root, "crates/secret-scan-core/src/detectors/mod.rs"), "utf8");
    assert.match(mod, /^mod demo_token;$/m);
    assert.match(mod, /row\("demo-token", &demo_token::DEMO_TOKEN\),/);
    assert.match(mod, /\("demo-token", Pack::Provider\),/);
    assert.match(mod, /demo_token::ID/);
    const modules = [...mod.matchAll(/^mod ([a-z0-9_]+);$/gm)].map((match) => match[1]);
    const head = modules.slice(0, modules.indexOf("demo_token") + 2);
    assert.deepEqual(head, [...head].sort(), "mod declarations stay alphabetical for rustfmt");

    const inventory = JSON.parse(readFileSync(join(root, "docs/coverage/detector-inventory.json"), "utf8"));
    const row = inventory.types.find((entry) => entry.detector === "demo-token");
    assert.equal(row.type, "demo_secret");
    assert.equal(row.policyClass, "always-redact");
    assert.ok(row.reconciliationTrigger.startsWith(PLACEHOLDER_PREFIX));

    const policy = readFileSync(join(root, "crates/secret-scan-core/src/policy.rs"), "utf8");
    const list = /const ALWAYS_REDACT_TYPES: \[&str; (\d+)\] = \[\n([\s\S]*?)\n\];/.exec(policy);
    const entries = list[2].split("\n");
    assert.equal(Number(list[1]), entries.length);
    assert.ok(entries.includes('    "demo_secret",'));
    assert.deepEqual(entries, [...entries].sort());

    const prefilter = readFileSync(join(root, "crates/secret-scan-core/src/detectors/prefilter.rs"), "utf8");
    const declared = /fn full_declares_(\d+)_detectors_and_common_4/.exec(prefilter)[1];
    assert.match(prefilter, new RegExp(`declared\\(built_in_entries\\(\\)\\), ${declared}\\);`));

    const corpus = JSON.parse(readFileSync(join(root, "conformance/fixtures/synchronous-corpus.json"), "utf8"));
    assert.equal(corpus.fixtureCount, corpus.fixtures.length);
    const own = corpus.fixtures.filter((fixture) => fixture.detector === "demo-token");
    assert.deepEqual(own.map((fixture) => fixture.kind).sort(), [
      "adversarial",
      "boundary",
      "negative",
      "overlap",
      "positive",
    ]);

    const allowlist = JSON.parse(
      readFileSync(join(root, "docs/coverage/detector-family-coverage-allowlist.json"), "utf8"),
    );
    assert.match(allowlist.unmeasured["demo-token"], /#4242/);
    assert.deepEqual(Object.keys(allowlist.unmeasured), Object.keys(allowlist.unmeasured).sort());

    const cost = readFileSync(join(root, "scripts/measure-detector-cost.mjs"), "utf8");
    assert.equal(cost.match(/^ {2}"demo-token",$/gm).length, 1);
    assert.equal(cost.match(/^ {4}"demo-token",$/gm).length, 1);
    assert.match(
      readFileSync(join(root, "CHANGELOG.md"), "utf8"),
      // Appended to the end of an existing "### Added" list, or opened as one.
      /### Added\n\n(?:[\s\S]*\n)?- `demo-token` \(#4242\): TODO\(scaffold\)/,
    );
    assert.match(
      readFileSync(join(root, "docs/specs/detector-families.md"), "utf8"),
      /## Scaffolded detector rows[\s\S]*`demo-token`/,
    );
  });
});

test("scaffolding twice refuses and leaves every file as the first run left it", () => {
  withSandbox((root) => {
    assert.equal(run(root, ["demo-token"]).code, 0);
    const after = snapshot(root);
    const second = run(root, ["demo-token"]);
    assert.equal(second.code, 1);
    assert.match(second.err, /already exists; refusing to overwrite/);
    assert.match(second.err, /nothing was written/);
    assert.deepEqual(snapshot(root), after);
  });
});

test("one conflicting target refuses the whole run before anything is written", () => {
  withSandbox((root) => {
    const module = join(root, "crates/secret-scan-core/src/detectors/demo_token.rs");
    writeFileSync(module, "// contributor work in progress\n");
    const before = snapshot(root);
    const { code, err } = run(root, ["demo-token"]);
    assert.equal(code, 1);
    assert.match(err, /demo_token\.rs: already exists/);
    assert.deepEqual(snapshot(root), before);
    assert.equal(readFileSync(module, "utf8"), "// contributor work in progress\n");
  });
});

test("an id or finding type that an existing detector owns is refused", () => {
  withSandbox((root) => {
    const before = snapshot(root);
    const existingId = run(root, ["fly-token"]);
    assert.equal(existingId.code, 1);
    assert.match(existingId.err, /already registered|already declared/);
    const existingType = run(root, ["demo-token", "--finding-type", "fly_access_token"]);
    assert.equal(existingType.code, 1);
    assert.match(existingType.err, /fly_access_token is already|finding type fly_access_token is already declared/);
    assert.deepEqual(snapshot(root), before);
  });
});

test("a confidence-gated detector skips the always-redact list", () => {
  withSandbox((root) => {
    const policyBefore = readFileSync(join(root, "crates/secret-scan-core/src/policy.rs"), "utf8");
    const { code } = run(root, ["demo-token", "--policy-class", "confidence-gated"]);
    assert.equal(code, 0);
    assert.equal(readFileSync(join(root, "crates/secret-scan-core/src/policy.rs"), "utf8"), policyBefore);
    const inventory = JSON.parse(readFileSync(join(root, "docs/coverage/detector-inventory.json"), "utf8"));
    assert.equal(inventory.types.find((entry) => entry.detector === "demo-token").policyClass, "confidence-gated");
  });
});

test("a handoff supplies id, finding types, policy, family, issue and benchmark counterpart", () => {
  withSandbox((root) => {
    const { code, out } = run(root, ["--handoff", writeHandoff(root, DEMO_IDENTITY)]);
    assert.equal(code, 0, out);
    assert.match(out, /ory_demo_session, ory_demo_oauth2/);
    assert.match(out, /npm run check:detector ; npm run check:rust ; npm run check:js/);
    const inventory = JSON.parse(readFileSync(join(root, "docs/coverage/detector-inventory.json"), "utf8"));
    assert.deepEqual(
      inventory.types.filter((entry) => entry.detector === "ory-demo").map((entry) => entry.type),
      ["ory_demo_session", "ory_demo_oauth2"],
    );
    const allowlist = readFileSync(join(root, "docs/coverage/detector-family-coverage-allowlist.json"), "utf8");
    assert.match(allowlist, /#1110/);
    assert.match(allowlist, /redact-secret-benchmarks#583/);
    assert.match(readFileSync(join(root, "docs/specs/detector-families.md"), "utf8"), /`ory-demo:network-api-key`/);
  });
});

test("invalid handoffs exit 2 and write nothing", () => {
  const cases = {
    "state other than implementation-ready": (h) => (h.state = "research-needed"),
    "unknown top-level field": (h) => (h.extra = true),
    "missing required field": (h) => delete h.policy,
    "support status other than separate": (h) => (h.evaluation.supportStatus = "stable"),
    "limitation without a matching exclusion": (h) => {
      h.exclusions = [];
      h.research.limitations = ["one limitation that no exclusion restates"];
    },
    "credential-shaped literal in a shape description": (h) => {
      h.positives[0].description = `Example value ${["sk", "live", "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6"].join("-")} is supported.`;
    },
    "long digit-bearing run in prose": (h) =>
      (h.task = `Add a detector for 0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b as described.`),
    "route that edits an existing detector": (h) => (h.identity.route = "extend-detector"),
    "block default that is a policy change": (h) => (h.policy.defaultAction = "block"),
  };
  for (const [name, mutate] of Object.entries(cases)) {
    withSandbox((root) => {
      const before = snapshot(root);
      const { code, err } = run(root, ["--handoff", writeHandoff(root, mutate)]);
      assert.equal(code, 2, `${name}: ${err}`);
      assert.deepEqual(snapshot(root), before, name);
    });
  }
});

test("handoff conflicts with flags and a non-JSON file are usage errors", () => {
  withSandbox((root) => {
    assert.equal(run(root, ["other-token", "--handoff", join(root, EXAMPLE)]).code, 2);
    assert.equal(run(root, ["--handoff", join(root, EXAMPLE), "--finding-type", "unrelated"]).code, 2);
    assert.equal(run(root, ["--handoff", join(root, EXAMPLE), "--policy-class", "confidence-gated"]).code, 2);
    const broken = join(root, "broken.handoff.json");
    writeFileSync(broken, "{ not json");
    assert.equal(run(root, ["--handoff", broken]).code, 2);
    assert.equal(run(root, ["--handoff", join(root, "missing.handoff.json")]).code, 2);
  });
});

test("usage errors exit 2 and --help exits 0", () => {
  withSandbox((root) => {
    for (const argv of [
      [],
      ["Bad_Id"],
      ["a-token", "b-token"],
      ["demo-token", "--nope"],
      ["demo-token", "--policy-class", "block"],
      ["demo-token", "--group", "everything"],
      ["demo-token", "--finding-type", "Not-Snake"],
      ["demo-token", "--issue", "abc"],
      ["demo-token", "--issue"],
    ]) {
      assert.equal(run(root, argv).code, 2, argv.join(" "));
    }
    const help = run(root, ["--help"]);
    assert.equal(help.code, 0);
    assert.match(help.out, /Usage: npm run contrib:new-detector/);
  });
});

test("generated text carries only the synthetic placeholder, never a secret-shaped literal", () => {
  withSandbox((root) => {
    const before = snapshot(root);
    assert.equal(run(root, ["--handoff", writeHandoff(root, DEMO_IDENTITY)]).code, 0);
    const after = snapshot(root);
    const added = [readFileSync(join(root, "crates/secret-scan-core/src/detectors/ory_demo.rs"), "utf8")];
    for (const [path, text] of after) {
      const old = before.get(path);
      if (old === undefined) continue;
      const known = new Set(old.split("\n"));
      added.push(...text.split("\n").filter((line) => !known.has(line)));
    }
    assert.ok(added.length > 20);
    for (const text of added) {
      // Remove the one allowed literal: the placeholder prefix and its filler.
      const rest = text
        .replaceAll(new RegExp(`${PLACEHOLDER_PREFIX}[0-9a-f* ]*`, "g"), "")
        .replaceAll('"5e7c0ded"', "");
      for (const run_ of rest.match(/[A-Za-z0-9+/_=-]{24,}/g) ?? []) {
        const mixedCase = /[a-z]/.test(run_) && /[A-Z]/.test(run_) && /[0-9]/.test(run_);
        assert.ok(!mixedCase && !/^[0-9a-f]{24,}$/.test(run_), `secret-shaped run in generated text: ${run_}`);
      }
      assert.doesNotMatch(rest, /\b(?:sk|pk)[-_][A-Za-z0-9]{16,}|ghp_|AKIA[0-9A-Z]{16}|xox[abp]-|eyJ[A-Za-z0-9]{10}/);
    }
    const names_ = names("ory-demo");
    for (const fixture of fixtureStubs(names_, ["ory_demo_session"])) {
      assert.ok(
        fixture.input.startsWith(PLACEHOLDER_PREFIX) || fixture.input.startsWith(`secret_key=${PLACEHOLDER_PREFIX}`),
      );
      assert.ok(fixture.note.startsWith(MARKER));
    }
  });
});

test("the scaffold is deterministic: two sandboxes end byte-identical", () => {
  const outputs = [0, 1].map(() => {
    const root = sandbox();
    try {
      assert.equal(run(root, ["demo-token", "--issue", "7"]).code, 0);
      return [...snapshot(root)];
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });
  assert.deepEqual(outputs[0], outputs[1]);
});
