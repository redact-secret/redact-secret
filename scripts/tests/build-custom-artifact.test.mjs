import assert from "node:assert/strict";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { fileURLToPath, pathToFileURL } from "node:url";

import {
  BuildError,
  buildCustomArtifact,
  bundleEntry,
  ENGINE_FLOOR,
  planCustomArtifact,
  UNSUPPORTED_TARGETS,
  verifyLockUnchanged,
} from "../build-custom-artifact.mjs";
import {
  CompositionError,
  canonicalCompositionDocument,
  constructorName,
  generateLeafLib,
  generateLeafManifest,
  parseComposition,
  readCatalog,
  resolveComposition,
} from "../lib/composition.mjs";
import { containsLiteral, measureElimination, printableRuns, sizes, words } from "../lib/wasm-inspect.mjs";

const REPO_ROOT = fileURLToPath(new URL("../..", import.meta.url));

test("the emitted loader keeps Workers' Node process shim out of the file loader", async () => {
  const root = mkdtempSync(join(tmpdir(), "custom-loader-"));
  const globals = Object.fromEntries(
    ["navigator", "window", "document"].map((name) => [name, Object.getOwnPropertyDescriptor(globalThis, name)]),
  );
  try {
    const dist = join(root, "dist");
    mkdirSync(join(dist, "runtime"), { recursive: true });
    writeFileSync(join(root, "package.json"), '{"type":"module"}');
    writeFileSync(join(dist, "runtime.js"), "export const createRedactSecretRuntime = load => ({initialize: load});");
    writeFileSync(join(dist, "entry-core.js"), "export {};");
    writeFileSync(
      join(dist, "runtime", "wasm-binding.js"),
      "export const assertWasmModuleShape = () => {}; export const createBindingFromWasmModule = module => module;",
    );
    writeFileSync(
      join(root, "redact_secret_wasm_custom.js"),
      'let mode; export default async function initialize(options) { mode = options?.module_or_path instanceof Uint8Array ? "file" : "default"; } export const observedMode = () => mode;',
    );
    writeFileSync(join(root, "redact_secret_wasm_custom_bg.wasm"), new Uint8Array([0, 97, 115, 109, 1, 0, 0, 0]));
    const entry = join(root, "index.js");
    writeFileSync(entry, bundleEntry({ distDir: dist }));
    // The real Node process has every property of the Workers compatibility
    // shim that originally selected the wrong branch.
    assert.equal(typeof process.versions.node, "string");
    for (const [name, userAgent, browser, expected] of [
      ["workers", "Cloudflare-Workers", false, "default"],
      ["node", "Node.js/22", false, "file"],
      ["browser", "synthetic-browser", true, "default"],
    ]) {
      Object.defineProperty(globalThis, "navigator", { configurable: true, value: { userAgent } });
      for (const property of ["window", "document"]) {
        Object.defineProperty(globalThis, property, { configurable: true, value: browser ? {} : undefined });
      }
      const api = await import(`${pathToFileURL(entry).href}?${name}`);
      const module = await api.initialize();
      assert.equal(module.observedMode(), expected, name);
    }
  } finally {
    for (const [name, descriptor] of Object.entries(globals)) {
      if (descriptor) Object.defineProperty(globalThis, name, descriptor);
      else delete globalThis[name];
    }
    rmSync(root, { recursive: true, force: true });
  }
});

/** The catalog, read from the core source the way the CLI manifest is generated from it. */
function catalog() {
  const source = readFileSync(join(REPO_ROOT, "crates", "secret-scan-core", "src", "detectors", "mod.rs"), "utf8");
  const table = source.match(/BUILT_IN_PACKS: &\[\(&str, Pack\)\] = &\[([\s\S]*?)\n\];/);
  assert.ok(table, "BUILT_IN_PACKS not found");
  return [...table[1].matchAll(/\("([a-z0-9-]+)", Pack::(Common|Provider)\)/g)].map(([, id, pack]) => ({
    id,
    pack: pack.toLowerCase(),
    types: [],
    aliases: [],
  }));
}

const fixture = JSON.parse(readFileSync(join(REPO_ROOT, "conformance", "fixtures", "composition-v1.json"), "utf8"));

test("the shared conformance cases resolve to the same canonical ids, documents and identities", () => {
  assert.ok(fixture.cases.length >= 5);
  for (const entry of fixture.cases) {
    const resolved = resolveComposition(parseComposition({ schema: "composition/v1", ...pick(entry) }), catalog());
    assert.deepEqual(resolved.ids, entry.ids);
    assert.equal(resolved.document, entry.canonical);
    assert.equal(resolved.id, entry.id);
    assert.match(resolved.id, /^custom:[0-9a-f]{64}$/);
  }
});

function pick(entry) {
  return { name: entry.name, include: entry.include, pii: entry.pii };
}

test("the canonical order ignores the order as written, and the name and pii flag bind the identity", () => {
  const forward = resolveComposition(
    parseComposition({ schema: "composition/v1", name: "same", include: ["jwt", "github-token"], pii: "none" }),
    catalog(),
  );
  const reverse = resolveComposition(
    parseComposition({ schema: "composition/v1", name: "same", include: ["github-token", "jwt"], pii: "none" }),
    catalog(),
  );
  assert.deepEqual(forward.ids, ["github-token", "jwt"]);
  assert.equal(forward.id, reverse.id);
  const renamed = resolveComposition(
    parseComposition({ schema: "composition/v1", name: "other", include: ["jwt", "github-token"], pii: "none" }),
    catalog(),
  );
  assert.notEqual(forward.id, renamed.id);
  const withPii = resolveComposition(
    parseComposition({ schema: "composition/v1", name: "same", include: ["jwt", "github-token"], pii: "all" }),
    catalog(),
  );
  assert.notEqual(forward.id, withPii.id);
  assert.deepEqual(
    [...forward.ids, ...forward.notIncluded].sort(),
    catalog()
      .map((entry) => entry.id)
      .sort(),
  );
  assert.equal(forward.notIncluded.length, catalog().length - 2);
});

test("every rejected input fails with its fixed code and fixed-syntax path, and echoes nothing", () => {
  for (const entry of fixture.rejected) {
    let error;
    try {
      resolveComposition(parseComposition(entry.composition), catalog());
    } catch (thrown) {
      error = thrown;
    }
    assert.ok(error instanceof CompositionError, JSON.stringify(entry.composition));
    assert.equal(error.code, entry.code);
    assert.equal(error.path, entry.path);
    assert.doesNotMatch(error.message, /no-such-detector|Not An Id|Bad Name/);
  }
  assert.throws(() => parseComposition(null), { code: "WRONG_TYPE" });
  assert.throws(
    () => parseComposition({ schema: "composition/v1", name: "x", include: Array(257).fill("jwt"), pii: "none" }),
    {
      code: "TOO_MANY_DETECTOR_IDS",
    },
  );
});

test("an alias resolves before the duplicate check and is reported", () => {
  const withAlias = catalog().map((entry) => (entry.id === "jwt" ? { ...entry, aliases: ["json-web-token"] } : entry));
  const resolved = resolveComposition(
    parseComposition({ schema: "composition/v1", name: "aliased", include: ["json-web-token"], pii: "none" }),
    withAlias,
  );
  assert.deepEqual(resolved.ids, ["jwt"]);
  assert.deepEqual(resolved.aliasesUsed, [0]);
  assert.throws(
    () =>
      resolveComposition(
        parseComposition({
          schema: "composition/v1",
          name: "aliased",
          include: ["json-web-token", "jwt"],
          pii: "none",
        }),
        withAlias,
      ),
    { code: "DUPLICATE_DETECTOR_ID", path: "include[1]" },
  );
});

test("an unsupported target fails in planning, naming the accepted reason", () => {
  const composition = { schema: "composition/v1", name: "x", include: ["jwt"], pii: "none" };
  for (const target of Object.keys(UNSUPPORTED_TARGETS)) {
    assert.throws(() => planCustomArtifact({ composition, catalog: catalog(), target }), {
      code: "UNSUPPORTED_TARGET",
    });
  }
  assert.throws(() => planCustomArtifact({ composition, catalog: catalog(), target: "wasi" }), {
    code: "UNSUPPORTED_TARGET",
  });
  assert.equal(planCustomArtifact({ composition, catalog: catalog(), target: "wasm" }).ids.length, 1);
});

test("the build fails before it writes a workspace or an artifact, and runs no command, on a bad input", async () => {
  const root = mkdtempSync(join(tmpdir(), "custom-refusal-"));
  try {
    const calls = [];
    const run = (...call) => {
      calls.push(call);
      throw new Error("no command may run before the composition resolves");
    };
    for (const include of [["no-such-detector"], ["jwt", "jwt"], []]) {
      await assert.rejects(
        buildCustomArtifact({
          composition: { schema: "composition/v1", name: "refused", include, pii: "none" },
          catalog: catalog(),
          root,
          outDir: "out",
          run,
        }),
        CompositionError,
      );
    }
    await assert.rejects(
      buildCustomArtifact({
        composition: { schema: "composition/v1", name: "refused", include: ["jwt"], pii: "none" },
        catalog: catalog(),
        target: "cli",
        root,
        outDir: "out",
        run,
      }),
      { code: "UNSUPPORTED_TARGET" },
    );
    assert.deepEqual(calls, []);
    assert.equal(existsSync(join(root, "out")), false);
    assert.equal(existsSync(join(root, "out.work")), false);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("an output directory that is not a previous custom artifact is never overwritten", async () => {
  const root = mkdtempSync(join(tmpdir(), "custom-outdir-"));
  try {
    const { mkdirSync, writeFileSync } = await import("node:fs");
    mkdirSync(join(root, "out"));
    writeFileSync(join(root, "out", "keep.txt"), "mine");
    await assert.rejects(
      buildCustomArtifact({
        composition: { schema: "composition/v1", name: "ok", include: ["jwt"], pii: "none" },
        catalog: catalog(),
        root,
        outDir: "out",
        run: () => {
          throw new Error("must not run");
        },
      }),
      BuildError,
    );
    assert.equal(readFileSync(join(root, "out", "keep.txt"), "utf8"), "mine");
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("the generated leaf names exactly the selected constructors, in canonical order", () => {
  const resolved = resolveComposition(
    parseComposition({
      schema: "composition/v1",
      name: "leaf-check",
      include: ["generic-token", "stripe-token", "jwt"],
      pii: "none",
    }),
    catalog(),
  );
  const source = generateLeafLib(resolved);
  const calls = [...source.matchAll(/composition::([a-z0-9_]+)\(\),/g)].map(([, name]) => name);
  assert.deepEqual(calls, ["stripe_token", "jwt", "generic_token"]);
  assert.ok(!source.includes("with_built_in"), "no standard constructor is named");
  assert.ok(!source.includes("built_in_detectors"), "no table of every detector is named");
  assert.match(source, /Composition::new\(\s*COMPOSITION_NAME,\s*false,/u);
  assert.match(source, new RegExp(resolved.id));
  const withPii = generateLeafLib({ ...resolved, pii: "all" });
  assert.match(withPii, /COMPOSITION_NAME,\s*true,/u);
  const manifest = generateLeafManifest({
    version: "0.0.0",
    coreDir: "/core",
    wasmDir: "/wasm",
    bindgenRequirement: "0.2.1",
    pii: true,
  });
  assert.match(manifest, /default-features = false, features = \["custom", "pii"\]/u);
  assert.match(
    generateLeafManifest({ version: "0.0.0", coreDir: "/c", wasmDir: "/w", bindgenRequirement: "0.2.1", pii: false }),
    /features = \["custom"\]/u,
  );
});

test("every built-in id has a unique constructor name that is a valid Rust identifier", () => {
  const names = catalog().map((entry) => constructorName(entry.id));
  assert.equal(new Set(names).size, names.length);
  for (const name of names) assert.match(name, /^[a-z][a-z0-9_]*$/u);
  // The constructors themselves are pinned by the core's own table test; here the
  // Rust source must declare every one of them.
  const selected = readFileSync(
    join(REPO_ROOT, "crates", "secret-scan-core", "src", "detectors", "selected.rs"),
    "utf8",
  );
  for (const entry of catalog()) {
    assert.ok(selected.includes(`${constructorName(entry.id)} = "${entry.id}",`), `${entry.id} has a constructor row`);
  }
});

test("the catalog reader accepts a full manifest and refuses anything else", () => {
  const manifest = {
    schema: "artifact-manifest/v1",
    detectors: catalog().map(({ id, pack }) => ({ id, pack, types: ["t"], aliases: [] })),
  };
  assert.equal(readCatalog(manifest).length, catalog().length);
  assert.equal(readCatalog(JSON.stringify(manifest))[0].id, "private-key");
  assert.throws(() => readCatalog("not json"), { code: "CATALOG_INVALID" });
  assert.throws(() => readCatalog({ schema: "other", detectors: [] }), { code: "CATALOG_INVALID" });
  assert.throws(() => readCatalog({ schema: "artifact-manifest/v1", detectors: [{ id: "jwt" }, { id: "jwt" }] }), {
    code: "CATALOG_INVALID",
  });
});

test("a lock may add only the generated leaf and must resolve every shared package identically", () => {
  const repository = `[[package]]\nname = "serde"\nversion = "1.0.0"\nsource = "registry+x"\nchecksum = "aa"\n\n[[package]]\nname = "unused"\nversion = "2.0.0"\nsource = "registry+x"\nchecksum = "bb"\n`;
  const same = `[[package]]\nname = "redact-secret-custom-artifact"\nversion = "0.1.0"\n\n[[package]]\nname = "serde"\nversion = "1.0.0"\nsource = "registry+x"\nchecksum = "aa"\n`;
  assert.deepEqual(verifyLockUnchanged(repository, same), []);
  const moved = same.replace('checksum = "aa"', 'checksum = "cc"');
  assert.equal(verifyLockUnchanged(repository, moved).length, 1);
  const added = `${same}\n[[package]]\nname = "surprise"\nversion = "9.9.9"\nsource = "registry+x"\nchecksum = "dd"\n`;
  assert.equal(verifyLockUnchanged(repository, added).length, 1);
});

test("binary inspection finds literals, words and sizes and separates probes from the baseline", () => {
  const full = Buffer.from("\0header ghp_ABC sk_live_ZZZ common-words-here\0\0");
  const custom = Buffer.from("\0header ghp_ABC common-words-here\0");
  assert.ok(containsLiteral(full, "sk_live_"));
  assert.ok(!containsLiteral(custom, "sk_live_"));
  assert.ok(words(full).has("sk_live_ZZZ"));
  assert.ok(printableRuns(full, 4).size > 0);
  assert.ok(sizes(full).raw > sizes(custom).raw);
  const measured = measureElimination(custom, full, {
    probes: [
      { id: "github-token", literals: ["ghp_"], selected: true },
      { id: "stripe-token", literals: ["sk_live_"], selected: false },
    ],
  });
  assert.deepEqual(
    measured.probes.map((p) => [p.id, p.inFull, p.inCustom]),
    [
      ["github-token", true, true],
      ["stripe-token", true, false],
    ],
  );
  assert.equal(measured.words.inFullButNotInCustom, 1);
});

test("the report states the engine floor and canonicalization is a pure function of the resolved ids", () => {
  assert.ok(ENGINE_FLOOR.length >= 5);
  assert.equal(
    canonicalCompositionDocument("n", ["jwt"], "none"),
    '{"include":["jwt"],"name":"n","pii":"none","schema":"composition/v1"}',
  );
});
