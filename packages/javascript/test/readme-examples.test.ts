import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const PACKAGE_ROOT = fileURLToPath(new URL("..", import.meta.url));
const README = readFileSync(join(PACKAGE_ROOT, "README.md"), "utf8");
const STREAMING_GUIDE = readFileSync(
  join(PACKAGE_ROOT, "..", "..", "docs", "guides", "streaming.md"),
  "utf8",
);
const TSC = join(PACKAGE_ROOT, "..", "..", "node_modules", "typescript", "bin", "tsc");

/** Runs `tsc` over `project` and returns its diagnostics, empty when clean. */
function typeCheck(project: string): string {
  try {
    return execFileSync(process.execPath, [TSC, "--project", project], {
      cwd: PACKAGE_ROOT,
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
    });
  } catch (error) {
    const { stdout, stderr } = error as { stdout?: string; stderr?: string };
    return `${stdout ?? ""}${stderr ?? ""}` || String(error);
  }
}

/** Every fenced ` ```ts ` block in the README, in document order. */
function typeScriptExamples(document = README): readonly string[] {
  return [...document.matchAll(/```ts\n([\s\S]*?)```/g)].map(
    ([, body]) => body ?? "",
  );
}

/**
 * The text of `dist/<declarationPath>`, plus the text of every `.d.ts` it
 * re-exports from via `export * from "./foo.js"`, recursively: a name a
 * declaration file exposes only through such a re-export (e.g. `index.d.ts`
 * re-exporting `entry-core.d.ts`'s types) would otherwise never appear in
 * the literal text this test scans for it.
 */
function declaredText(declarationPath: string, seen = new Set<string>()): string {
  if (seen.has(declarationPath)) return "";
  seen.add(declarationPath);

  const absolute = join(PACKAGE_ROOT, "dist", declarationPath);
  const text = readFileSync(absolute, "utf8");
  const directory = declarationPath.includes("/")
    ? declarationPath.slice(0, declarationPath.lastIndexOf("/") + 1)
    : "";

  let combined = text;
  for (const [, specifier] of text.matchAll(
    /export \* from "\.\/([^"]+)\.js"/g,
  )) {
    combined += declaredText(`${directory}${specifier}.d.ts`, seen);
  }
  return combined;
}

/** Every name a README example imports from `subpath` of the package. */
function importedNames(example: string, subpath = ""): readonly string[] {
  const names: string[] = [];
  const pattern = new RegExp(
    `import(?:\\s+type)?\\s+\\{([^}]*)\\}\\s+from\\s+"@redact-secret/core${subpath}"`,
    "g",
  );
  for (const [, clause] of example.matchAll(pattern)) {
    for (const name of (clause ?? "").split(",")) {
      const trimmed = name.trim();
      if (trimmed !== "") names.push(trimmed);
    }
  }
  return names;
}

describe("README examples", () => {
  it("documents examples for supported whole-input capabilities", () => {
    const examples = typeScriptExamples();
    const imported = new Set(
      examples.flatMap((example) => importedNames(example)),
    );

    expect(examples.length).toBeGreaterThan(0);
    for (const name of [
      "initialize",
      "scan",
      "redact",
      "scanAndRedact",
      "typedPlaceholderFormatter",
      "SecretScanError",
      "RANGE_UNIT",
    ]) {
      expect(imported).toContain(name);
    }
  });

  it("documents working Node incremental examples", () => {
    expect(README).toContain("The Node artifact builds a real incremental session");
    for (const name of ["createIncrementalSanitizer", "createNodeStreamSanitizer"]) {
      expect(README).toContain(`\`${name}\``);
      expect(typeScriptExamples().some((example) => example.includes(`${name}(`))).toBe(true);
    }
    expect(README).toContain("@redact-secret/core/node-stream");
  });

  it("documents working browser incremental and stream examples", () => {
    expect(README).toContain("builds the same kind of session");
    for (const name of ["createIncrementalSanitizer", "createWebStreamSanitizer"]) {
      expect(README).toContain(`\`${name}\``);
      expect(typeScriptExamples().some((example) => example.includes(`${name}(`))).toBe(true);
    }
    expect(README).toContain("@redact-secret/core/web-stream");
  });

  it("keeps the repository streaming guide on the public JavaScript API", () => {
    expect(STREAMING_GUIDE).toContain("createIncrementalSanitizer");
    expect(STREAMING_GUIDE).toContain("createNodeStreamSanitizer");
    expect(typeScriptExamples(STREAMING_GUIDE).length).toBeGreaterThan(0);
  });

  it("imports only names the package actually exports", async () => {
    for (const [subpath, declarations] of [
      ["", "index.d.ts"],
      ["/node-stream", "adapters/node-stream.d.ts"],
      ["/web-stream", "adapters/web-stream.d.ts"],
    ]) {
      const module = `@redact-secret/core${subpath}`;
      const publicApi = (await import(module)) as Record<string, unknown>;
      const declared = declaredText(declarations ?? "");

      for (const name of new Set(
        typeScriptExamples().flatMap((example) =>
          importedNames(example, subpath),
        ),
      )) {
        const exported = name in publicApi || declared.includes(name);
        expect(exported, `${module} imports "${name}"`).toBe(true);
      }
    }
  });

  it("type-checks every example against the published declarations", () => {
    // The examples must compile inside the package so that
    // `@redact-secret/core` resolves through the same `exports` map a
    // consumer uses, rather than through a relative path into `src/`.
    const scratch = mkdtempSync(join(PACKAGE_ROOT, ".readme-examples-"));
    try {
      const sources: string[] = [];
      [...typeScriptExamples(), ...typeScriptExamples(STREAMING_GUIDE)].forEach((example, index) => {
        const name = `example-${index}.ts`;
        writeFileSync(
          join(scratch, name),
          `${example}\nexport {};\n`,
        );
        sources.push(name);
      });
      writeFileSync(
        join(scratch, "tsconfig.json"),
        `${JSON.stringify(
          {
            extends: "../tsconfig.json",
            compilerOptions: {
              rootDir: ".",
              noEmit: true,
              declaration: false,
              lib: ["ES2022", "DOM"],
              // The Node adapter's own example needs `node:stream/promises`.
              // That the Web adapter and the root export resolve nothing
              // Node-only is proved by the browser bundle tests, not here.
              types: ["node"],
            },
            include: ["./*.ts"],
          },
          null,
          2,
        )}\n`,
      );

      expect(sources.length).toBeGreaterThan(0);
      const diagnostics = typeCheck(join(scratch, "tsconfig.json"));

      expect(diagnostics).toBe("");
    } finally {
      rmSync(scratch, { recursive: true, force: true });
    }
  });
});
