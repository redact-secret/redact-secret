/**
 * Drives the public `@redact-secret/core` API against a real install in
 * a clean directory outside this repository, on both JavaScript runtimes.
 * Shared between `scripts/qualify-package-consumer.mjs` (installs packed
 * local tarballs, standing in for a registry `npm install` before the
 * dependency packages are published) and `scripts/verify-registry-install.mjs`
 * (installs the real, published package from the registry, after they are)
 * -- the install source differs, but "does the installed package initialize,
 * scan, sanitize incrementally, and stream correctly" does not.
 */

import { build } from "esbuild";
import { createServer } from "node:http";
import { execFileSync } from "node:child_process";
import { copyFileSync, readFileSync } from "node:fs";
import { cp, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, extname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { assertMatchesFixture } from "./qualify-runtime-fixture.mjs";

export const WASM_SPECIFIER = "@redact-secret/wasm";

const REPOSITORY_ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");

/**
 * The framework-neutral AI-context boundary contract (issue #610): its
 * fixture and the plain-ESM reference runner that replays it. The runner is
 * copied into the clean consumer directory and imports nothing but the
 * installed `@redact-secret/core` API handed to it, so the contract is
 * qualified against the publish-shaped package, not the source tree.
 */
export const AI_CONTEXT_BOUNDARY_FIXTURE = "conformance/fixtures/ai-context-boundary.json";
const AI_CONTEXT_BOUNDARY_RUNNER = "conformance/ai-context-boundary.mjs";
const AI_CONTEXT_BOUNDARY_STAGED = "ai-context-boundary.mjs";

function stageAiContextBoundary(consumerRoot) {
  copyFileSync(
    join(REPOSITORY_ROOT, AI_CONTEXT_BOUNDARY_RUNNER),
    join(consumerRoot, AI_CONTEXT_BOUNDARY_STAGED),
  );
  return JSON.parse(readFileSync(join(REPOSITORY_ROOT, AI_CONTEXT_BOUNDARY_FIXTURE), "utf8"));
}

function assertAiContextBoundary(label, summary, fixture) {
  const expected = { uninitialized: 0, initialized: 0 };
  for (const testCase of fixture.cases) {
    if (testCase.runtimes && !testCase.runtimes.includes("javascript")) continue;
    expected[testCase.phase ?? "initialized"] += 1;
  }
  if (
    summary?.uninitialized?.cases !== expected.uninitialized ||
    summary?.initialized?.cases !== expected.initialized ||
    !(summary.initialized.partitions > 0)
  ) {
    throw new Error(`${label}: AI-context boundary contract replay was incomplete: ${JSON.stringify(summary)}`);
  }
}

const LIMITS = Object.freeze({
  maxInputCodeUnits: 32_768,
  maxBufferedCodeUnits: 16_512,
  maxTokenCodeUnits: 8_192,
  maxMultilineCodeUnits: 16_384,
});

const MIME_TYPES = {
  ".html": "text/html",
  ".js": "text/javascript",
  ".wasm": "application/wasm",
};

const INCREMENTAL_CORPUS_HELPERS = String.raw`
const qualificationEncoder = new TextEncoder();
const qualificationDecoder = new TextDecoder();

function assertQualification(condition, message) {
  if (!condition) throw new Error(message);
}

function assertQualificationEqual(actual, expected, message) {
  const left = JSON.stringify(actual);
  const right = JSON.stringify(expected);
  if (left !== right) throw new Error(message + ": expected " + right + ", got " + left);
}

function byteOffsetToCodeUnitOffset(text, byteOffset) {
  let bytes = 0;
  let codeUnits = 0;
  for (const character of text) {
    if (bytes === byteOffset) return codeUnits;
    const nextBytes = bytes + qualificationEncoder.encode(character).length;
    if (nextBytes > byteOffset) {
      throw new Error("byte offset splits a UTF-8 sequence");
    }
    bytes = nextBytes;
    codeUnits += character.length;
  }
  if (bytes === byteOffset) return codeUnits;
  throw new Error("byte offset is outside the input");
}

function expectedMetadata(fixture) {
  return fixture.expected.map((entry, index) => ({
    id: "finding-" + (index + 1),
    detector: entry.detector,
    type: entry.type,
    confidence: entry.confidence,
    start: byteOffsetToCodeUnitOffsetForFixture(fixture, entry.start),
    end: byteOffsetToCodeUnitOffsetForFixture(fixture, entry.end),
  }));
}

function byteOffsetToCodeUnitOffsetForFixture(fixture, byteOffset) {
  try {
    return byteOffsetToCodeUnitOffset(fixture.input, byteOffset);
  } catch (error) {
    throw new Error(fixture.id + ": invalid expected byte offset " + byteOffset + ": " + String(error && error.message || error));
  }
}

function comparableFinding(finding) {
  return {
    id: finding.id,
    detector: finding.detector,
    type: finding.type,
    confidence: finding.confidence,
    action: finding.action,
    start: finding.start,
    end: finding.end,
  };
}

function compareRun(label, actual, expected) {
  assertQualificationEqual(actual.text, expected.text, label + ": concatenated text");
  assertQualificationEqual(
    actual.findings.map(comparableFinding),
    expected.findings.map(comparableFinding),
    label + ": findings, actions, ordering, identifiers, and absolute ranges",
  );
}

function runStringPartition(api, chunks, limits) {
  const session = api.createIncrementalSanitizer({ limits });
  let text = "";
  const findings = [];
  for (const chunk of chunks) {
    const result = session.append(chunk);
    text += result.text;
    findings.push(...result.findings);
  }
  const finalized = session.finalize();
  text += finalized.text;
  findings.push(...finalized.findings);
  return { text, findings };
}

function isValidStringBoundary(input, index) {
  if (index <= 0 || index >= input.length) return true;
  const before = input.charCodeAt(index - 1);
  const after = input.charCodeAt(index);
  return !(before >= 0xd800 && before <= 0xdbff && after >= 0xdc00 && after <= 0xdfff);
}

async function qualifyIncrementalCorpus(api, corpus, sanitizeByteChunks, limits) {
  assertQualification(corpus.offsetUnit === "utf8-byte", "incremental corpus offset unit changed");
  assertQualification(corpus.fixtures.length >= 16, "incremental corpus unexpectedly shrank");
  const summary = {
    fixtures: corpus.fixtures.length,
    stringPartitions: 0,
    bytePartitions: 0,
    findings: 0,
  };

  for (const fixture of corpus.fixtures) {
    const reference = api.scanAndRedact(fixture.input);
    assertQualificationEqual(reference.text, fixture.text, fixture.id + ": canonical redacted text");
    const metadata = expectedMetadata(fixture);
    assertQualificationEqual(
      reference.findings.map(({ id, detector, type, confidence, start, end }) => ({
        id,
        detector,
        type,
        confidence,
        start,
        end,
      })),
      metadata,
      fixture.id + ": canonical finding metadata",
    );
    summary.findings += reference.findings.length;

    for (let boundary = 0; boundary <= fixture.input.length; boundary += 1) {
      if (!isValidStringBoundary(fixture.input, boundary)) continue;
      compareRun(
        fixture.id + " valid UTF-16 boundary " + boundary,
        runStringPartition(api, [
          fixture.input.slice(0, boundary),
          fixture.input.slice(boundary),
        ], limits),
        reference,
      );
      summary.stringPartitions += 1;
    }
    compareRun(
      fixture.id + " one chunk per valid UTF-16 segment",
      runStringPartition(api, Array.from(fixture.input), limits),
      reference,
    );
    summary.stringPartitions += 1;

    const bytes = qualificationEncoder.encode(fixture.input);
    for (let boundary = 0; boundary <= bytes.length; boundary += 1) {
      compareRun(
        fixture.id + " UTF-8 byte boundary " + boundary,
        await sanitizeByteChunks([bytes.slice(0, boundary), bytes.slice(boundary)]),
        reference,
      );
      summary.bytePartitions += 1;
    }
    compareRun(
      fixture.id + " one chunk per UTF-8 byte",
      await sanitizeByteChunks(
        Array.from({ length: bytes.length }, (_, index) => bytes.slice(index, index + 1)),
      ),
      reference,
    );
    summary.bytePartitions += 1;
  }
  return summary;
}
`;

export function qualifyNode(
  consumerRoot,
  fixture,
  expectedVersion,
  integrationFixtures,
  incrementalCorpus,
) {
  const source = [
    "const { Readable } = await import('node:stream');",
    "const { artifact, createIncrementalSanitizer, initialize, scan, scanAndRedact, VERSION } = await import('@redact-secret/core');",
    "const { createNodeStreamSanitizer } = await import('@redact-secret/core/node-stream');",
    "const { createServerHandler } = await import('./safe-integration/server.mjs');",
    `const { runAiContextBoundaryConformance } = await import('./${AI_CONTEXT_BOUNDARY_STAGED}');`,
    INCREMENTAL_CORPUS_HELPERS,
    "const aiContextBoundaryFixture = JSON.parse(process.env.REDACT_SECRET_AI_CONTEXT_BOUNDARY);",
    "const aiContextBoundaryUninitialized = runAiContextBoundaryConformance({ createIncrementalSanitizer, scanAndRedact }, aiContextBoundaryFixture, { phase: 'uninitialized' });",
    "await initialize();",
    "const aiContextBoundaryInitialized = runAiContextBoundaryConformance({ createIncrementalSanitizer, scanAndRedact }, aiContextBoundaryFixture, { phase: 'initialized' });",
    "const fixtureInput = process.env.REDACT_SECRET_QUALIFICATION_INPUT;",
    "if (fixtureInput === undefined) throw new Error('qualification input is missing');",
    "const integrationFixtures = JSON.parse(process.env.REDACT_SECRET_INTEGRATION_FIXTURES);",
    "const incrementalCorpus = JSON.parse(process.env.REDACT_SECRET_INCREMENTAL_CORPUS);",
    "const findings = scan(fixtureInput);",
    `const limits = ${JSON.stringify(LIMITS)};`,
    "const incrementalInput = `${fixtureInput}\n`;",
    "const split = Math.floor(incrementalInput.length / 2);",
    "const session = createIncrementalSanitizer({ limits });",
    "const incrementalText = session.append(incrementalInput.slice(0, split)).text + session.append(incrementalInput.slice(split)).text + session.finalize().text;",
    "const expectedIncrementalText = scanAndRedact(incrementalInput).text;",
    "const streamInput = `🔑 lead\n${fixtureInput}\n🔒 tail`;",
    "const encoded = Buffer.from(streamInput, 'utf8');",
    "const transform = createNodeStreamSanitizer({ limits });",
    "const output = [];",
    "for await (const chunk of Readable.from([encoded.subarray(0, 1), encoded.subarray(1)]).pipe(transform)) output.push(chunk);",
    "const streamText = Buffer.concat(output).toString('utf8');",
    "async function sanitizeByteChunks(chunks) {",
    "  const transform = createNodeStreamSanitizer({ limits });",
    "  const byteOutput = [];",
    "  for await (const chunk of Readable.from(chunks).pipe(transform)) byteOutput.push(chunk);",
    "  return { text: Buffer.concat(byteOutput).toString('utf8'), findings: transform.findings };",
    "}",
    "const incrementalCorpusSummary = await qualifyIncrementalCorpus({ createIncrementalSanitizer, scanAndRedact }, incrementalCorpus, sanitizeByteChunks, limits);",
    "const forwarded = [];",
    "const events = [];",
    "const body = (content) => new TextEncoder().encode(JSON.stringify({ content }));",
    "const handler = await createServerHandler({ forward: async ({ content }) => forwarded.push(content), record: (event) => events.push(event) });",
    "const clean = await handler(body('ordinary text'));",
    "const redacted = await handler(body(integrationFixtures.redact));",
    "const warned = await handler(body(integrationFixtures.warn));",
    "const blocked = await handler(body(integrationFixtures.block));",
    "const failed = await handler(body(String.fromCharCode(0xd800)));",
    "const limitedHandler = await createServerHandler({ limits: { maxTransportBytes: 4 }, forward: async () => { throw new Error('limit reached downstream'); } });",
    "const limited = await limitedHandler(body('ordinary text'));",
    "const eventText = JSON.stringify(events);",
    "const redactedMatch = integrationFixtures.redact.slice(redacted.findings[0].start, redacted.findings[0].end);",
    "const safeIntegration = { clean: clean.code === 'OK', redacted: redacted.code === 'OK' && forwarded[1] !== integrationFixtures.redact && !forwarded[1].includes(redactedMatch), warned: warned.code === 'SECRET_WARNING', blocked: blocked.code === 'SECRET_BLOCKED', failedClosed: failed.code === 'SCAN_FAILED', limited: limited.code === 'TRANSPORT_LIMIT_EXCEEDED', downstreamCalls: forwarded.length === 2, safeEvents: !Object.values(integrationFixtures).some((input) => eventText.includes(input)) };",
    "console.log(JSON.stringify({ version: VERSION, artifact: artifact(), findings, incremental: incrementalText === expectedIncrementalText, incrementalCorpus: incrementalCorpusSummary, stream: streamText === scanAndRedact(streamInput).text, streamFindings: transform.findings.length, safeIntegration, aiContextBoundary: { uninitialized: aiContextBoundaryUninitialized, initialized: aiContextBoundaryInitialized } }));",
  ].join("\n");
  const aiContextBoundaryFixture = stageAiContextBoundary(consumerRoot);
  const output = execFileSync(
    process.execPath,
    ["--input-type=module", "--eval", source],
    {
      cwd: consumerRoot,
      encoding: "utf8",
      env: {
        ...process.env,
        REDACT_SECRET_QUALIFICATION_INPUT: fixture.input,
        REDACT_SECRET_INTEGRATION_FIXTURES: JSON.stringify(
          Object.fromEntries(
            Object.entries(integrationFixtures).map(([kind, entry]) => [kind, entry.input]),
          ),
        ),
        REDACT_SECRET_INCREMENTAL_CORPUS: JSON.stringify(incrementalCorpus),
        REDACT_SECRET_AI_CONTEXT_BOUNDARY: JSON.stringify(aiContextBoundaryFixture),
      },
    },
  );
  const result = JSON.parse(output);
  if (result.version !== expectedVersion) {
    throw new Error(
      `Node lane version mismatch: reports ${result.version}, expected ${expectedVersion}`,
    );
  }
  // The WebAssembly fallback (`decision-add-node-wasm-fallback`) would let
  // every check below pass on a host whose native addon never installed or
  // loaded, so this lane only qualifies the addon if the addon is what ran.
  if (result.artifact !== "addon") {
    throw new Error(
      `Node lane: expected the native addon to load, but artifact() reports ${result.artifact}`,
    );
  }
  if (result.findings.length !== 1) {
    throw new Error(
      `Node lane: expected exactly one finding for fixture ${fixture.id}, got ${result.findings.length}`,
    );
  }
  assertMatchesFixture(result.findings[0], fixture);
  if (!result.incremental || !result.stream || result.streamFindings < 1) {
    throw new Error("Node lane: installed incremental or stream API diverged");
  }
  if (result.incrementalCorpus?.fixtures !== incrementalCorpus.fixtures.length) {
    throw new Error(
      `Node lane: incremental corpus replay was incomplete: ${JSON.stringify(result.incrementalCorpus)}`,
    );
  }
  if (
    Object.values(result.safeIntegration ?? {}).length !== 8 ||
    !Object.values(result.safeIntegration).every(Boolean)
  ) {
    throw new Error(
      `Node lane: safe integration example diverged: ${JSON.stringify(result.safeIntegration)}`,
    );
  }
  assertAiContextBoundary("Node lane", result.aiContextBoundary, aiContextBoundaryFixture);
  return {
    initialize: "passed",
    scan: "passed",
    incremental: "passed",
    incrementalCorpus: "passed",
    stream: "passed",
    safeIntegration: "passed",
    aiContextBoundary: "passed",
    incrementalCorpusSummary: result.incrementalCorpus,
    aiContextBoundarySummary: result.aiContextBoundary,
  };
}

async function bundleForBrowser(consumerRoot) {
  const result = await build({
    bundle: true,
    format: "esm",
    platform: "browser",
    conditions: ["browser", "import"],
    alias: {
      "#native": join(
        consumerRoot,
        "node_modules",
        "@redact-secret",
        "core",
        "dist",
        "runtime",
        "browser.js",
      ),
    },
    external: [WASM_SPECIFIER],
    stdin: {
      contents: [
        `import { createIncrementalSanitizer, initialize, scan, scanAndRedact, VERSION } from "@redact-secret/core";`,
        `import { createWebStreamSanitizer } from "@redact-secret/core/web-stream";`,
        `import { prepareBrowserSubmission } from "./safe-integration/browser.mjs";`,
        `import { runAiContextBoundaryConformance } from "./${AI_CONTEXT_BOUNDARY_STAGED}";`,
        "window.__secretScan = { createIncrementalSanitizer, createWebStreamSanitizer, initialize, prepareBrowserSubmission, runAiContextBoundaryConformance, scan, scanAndRedact, VERSION };",
      ].join("\n"),
      loader: "js",
      resolveDir: consumerRoot,
      sourcefile: "browser-consumer-qualify-entry.js",
    },
    write: false,
  });
  if (result.errors.length > 0) {
    throw new Error(`esbuild failed: ${JSON.stringify(result.errors)}`);
  }
  return result.outputFiles[0].text;
}

async function writeHarness(
  root,
  bundleText,
  installedWasmDir,
  fixture,
  integrationFixtures,
  incrementalCorpus,
  aiContextBoundaryFixture,
) {
  await writeFile(join(root, "bundle.js"), bundleText);
  await cp(installedWasmDir, join(root, "wasm"), { recursive: true });
  const importMap = { imports: { [WASM_SPECIFIER]: "/wasm/redact_secret_wasm.js" } };
  const html = `<!doctype html>
<meta charset="utf-8">
<script type="importmap">${JSON.stringify(importMap)}</script>
<script type="module">
  import "/bundle.js";
  ${INCREMENTAL_CORPUS_HELPERS}
  (async () => {
    try {
      const aiContextBoundaryFixture = ${JSON.stringify(aiContextBoundaryFixture)};
      const aiContextBoundaryUninitialized = window.__secretScan.runAiContextBoundaryConformance(window.__secretScan, aiContextBoundaryFixture, { phase: "uninitialized" });
      await window.__secretScan.initialize();
      const aiContextBoundaryInitialized = window.__secretScan.runAiContextBoundaryConformance(window.__secretScan, aiContextBoundaryFixture, { phase: "initialized" });
      const findings = window.__secretScan.scan(${JSON.stringify(fixture.input)});
      const limits = ${JSON.stringify(LIMITS)};
      const incrementalCorpus = ${JSON.stringify(incrementalCorpus)};
      const incrementalInput = ${JSON.stringify(`${fixture.input}\n`)};
      const split = Math.floor(incrementalInput.length / 2);
      const session = window.__secretScan.createIncrementalSanitizer({ limits });
      const incrementalText = session.append(incrementalInput.slice(0, split)).text
        + session.append(incrementalInput.slice(split)).text
        + session.finalize().text;
      const streamInput = ${JSON.stringify(`🔑 lead\n${fixture.input}\n🔒 tail`)};
      const encoded = new TextEncoder().encode(streamInput);
      const source = new ReadableStream({
        start(controller) {
          controller.enqueue(encoded.slice(0, 1));
          controller.enqueue(encoded.slice(1));
          controller.close();
        },
      });
      const transform = window.__secretScan.createWebStreamSanitizer({ limits });
      const reader = source.pipeThrough(transform).getReader();
      const output = [];
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        output.push(value);
      }
      const streamText = output.join("");
      async function sanitizeByteChunks(chunks) {
        const source = new ReadableStream({
          start(controller) {
            for (const chunk of chunks) controller.enqueue(chunk);
            controller.close();
          },
        });
        const byteTransform = window.__secretScan.createWebStreamSanitizer({ limits });
        const byteReader = source.pipeThrough(byteTransform).getReader();
        const byteOutput = [];
        while (true) {
          const { done, value } = await byteReader.read();
          if (done) break;
          byteOutput.push(value);
        }
        return { text: byteOutput.join(""), findings: byteTransform.findings };
      }
      const incrementalCorpusSummary = await qualifyIncrementalCorpus(window.__secretScan, incrementalCorpus, sanitizeByteChunks, limits);
      const integrationInputs = ${JSON.stringify(
        Object.fromEntries(
          Object.entries(integrationFixtures).map(([kind, entry]) => [kind, entry.input]),
        ),
      )};
      const clean = await window.__secretScan.prepareBrowserSubmission("ordinary text");
      const redacted = await window.__secretScan.prepareBrowserSubmission(integrationInputs.redact);
      const warned = await window.__secretScan.prepareBrowserSubmission(integrationInputs.warn);
      const blocked = await window.__secretScan.prepareBrowserSubmission(integrationInputs.block);
      const safeIntegration = {
        clean: clean.state === "ready",
        redacted: redacted.state === "ready"
          && !redacted.request.body.includes(integrationInputs.redact.slice(
            redacted.findings[0].start,
            redacted.findings[0].end,
          )),
        warned: warned.state === "warning" && warned.request === undefined,
        blocked: blocked.state === "blocked" && blocked.request === undefined,
      };
      window.__qualifyResult = {
        ok: true,
        version: window.__secretScan.VERSION,
        findings,
        incremental: incrementalText === window.__secretScan.scanAndRedact(incrementalInput).text,
        incrementalCorpus: incrementalCorpusSummary,
        stream: streamText === window.__secretScan.scanAndRedact(streamInput).text,
        streamFindings: transform.findings.length,
        safeIntegration,
        aiContextBoundary: { uninitialized: aiContextBoundaryUninitialized, initialized: aiContextBoundaryInitialized },
      };
    } catch (error) {
      window.__qualifyResult = { ok: false, error: String((error && error.stack) || error) };
    }
  })();
</script>
`;
  await writeFile(join(root, "harness.html"), html);
}

function serveDirectory(root) {
  return createServer(async (req, res) => {
    try {
      const path = req.url === "/" ? "/harness.html" : req.url;
      const data = await readFile(join(root, path));
      res.writeHead(200, { "content-type": MIME_TYPES[extname(path)] ?? "application/octet-stream" });
      res.end(data);
    } catch {
      res.writeHead(404);
      res.end();
    }
  });
}

export async function qualifyBrowser(
  consumerRoot,
  fixture,
  expectedVersion,
  engine = "chromium",
  integrationFixtures,
  incrementalCorpus,
) {
  const aiContextBoundaryFixture = stageAiContextBoundary(consumerRoot);
  const bundleText = await bundleForBrowser(consumerRoot);
  const harnessRoot = await mkdtemp(join(tmpdir(), "redact-secret-consumer-browser-"));
  const playwright = await import("playwright");
  const browserType = playwright[engine];
  if (browserType === undefined || typeof browserType.launch !== "function") {
    throw new Error(`Browser lane: unsupported engine ${engine}`);
  }

  let server;
  let browser;
  try {
    await writeHarness(
      harnessRoot,
      bundleText,
      join(consumerRoot, "node_modules", WASM_SPECIFIER),
      fixture,
      integrationFixtures,
      incrementalCorpus,
      aiContextBoundaryFixture,
    );

    server = serveDirectory(harnessRoot);
    await new Promise((resolve, reject) => {
      server.once("error", reject);
      server.listen(0, "127.0.0.1", resolve);
    });
    const { port } = server.address();

    browser = await browserType.launch();
    const page = await browser.newPage();
    const consoleErrors = [];
    page.on("pageerror", (error) => consoleErrors.push(String(error)));
    await page.goto(`http://127.0.0.1:${port}/harness.html`);
    await page.waitForFunction(() => window.__qualifyResult !== undefined, { timeout: 10_000 });
    const result = await page.evaluate(() => window.__qualifyResult);

    if (consoleErrors.length > 0) {
      throw new Error(`Browser lane: uncaught page errors: ${consoleErrors.join("; ")}`);
    }
    if (!result.ok) {
      throw new Error(`Browser lane harness failed: ${result.error}`);
    }
    if (result.version !== expectedVersion) {
      throw new Error(
        `Browser lane version mismatch: reports ${result.version}, expected ${expectedVersion}`,
      );
    }
    if (result.findings.length !== 1) {
      throw new Error(
        `Browser lane: expected exactly one finding for fixture ${fixture.id}, got ${result.findings.length}`,
      );
    }
    assertMatchesFixture(result.findings[0], fixture);
    if (!result.incremental || !result.stream || result.streamFindings < 1) {
      throw new Error(
        `Browser lane (${engine}): installed incremental or stream API diverged`,
      );
    }
    if (result.incrementalCorpus?.fixtures !== incrementalCorpus.fixtures.length) {
      throw new Error(
        `Browser lane (${engine}): incremental corpus replay was incomplete: ${JSON.stringify(result.incrementalCorpus)}`,
      );
    }
    if (
      Object.values(result.safeIntegration ?? {}).length !== 4 ||
      !Object.values(result.safeIntegration).every(Boolean)
    ) {
      throw new Error(
        `Browser lane (${engine}): safe integration example diverged: ${JSON.stringify(result.safeIntegration)}`,
      );
    }
    assertAiContextBoundary(`Browser lane (${engine})`, result.aiContextBoundary, aiContextBoundaryFixture);
    return {
      initialize: "passed",
      scan: "passed",
      incremental: "passed",
      incrementalCorpus: "passed",
      stream: "passed",
      safeIntegration: "passed",
      aiContextBoundary: "passed",
      incrementalCorpusSummary: result.incrementalCorpus,
      aiContextBoundarySummary: result.aiContextBoundary,
      engine,
      engineVersion: browser.version(),
    };
  } finally {
    await browser?.close();
    await new Promise((resolve) => (server ? server.close(resolve) : resolve()));
    await rm(harnessRoot, { recursive: true, force: true });
  }
}
