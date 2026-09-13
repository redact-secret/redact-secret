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
import { cp, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { extname, join } from "node:path";

import { assertMatchesFixture } from "./qualify-runtime-fixture.mjs";

export const WASM_SPECIFIER = "@redact-secret/wasm";

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

export function qualifyNode(
  consumerRoot,
  fixture,
  expectedVersion,
  integrationFixtures,
) {
  const source = [
    "const { Readable } = await import('node:stream');",
    "const { createIncrementalSanitizer, initialize, scan, scanAndRedact, VERSION } = await import('@redact-secret/core');",
    "const { createNodeStreamSanitizer } = await import('@redact-secret/core/node-stream');",
    "const { createServerHandler } = await import('./safe-integration/server.mjs');",
    "await initialize();",
    "const fixtureInput = process.env.REDACT_SECRET_QUALIFICATION_INPUT;",
    "if (fixtureInput === undefined) throw new Error('qualification input is missing');",
    "const integrationFixtures = JSON.parse(process.env.REDACT_SECRET_INTEGRATION_FIXTURES);",
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
    "console.log(JSON.stringify({ version: VERSION, findings, incremental: incrementalText === expectedIncrementalText, stream: streamText === scanAndRedact(streamInput).text, streamFindings: transform.findings.length, safeIntegration }));",
  ].join("\n");
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
      },
    },
  );
  const result = JSON.parse(output);
  if (result.version !== expectedVersion) {
    throw new Error(
      `Node lane version mismatch: reports ${result.version}, expected ${expectedVersion}`,
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
  if (
    Object.values(result.safeIntegration ?? {}).length !== 8 ||
    !Object.values(result.safeIntegration).every(Boolean)
  ) {
    throw new Error(
      `Node lane: safe integration example diverged: ${JSON.stringify(result.safeIntegration)}`,
    );
  }
  return {
    initialize: "passed",
    scan: "passed",
    incremental: "passed",
    stream: "passed",
    safeIntegration: "passed",
  };
}

async function bundleForBrowser(consumerRoot) {
  const result = await build({
    bundle: true,
    format: "esm",
    platform: "browser",
    external: [WASM_SPECIFIER],
    stdin: {
      contents: [
        `import { createIncrementalSanitizer, initialize, scan, scanAndRedact, VERSION } from "@redact-secret/core";`,
        `import { createWebStreamSanitizer } from "@redact-secret/core/web-stream";`,
        `import { prepareBrowserSubmission } from "./safe-integration/browser.mjs";`,
        "window.__secretScan = { createIncrementalSanitizer, createWebStreamSanitizer, initialize, prepareBrowserSubmission, scan, scanAndRedact, VERSION };",
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
) {
  await writeFile(join(root, "bundle.js"), bundleText);
  await cp(installedWasmDir, join(root, "wasm"), { recursive: true });
  const importMap = { imports: { [WASM_SPECIFIER]: "/wasm/redact_secret_wasm.js" } };
  const html = `<!doctype html>
<script type="importmap">${JSON.stringify(importMap)}</script>
<script type="module">
  import "/bundle.js";
  (async () => {
    try {
      await window.__secretScan.initialize();
      const findings = window.__secretScan.scan(${JSON.stringify(fixture.input)});
      const limits = ${JSON.stringify(LIMITS)};
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
        stream: streamText === window.__secretScan.scanAndRedact(streamInput).text,
        streamFindings: transform.findings.length,
        safeIntegration,
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
) {
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
    if (
      Object.values(result.safeIntegration ?? {}).length !== 4 ||
      !Object.values(result.safeIntegration).every(Boolean)
    ) {
      throw new Error(
        `Browser lane (${engine}): safe integration example diverged: ${JSON.stringify(result.safeIntegration)}`,
      );
    }
    return {
      initialize: "passed",
      scan: "passed",
      incremental: "passed",
      stream: "passed",
      safeIntegration: "passed",
      engine,
      engineVersion: browser.version(),
    };
  } finally {
    await browser?.close();
    await new Promise((resolve) => (server ? server.close(resolve) : resolve()));
    await rm(harnessRoot, { recursive: true, force: true });
  }
}
