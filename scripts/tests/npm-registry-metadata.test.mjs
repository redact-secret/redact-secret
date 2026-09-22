import { test } from "node:test";
import assert from "node:assert/strict";
import {
  describePublication,
  listedInPackument,
  viewPublished,
  waitForInstallable,
  waitForPublished,
  waitForVisible,
} from "../npm-registry-metadata.mjs";

const name = "@redact-secret/test";
const version = "0.1.0-beta.1";
const metadata = { name, version, dist: { shasum: "a".repeat(40) } };
test("uses exact version endpoint without aggregate metadata or credentials", async () => {
  assert.deepEqual(await viewPublished(name, version, async (url, options) => {
    assert.equal(url.origin, "https://registry.npmjs.org");
    assert.equal(url.pathname, "/%40redact-secret%2Ftest/0.1.0-beta.1");
    assert.ok(url.searchParams.has("release_check"));
    assert.deepEqual(options.headers, { "Cache-Control": "no-cache" });
    return Response.json(metadata);
  }), metadata);
});
test("only 404 is unpublished; authorization and server errors fail closed", async () => {
  assert.equal(await viewPublished(name, version, async () => new Response(null, { status: 404 })), undefined);
  for (const status of [401, 403, 429, 500]) {
    await assert.rejects(viewPublished(name, version, async () => new Response(null, { status })), /registry returned HTTP/);
  }
});
test("rejects wrong package, version, and absent checksum", async () => {
  for (const data of [{ ...metadata, name: "wrong" }, { ...metadata, version: "wrong" }, { ...metadata, dist: {} }]) {
    await assert.rejects(viewPublished(name, version, async () => Response.json(data)), /invalid registry metadata/);
  }
});

test("with no expected shasum, waitForPublished is a single unretried read", async () => {
  let calls = 0;
  const request = async () => {
    calls += 1;
    return new Response(null, { status: 404 });
  };
  assert.equal(await waitForPublished(name, version, { request, pollIntervalMs: 0 }), undefined);
  assert.equal(calls, 1);
});

test("waitForPublished keeps polling through 404s, exactly like a mismatch, until the shasum matches", async () => {
  let calls = 0;
  const staleMetadata = { ...metadata, dist: { shasum: "b".repeat(40) } };
  const request = async () => {
    calls += 1;
    if (calls === 1) return new Response(null, { status: 404 });
    if (calls === 2) return Response.json(staleMetadata);
    return Response.json(metadata);
  };
  const result = await waitForPublished(name, version, {
    request,
    expectedShasum: metadata.dist.shasum,
    pollIntervalMs: 0,
  });
  assert.deepEqual(result, metadata);
  assert.equal(calls, 3);
});

test("waitForPublished throws distinct errors for never-visible vs. never-matching once the deadline passes, naming the timeout", async () => {
  const neverVisible = async () => new Response(null, { status: 404 });
  await assert.rejects(
    waitForPublished(name, version, {
      request: neverVisible,
      expectedShasum: metadata.dist.shasum,
      pollIntervalMs: 0,
      maxWaitMs: 0,
    }),
    /not visible on the registry after waiting 0ms for publish propagation/,
  );

  const staleMetadata = { ...metadata, dist: { shasum: "b".repeat(40) } };
  const alwaysStale = async () => Response.json(staleMetadata);
  await assert.rejects(
    waitForPublished(name, version, {
      request: alwaysStale,
      expectedShasum: metadata.dist.shasum,
      pollIntervalMs: 0,
      maxWaitMs: 0,
    }),
    /registry checksum still does not match qualified content after waiting 0ms \(saw b+, expected a+\)/,
  );
});

test("waitForVisible keeps polling through 404s until the version is visible with any content -- a simulated slow-registry publish", async () => {
  let calls = 0;
  const request = async () => {
    calls += 1;
    if (calls < 3) return new Response(null, { status: 404 });
    return Response.json(metadata);
  };
  const result = await waitForVisible(name, version, { request, pollIntervalMs: 0 });
  assert.deepEqual(result, metadata);
  assert.equal(calls, 3);
});

test("waitForVisible fails closed, naming the timeout, once the deadline passes with nothing visible", async () => {
  const neverVisible = async () => new Response(null, { status: 404 });
  await assert.rejects(
    waitForVisible(name, version, { request: neverVisible, pollIntervalMs: 0, maxWaitMs: 0 }),
    /not visible on the registry after waiting 0ms for publish propagation/,
  );
});

// Issue #614: beta.5 and beta.6 lost a clean release to a registry that was
// still serving 404 when a successful publish's window closed.
test("a registry slower than the window does not fail a publish npm accepted", async () => {
  const neverVisibleInWindow = async () => new Response(null, { status: 404 });
  const result = await waitForPublished(name, version, {
    request: neverVisibleInWindow,
    expectedShasum: metadata.dist.shasum,
    publishAccepted: true,
    pollIntervalMs: 0,
    maxWaitMs: 0,
  });
  assert.deepEqual(result, { name, version, dist: { shasum: metadata.dist.shasum }, pending: true });
  assert.match(describePublication(name, version, result), /npm accepted the publish of shasum a+/);
  assert.match(describePublication(name, version, metadata), /published and verified \(shasum a+\)/);
});

test("a visible content mismatch still fails even when npm accepted the publish", async () => {
  const staleMetadata = { ...metadata, dist: { shasum: "b".repeat(40) } };
  await assert.rejects(
    waitForPublished(name, version, {
      request: async () => Response.json(staleMetadata),
      expectedShasum: metadata.dist.shasum,
      publishAccepted: true,
      pollIntervalMs: 0,
      maxWaitMs: 0,
    }),
    /registry checksum still does not match qualified content/,
  );
});

test("a registry error still fails closed when npm accepted the publish", async () => {
  await assert.rejects(
    waitForPublished(name, version, {
      request: async () => new Response(null, { status: 500 }),
      expectedShasum: metadata.dist.shasum,
      publishAccepted: true,
      pollIntervalMs: 0,
      maxWaitMs: 0,
    }),
    /registry returned HTTP 500/,
  );
});

test("listedInPackument reads the abbreviated install packument", async () => {
  const listed = await listedInPackument(name, version, async (url, options) => {
    assert.equal(url.pathname, "/%40redact-secret%2Ftest");
    assert.equal(options.headers.Accept, "application/vnd.npm.install-v1+json");
    return Response.json({ name, versions: { [version]: {} } });
  });
  assert.equal(listed, true);
  assert.equal(await listedInPackument(name, version, async () => Response.json({ name, versions: {} })), false);
  assert.equal(await listedInPackument(name, version, async () => new Response(null, { status: 404 })), false);
  await assert.rejects(listedInPackument(name, version, async () => Response.json({ name: "wrong" })), /invalid registry packument/);
});

test("waitForInstallable waits until every package is on its version endpoint and in its packument", async () => {
  const other = "@redact-secret/other";
  const packumentReads = new Map();
  const request = async (url) => {
    const isVersion = url.pathname.endsWith(`/${version}`);
    const pkg = decodeURIComponent(isVersion ? url.pathname.slice(1, -(version.length + 1)) : url.pathname.slice(1));
    if (isVersion) return Response.json({ name: pkg, version, dist: { shasum: "a".repeat(40) } });
    const reads = (packumentReads.get(pkg) ?? 0) + 1;
    packumentReads.set(pkg, reads);
    // `other` is already on its version endpoint, but its packument -- what
    // `npm install` resolves through -- lags until the third read.
    const listed = pkg === name || reads >= 3;
    return Response.json({ name: pkg, versions: listed ? { [version]: {} } : {} });
  };
  await waitForInstallable([{ name, version }, { name: other, version }], { request, pollIntervalMs: 0 });
  assert.equal(packumentReads.get(name), 1);
  assert.equal(packumentReads.get(other), 3);
});

test("waitForInstallable fails closed, naming every package still missing, once the deadline passes", async () => {
  await assert.rejects(
    waitForInstallable([{ name, version }], {
      request: async () => new Response(null, { status: 404 }),
      pollIntervalMs: 0,
      maxWaitMs: 0,
    }),
    /not installable from the registry after waiting 0ms for publish propagation: @redact-secret\/test@0\.1\.0-beta\.1/,
  );
});
