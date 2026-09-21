import { test } from "node:test";
import assert from "node:assert/strict";
import { viewPublished, waitForPublished, waitForVisible } from "../npm-registry-metadata.mjs";

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
