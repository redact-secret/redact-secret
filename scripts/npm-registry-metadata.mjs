#!/usr/bin/env node
import { pathToFileURL } from "node:url";

// npm view consults aggregate package metadata, which can remain a cached 404
// after a first publication. Read the immutable version endpoint directly.
export async function viewPublished(name, version, request = fetch) {
  const url = new URL(`https://registry.npmjs.org/${encodeURIComponent(name)}/${encodeURIComponent(version)}`);
  url.searchParams.set("release_check", Date.now().toString());
  const response = await request(url, {
    headers: { "Cache-Control": "no-cache" },
    signal: AbortSignal.timeout(30_000),
  });
  if (response.status === 404) return undefined;
  if (!response.ok) throw new Error(`${name}@${version}: registry returned HTTP ${response.status}`);
  const metadata = await response.json();
  if (metadata.name !== name || metadata.version !== version || !/^[a-f0-9]{40}$/.test(metadata.dist?.shasum ?? "")) {
    throw new Error(`${name}@${version}: invalid registry metadata`);
  }
  return metadata;
}

const POLL_INTERVAL_MS = 5000;
// npm's own publish response warns the tarball "may take a few minutes to
// become available" on this immutable per-version endpoint. A read that comes
// back defined but with the wrong shasum during that window is the same
// not-settled-yet state as a 404, not a real conflict -- keep polling on a
// mismatch exactly as on a miss, instead of failing on the first response.
const MAX_WAIT_MS = 3 * 60 * 1000;

/**
 * Poll the registry until the published metadata's shasum matches
 * `expectedShasum`, or `maxWaitMs` elapses. With no `expectedShasum`, this is
 * a single unretried read of current registry state (used by callers that
 * want "what's there right now", such as before deciding whether to publish).
 */
export async function waitForPublished(
  name,
  version,
  { expectedShasum, request = fetch, pollIntervalMs = POLL_INTERVAL_MS, maxWaitMs = MAX_WAIT_MS } = {},
) {
  if (!expectedShasum) return viewPublished(name, version, request);
  const deadline = Date.now() + maxWaitMs;
  let metadata;
  for (;;) {
    metadata = await viewPublished(name, version, request);
    if (metadata !== undefined && metadata.dist.shasum === expectedShasum) return metadata;
    if (Date.now() >= deadline) break;
    await new Promise((resolve) => setTimeout(resolve, pollIntervalMs));
  }
  throw new Error(
    metadata === undefined
      ? `${name}@${version}: not visible on the registry after publishing`
      : `${name}@${version}: registry checksum does not match qualified content ` +
          `(saw ${metadata.dist.shasum}, expected ${expectedShasum})`,
  );
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const [name, version, expected] = process.argv.slice(2);
  if (!name || !version) throw new Error("usage: npm-registry-metadata.mjs <name> <version> [expected-shasum]");
  const metadata = await waitForPublished(name, version, { expectedShasum: expected || undefined });
  console.log(metadata?.dist.shasum ?? "unpublished");
}
