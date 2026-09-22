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
 *
 * Issue #614: `publishAccepted` is for a caller whose own `npm publish` of a
 * tarball with exactly `expectedShasum` just exited successfully. npm has
 * then accepted that content, and the version is immutable, so a registry
 * that is still serving 404 once the window closes is propagation lag, not a
 * failed publish -- beta.5 and beta.6 both lost a clean release to that. The
 * wait resolves with `{ pending: true, ... }` instead of throwing. Any
 * *visible* checksum other than `expectedShasum` at the deadline is still a
 * hard failure, with or without `publishAccepted`.
 */
export async function waitForPublished(
  name,
  version,
  {
    expectedShasum,
    publishAccepted = false,
    request = fetch,
    pollIntervalMs = POLL_INTERVAL_MS,
    maxWaitMs = MAX_WAIT_MS,
  } = {},
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
  if (metadata === undefined && publishAccepted) {
    return { name, version, dist: { shasum: expectedShasum }, pending: true };
  }
  throw new Error(
    metadata === undefined
      ? `${name}@${version}: not visible on the registry after waiting ${maxWaitMs}ms for publish propagation`
      : `${name}@${version}: registry checksum still does not match qualified content after waiting ` +
          `${maxWaitMs}ms (saw ${metadata.dist.shasum}, expected ${expectedShasum})`,
  );
}

/** One line naming what `waitForPublished` resolved with, for job logs. */
export function describePublication(name, version, metadata) {
  return metadata.pending
    ? `${name}@${version}: npm accepted the publish of shasum ${metadata.dist.shasum}, but the ` +
        "version endpoint is not serving it yet (publish propagation). Treating npm's acceptance as " +
        "authoritative; the registry-install verification waits for it to become installable."
    : `${name}@${version} published and verified (shasum ${metadata.dist.shasum}).`;
}

/**
 * Poll until `name@version` is visible on the registry with *any* content,
 * or `maxWaitMs` elapses -- for callers that need to know a version is
 * installable (e.g. a registry-install verification lane) but, unlike
 * `waitForPublished`'s callers, hold no local shasum to verify it against.
 * A propagation delay within the timeout resolves silently; exceeding it is
 * a real failure, not "not published" treated as safe to proceed.
 */
export async function waitForVisible(
  name,
  version,
  { request = fetch, pollIntervalMs = POLL_INTERVAL_MS, maxWaitMs = MAX_WAIT_MS } = {},
) {
  const deadline = Date.now() + maxWaitMs;
  for (;;) {
    const metadata = await viewPublished(name, version, request);
    if (metadata !== undefined) return metadata;
    if (Date.now() >= deadline) {
      throw new Error(
        `${name}@${version}: not visible on the registry after waiting ${maxWaitMs}ms for publish propagation`,
      );
    }
    await new Promise((resolve) => setTimeout(resolve, pollIntervalMs));
  }
}

// Issue #614: `npm install` resolves a version through the aggregate
// packument, which is the read that lags longest after a publish. The
// registry-install lane runs after every publish job, so it can afford a much
// longer window than a publish leg -- a slow registry costs minutes here
// instead of a failed release plus a Reconcile.
const INSTALLABLE_MAX_WAIT_MS = 20 * 60 * 1000;
const INSTALLABLE_POLL_INTERVAL_MS = 15_000;

/** Read whether the abbreviated packument `npm install` uses lists `version`. */
export async function listedInPackument(name, version, request = fetch) {
  const url = new URL(`https://registry.npmjs.org/${encodeURIComponent(name)}`);
  url.searchParams.set("release_check", Date.now().toString());
  const response = await request(url, {
    headers: { Accept: "application/vnd.npm.install-v1+json", "Cache-Control": "no-cache" },
    signal: AbortSignal.timeout(30_000),
  });
  if (response.status === 404) return false;
  if (!response.ok) throw new Error(`${name}: registry returned HTTP ${response.status}`);
  const packument = await response.json();
  if (packument.name !== name) throw new Error(`${name}: invalid registry packument`);
  return Object.hasOwn(packument.versions ?? {}, version);
}

/**
 * Poll until every `name@version` in `packages` is visible on its immutable
 * version endpoint *and* listed in the packument `npm install` resolves
 * through, or `maxWaitMs` elapses. This is the "published but not yet
 * visible" tolerance issue #614 moves out of the publish legs: exceeding the
 * window is still a real failure.
 */
export async function waitForInstallable(
  packages,
  {
    request = fetch,
    pollIntervalMs = INSTALLABLE_POLL_INTERVAL_MS,
    maxWaitMs = INSTALLABLE_MAX_WAIT_MS,
  } = {},
) {
  const deadline = Date.now() + maxWaitMs;
  let waiting = [...packages];
  for (;;) {
    const still = [];
    for (const pkg of waiting) {
      const visible =
        (await viewPublished(pkg.name, pkg.version, request)) !== undefined &&
        (await listedInPackument(pkg.name, pkg.version, request));
      if (!visible) still.push(pkg);
    }
    waiting = still;
    if (waiting.length === 0) return;
    if (Date.now() >= deadline) {
      throw new Error(
        `not installable from the registry after waiting ${maxWaitMs}ms for publish propagation: ` +
          waiting.map((pkg) => `${pkg.name}@${pkg.version}`).join(", "),
      );
    }
    await new Promise((resolve) => setTimeout(resolve, pollIntervalMs));
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const args = process.argv.slice(2);
  const publishAccepted = args.includes("--publish-accepted");
  const [name, version, expected] = args.filter((arg) => arg !== "--publish-accepted");
  if (!name || !version || (publishAccepted && !expected)) {
    throw new Error(
      "usage: npm-registry-metadata.mjs <name> <version> [expected-shasum [--publish-accepted]]",
    );
  }
  const metadata = await waitForPublished(name, version, {
    expectedShasum: expected || undefined,
    publishAccepted,
  });
  if (metadata?.pending) console.error(describePublication(name, version, metadata));
  console.log(metadata?.dist.shasum ?? "unpublished");
}
