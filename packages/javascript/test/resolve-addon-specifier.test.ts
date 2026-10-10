import { describe, expect, it, vi } from "vitest";

import { resolveAddonSpecifier } from "../src/runtime/node.js";

/**
 * `resolveAddonSpecifier`'s host-to-package mapping, pinned against every
 * `napi.targets` entry `bindings/node/package.json` declares so the two
 * cannot drift silently: adding a target there without a matching case here
 * is a runtime gap this test would not catch on its own, but removing or
 * renaming a case here without updating that manifest is exactly what this
 * test exists to catch. `linux` cases also carry the libc the host must
 * report to select that entry (`decision-publish-musl-node-addons`).
 */
const NON_LINUX: ReadonlyArray<readonly [platform: string, arch: string, specifier: string]> = [
  ["darwin", "arm64", "@redact-secret/node-darwin-arm64"],
  ["darwin", "x64", "@redact-secret/node-darwin-x64"],
  ["win32", "arm64", "@redact-secret/node-win32-arm64-msvc"],
  ["win32", "x64", "@redact-secret/node-win32-x64-msvc"],
];

const LINUX: ReadonlyArray<readonly [arch: string, libc: "gnu" | "musl", specifier: string]> = [
  ["arm64", "gnu", "@redact-secret/node-linux-arm64-gnu"],
  ["arm64", "musl", "@redact-secret/node-linux-arm64-musl"],
  ["x64", "gnu", "@redact-secret/node-linux-x64-gnu"],
  ["x64", "musl", "@redact-secret/node-linux-x64-musl"],
];

function withHost<T>(platform: string, arch: string, fn: () => T): T {
  const platformDescriptor = Object.getOwnPropertyDescriptor(process, "platform");
  const archDescriptor = Object.getOwnPropertyDescriptor(process, "arch");
  Object.defineProperty(process, "platform", { value: platform, configurable: true });
  Object.defineProperty(process, "arch", { value: arch, configurable: true });
  try {
    return fn();
  } finally {
    if (platformDescriptor) Object.defineProperty(process, "platform", platformDescriptor);
    if (archDescriptor) Object.defineProperty(process, "arch", archDescriptor);
  }
}

/**
 * Stands in for a glibc or musl host by controlling what
 * `process.report.getReport().header.glibcVersionRuntime` reports —
 * present (glibc) or absent (musl) — the same signal
 * `detectLinuxLibc` reads.
 */
function withLibc<T>(libc: "gnu" | "musl", fn: () => T): T {
  const original = process.report.getReport;
  process.report.getReport = () => (libc === "gnu" ? { header: { glibcVersionRuntime: "2.31" } } : { header: {} });
  try {
    return fn();
  } finally {
    process.report.getReport = original;
  }
}

function withReport<T>(report: { getReport: () => unknown; excludeNetwork?: boolean }, fn: () => T): T {
  const descriptor = Object.getOwnPropertyDescriptor(process, "report");
  Object.defineProperty(process, "report", { value: report, configurable: true });
  try {
    return fn();
  } finally {
    if (descriptor) Object.defineProperty(process, "report", descriptor);
  }
}

describe("resolveAddonSpecifier", () => {
  it.each(NON_LINUX)("maps %s/%s to %s", (platform, arch, specifier) => {
    expect(withHost(platform, arch, () => resolveAddonSpecifier())).toBe(specifier);
  });

  it.each(LINUX)("maps linux/%s on %s libc to %s", (arch, libc, specifier) => {
    expect(withHost("linux", arch, () => withLibc(libc, () => resolveAddonSpecifier()))).toBe(specifier);
  });

  it("has one non-linux entry per bindings/node/package.json napi.target", () => {
    expect(NON_LINUX).toHaveLength(4);
  });

  it("has one linux entry per arch/libc pair bindings/node/package.json napi.targets declares", () => {
    expect(LINUX).toHaveLength(4);
  });

  it("returns undefined for a platform this package ships no addon for", () => {
    expect(withHost("freebsd", "x64", () => resolveAddonSpecifier())).toBeUndefined();
  });

  it("returns undefined for a supported platform on an unsupported architecture", () => {
    expect(withHost("linux", "ia32", () => resolveAddonSpecifier())).toBeUndefined();
  });

  it("detects libc, rather than trying one candidate and falling back to the other", () => {
    // A wrong-libc addon fails process-fatally, not catchably
    // (`decision-publish-musl-node-addons`), so the two Linux specifiers
    // must never be tried in sequence — only the one detection selects.
    const gnu = withHost("linux", "x64", () => withLibc("gnu", () => resolveAddonSpecifier()));
    const musl = withHost("linux", "x64", () => withLibc("musl", () => resolveAddonSpecifier()));

    expect(gnu).not.toBe(musl);
  });

  it.each([
    ["gnu", false],
    ["gnu", true],
    ["musl", false],
    ["musl", true],
  ] as const)("omits network collection for %s and restores excludeNetwork=%s", (libc, previous) => {
    const report = {
      excludeNetwork: previous as boolean,
      getReport: () => {
        expect(report.excludeNetwork).toBe(true);
        return libc === "gnu" ? { header: { glibcVersionRuntime: "2.31" } } : { header: {} };
      },
    };
    expect(withHost("linux", "x64", () => withReport(report, resolveAddonSpecifier))).toBe(
      `@redact-secret/node-linux-x64-${libc}`,
    );
    expect(report.excludeNetwork).toBe(previous);
  });

  it("leaves an older Node report without excludeNetwork unchanged", () => {
    const report = {
      getReport: () => {
        expect(Object.hasOwn(report, "excludeNetwork")).toBe(false);
        return { header: { glibcVersionRuntime: "2.31" } };
      },
    };
    expect(withHost("linux", "x64", () => withReport(report, resolveAddonSpecifier))).toBe(
      "@redact-secret/node-linux-x64-gnu",
    );
    expect(Object.hasOwn(report, "excludeNetwork")).toBe(false);
  });

  it.each([false, true])("restores excludeNetwork=%s and rethrows a report failure", (previous) => {
    const failure = new Error("synthetic report failure");
    const report = {
      excludeNetwork: previous,
      getReport: () => {
        expect(report.excludeNetwork).toBe(true);
        throw failure;
      },
    };
    expect(() => withHost("linux", "x64", () => withReport(report, resolveAddonSpecifier))).toThrow(failure);
    expect(report.excludeNetwork).toBe(previous);
  });

  it.each([
    ["darwin", "arm64"],
    ["freebsd", "x64"],
    ["linux", "ia32"],
  ])("does not collect or change reports for %s/%s", (platform, arch) => {
    const report = { excludeNetwork: false, getReport: vi.fn() };
    withHost(platform, arch, () => withReport(report, resolveAddonSpecifier));
    expect(report.getReport).not.toHaveBeenCalled();
    expect(report.excludeNetwork).toBe(false);
  });
});
