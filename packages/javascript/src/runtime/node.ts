/**
 * The Node.js adapter: the N-API native addon, normalized to the internal
 * binding contract (`decision-define-runtime-bindings`), with a WebAssembly
 * fallback when the addon path cannot produce a usable binding
 * (`decision-add-node-wasm-fallback`).
 *
 * The package's `imports` map reaches this module only under the `node`
 * condition, so a browser build never resolves it and never pulls in the
 * `node:` modules below.
 *
 * Node's own loading has nothing to await, so `initialize()` here is a fast
 * idempotent no-op in the addon. It stays part of the contract regardless, so
 * the usage model does not vary by runtime.
 */

import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { dirname, join } from "node:path";

import { SecretScanError } from "../errors.js";
import type {
  NativeBinding,
  NativeFinding,
  NativeFormatterCallback,
  NativeIncrementalOptions,
  NativeIncrementalSanitizer,
  NativePolicyCallback,
  NativeScanAndRedactResult,
  NativeWholeInputLimits,
} from "../native.js";
import {
  assertWasmModuleShape,
  createBindingFromWasmModule,
  type WasmModule,
} from "./wasm-binding.js";

/**
 * The addon's own exported shape. `scanAndRedact` names its text `redacted`,
 * which this adapter renames to the contract's `text`; everything else is
 * already the documented UTF-16 shape.
 *
 * Incremental sanitization is part of the artifact contract. A package and
 * platform addon are released in lockstep, so an addon without that export is
 * an invalid installation and fails initialization with the other missing
 * required exports.
 */
interface NodeAddon {
  version(): string;
  profile(): string;
  initialize(): void;
  scan(
    input: string,
    policy?: NativePolicyCallback,
    limits?: NativeWholeInputLimits,
  ): readonly NativeFinding[];
  redact(
    input: string,
    findings: readonly NativeFinding[],
    formatter?: NativeFormatterCallback,
    limits?: NativeWholeInputLimits,
  ): string;
  scanAndRedact(
    input: string,
    policy?: NativePolicyCallback,
    formatter?: NativeFormatterCallback,
    limits?: NativeWholeInputLimits,
  ): { readonly findings: readonly NativeFinding[]; readonly redacted: string };
  createIncrementalSanitizer(
    options: NativeIncrementalOptions,
  ): NativeIncrementalSanitizer;
}

/**
 * The addon's `common`-profile export surface: the same operations as
 * {@link NodeAddon}, each named for the `common` registry it runs against,
 * except `version` and `redact` — profile-independent, so both operate the
 * same way regardless of which registry produced a finding, and are shared
 * between both profiles on the one addon file that exports both
 * (`bindings/node/src/lib.rs`).
 */
interface CommonNodeAddon {
  version(): string;
  initializeCommon(): void;
  scanCommon(
    input: string,
    policy?: NativePolicyCallback,
    limits?: NativeWholeInputLimits,
  ): readonly NativeFinding[];
  redact(
    input: string,
    findings: readonly NativeFinding[],
    formatter?: NativeFormatterCallback,
    limits?: NativeWholeInputLimits,
  ): string;
  scanAndRedactCommon(
    input: string,
    policy?: NativePolicyCallback,
    formatter?: NativeFormatterCallback,
    limits?: NativeWholeInputLimits,
  ): { readonly findings: readonly NativeFinding[]; readonly redacted: string };
  createIncrementalSanitizerCommon(
    options: NativeIncrementalOptions,
  ): NativeIncrementalSanitizer;
  profileCommon(): string;
}

/**
 * One `optionalDependencies` entry per `node-publish-targets`, published in
 * lockstep with this package (`bindings/node/npm/<platform>/package.json`).
 * `os`/`cpu`/`libc` on each of those manifests is what makes every
 * non-matching entry optional in the literal npm sense: an install skips
 * the ones that do not match instead of failing on them.
 *
 * `darwin` and `win32` have no libc dimension. `linux` does — see
 * {@link LINUX_PLATFORM_PACKAGES} — because `node-publish-targets` now
 * covers both the glibc and musl triples `napi.targets` builds and
 * qualifies (`decision-publish-musl-node-addons`).
 */
const PLATFORM_PACKAGES: Readonly<
  Partial<Record<string, Readonly<Partial<Record<string, string>>>>>
> = {
  darwin: {
    arm64: "@redact-secret/node-darwin-arm64",
    x64: "@redact-secret/node-darwin-x64",
  },
  win32: {
    arm64: "@redact-secret/node-win32-arm64-msvc",
    x64: "@redact-secret/node-win32-x64-msvc",
  },
};

/**
 * Linux's own host-to-package mapping, keyed by architecture and then libc,
 * since Linux is the one platform this package publishes two addons per
 * architecture for (`decision-publish-musl-node-addons`).
 */
const LINUX_PLATFORM_PACKAGES: Readonly<
  Partial<Record<string, Readonly<Record<"gnu" | "musl", string>>>>
> = {
  arm64: {
    gnu: "@redact-secret/node-linux-arm64-gnu",
    musl: "@redact-secret/node-linux-arm64-musl",
  },
  x64: {
    gnu: "@redact-secret/node-linux-x64-gnu",
    musl: "@redact-secret/node-linux-x64-musl",
  },
};

/**
 * Distinguishes glibc from musl on a Linux host by **detection**, not by
 * probing candidate addons in order (`decision-publish-musl-node-addons`):
 * an addon linked against the wrong libc does not fail at `require()` the
 * way a missing or corrupt addon does. It fails later, at the first
 * unresolved symbol touch, as a process-fatal `symbol lookup error` outside
 * any `try`/`catch`'s reach — so the wrong candidate can never be allowed to
 * load at all, only skipped in favor of the right one.
 *
 * `process.report.getReport().header.glibcVersionRuntime` is populated by
 * Node's own diagnostics on a glibc host and absent on musl; that is the
 * same signal napi-rs's own platform detection uses.
 */
function detectLinuxLibc(): "gnu" | "musl" {
  const report = process.report.getReport() as {
    header?: { glibcVersionRuntime?: unknown };
  };
  return typeof report.header?.glibcVersionRuntime === "string" ? "gnu" : "musl";
}

/**
 * The addon package this host should have installed, or `undefined` on a
 * platform/architecture this package ships no addon for at all — the
 * runtime fallback that keeps an unsupported host's failure identical to a
 * supported host whose optional dependency did not install: both reach
 * `loadAddon`'s own `INITIALIZATION_FAILED`, never a raw `require` error (or,
 * since `decision-add-node-wasm-fallback`, the WebAssembly fallback below).
 *
 * Exported so `scripts/qualify-node-addon.mjs` and
 * `scripts/qualify-package-consumer.mjs` compute the same host-to-package
 * mapping this module actually loads from, instead of restating it.
 */
export function resolveAddonSpecifier(): string | undefined {
  if (process.platform === "linux") {
    return LINUX_PLATFORM_PACKAGES[process.arch]?.[detectLinuxLibc()];
  }
  return PLATFORM_PACKAGES[process.platform]?.[process.arch];
}

/**
 * Resolves this host's platform addon specifier and `require`s it, without
 * validating which exports it carries.
 *
 * Shared by {@link loadAddon} (full) and {@link loadCommonAddon} so the
 * specifier resolution and the `require` try/catch are not duplicated: the
 * two callers differ only in which exports they then require present.
 */
function requireAddon(): Partial<NodeAddon> & Partial<CommonNodeAddon> {
  const specifier = resolveAddonSpecifier();
  if (specifier === undefined) {
    throw new SecretScanError("INITIALIZATION_FAILED");
  }

  const require = createRequire(import.meta.url);
  try {
    return require(specifier) as Partial<NodeAddon> & Partial<CommonNodeAddon>;
  } catch {
    // Not installed (an optional dependency npm skipped, or one that failed
    // to install) and a corrupt addon both fail the same fixed way.
    throw new SecretScanError("INITIALIZATION_FAILED");
  }
}

/**
 * Asserts every one of `names` is a function on `addon`, the shared body
 * {@link loadAddon} and {@link loadCommonAddon} apply to their own required
 * export lists.
 */
function requireExports<T>(
  addon: Partial<NodeAddon> & Partial<CommonNodeAddon>,
  names: readonly (keyof T)[],
): T {
  for (const name of names) {
    if (typeof (addon as Record<string, unknown>)[name as string] !== "function") {
      throw new SecretScanError("INITIALIZATION_FAILED");
    }
  }
  return addon as T;
}

function loadAddon(): NodeAddon {
  return requireExports<NodeAddon>(requireAddon(), [
    "version",
    "profile",
    "initialize",
    "scan",
    "redact",
    "scanAndRedact",
    "createIncrementalSanitizer",
  ]);
}

/**
 * Loads the same per-platform addon {@link loadAddon} does, requiring its
 * `common`-profile exports instead of its full-profile ones
 * (`bindings/node/src/lib.rs`'s `*_common` N-API functions).
 */
export function loadCommonAddon(): CommonNodeAddon {
  return requireExports<CommonNodeAddon>(requireAddon(), [
    "version",
    "initializeCommon",
    "scanCommon",
    "redact",
    "scanAndRedactCommon",
    "createIncrementalSanitizerCommon",
    "profileCommon",
  ]);
}

/**
 * The profile-selected addon methods {@link buildBinding} normalizes:
 * `version` and `redact` are not part of this shape because they are
 * profile-independent, called directly on the addon by every binding.
 */
interface ProfiledAddonMethods {
  profile(): string;
  initialize(): void;
  scan(
    input: string,
    policy?: NativePolicyCallback,
    limits?: NativeWholeInputLimits,
  ): readonly NativeFinding[];
  scanAndRedact(
    input: string,
    policy?: NativePolicyCallback,
    formatter?: NativeFormatterCallback,
    limits?: NativeWholeInputLimits,
  ): { readonly findings: readonly NativeFinding[]; readonly redacted: string };
  createIncrementalSanitizer(
    options: NativeIncrementalOptions,
  ): NativeIncrementalSanitizer;
}

/**
 * Builds the internal binding contract from an addon's shared `version` and
 * `redact` exports plus its profile-selected methods — {@link NodeAddon}
 * itself for {@link createBindingFromAddon}, or a `CommonNodeAddon` view
 * onto its `*Common` exports for {@link createBindingFromCommonAddon}.
 */
function buildBinding(
  addon: Pick<NodeAddon, "version" | "redact">,
  methods: ProfiledAddonMethods,
): NativeBinding {
  return {
    version: () => addon.version(),
    profile: () => methods.profile(),
    artifact: () => "addon",
    initialize: () => {
      methods.initialize();
    },
    scan: (input, policy, limits) => methods.scan(input, policy, limits),
    redact: (input, findings, formatter, limits) =>
      addon.redact(input, findings, formatter, limits),
    scanAndRedact: (
      input,
      policy,
      formatter,
      limits,
    ): NativeScanAndRedactResult => {
      const result = methods.scanAndRedact(input, policy, formatter, limits);
      return { text: result.redacted, findings: result.findings };
    },
    createIncrementalSanitizer: (options) =>
      methods.createIncrementalSanitizer(options),
  };
}

/**
 * Builds the internal binding contract from an already-loaded addon.
 *
 * Exported so a test double can exercise this exact normalization without
 * loading the real addon, the way `runtime/browser.ts`'s
 * `createBindingFromWasmModule` does for the WebAssembly artifact.
 */
export function createBindingFromAddon(addon: NodeAddon): NativeBinding {
  return buildBinding(addon, {
    profile: () => addon.profile(),
    initialize: () => addon.initialize(),
    scan: (input, policy, limits) => addon.scan(input, policy, limits),
    scanAndRedact: (input, policy, formatter, limits) =>
      addon.scanAndRedact(input, policy, formatter, limits),
    createIncrementalSanitizer: (options) =>
      addon.createIncrementalSanitizer(options),
  });
}

/**
 * Builds the internal binding contract from an already-loaded `common`-profile
 * addon, mirroring {@link createBindingFromAddon}'s normalization but against
 * the `*Common` exports. `redact` is shared: it is profile-independent, so
 * the same addon export backs both bindings.
 *
 * Exported so a test double can exercise this exact normalization without
 * loading the real addon.
 */
export function createBindingFromCommonAddon(
  addon: CommonNodeAddon,
): NativeBinding {
  return buildBinding(addon, {
    profile: () => addon.profileCommon(),
    initialize: () => addon.initializeCommon(),
    scan: (input, policy, limits) => addon.scanCommon(input, policy, limits),
    scanAndRedact: (input, policy, formatter, limits) =>
      addon.scanAndRedactCommon(input, policy, formatter, limits),
    createIncrementalSanitizer: (options) =>
      addon.createIncrementalSanitizerCommon(options),
  });
}

/**
 * The WebAssembly fallback artifact per detector profile
 * (`decision-add-node-wasm-fallback`): the exact browser artifact
 * `runtime/browser.ts`/`browser-common.ts` load, reused rather than
 * duplicated with a second `wasm-bindgen` target. `binaryName` is the
 * sibling `.wasm` file `scripts/build-browser-artifact.mjs` always emits
 * next to each profile's glue, fixed by that build and by
 * `bindings/wasm/npm/package.json`'s own `files` list.
 */
const WASM_PACKAGE = "@redact-secret/wasm";
const WASM_FALLBACK: Readonly<
  Record<"full" | "common", Readonly<{ specifier: string; binaryName: string }>>
> = {
  full: { specifier: WASM_PACKAGE, binaryName: "redact_secret_wasm_bg.wasm" },
  common: {
    specifier: `${WASM_PACKAGE}/common`,
    binaryName: "redact_secret_wasm_common_bg.wasm",
  },
};

/**
 * Reads the WebAssembly binary next to the loaded glue module, without a
 * literal relative path: `@redact-secret/wasm`'s `"./package.json"` export
 * is a bare string, resolvable under any condition (including `require`)
 * even though the package's main entry declares only `types`/`import`.
 * Resolving it and taking its directory finds either profile's sibling
 * `.wasm` file the same way, since both binaries always sit next to the
 * package's own `package.json` (`bindings/wasm/npm/package.json`).
 */
function readWasmBytes(binaryName: string): Uint8Array {
  const require = createRequire(import.meta.url);
  const packageJsonPath = require.resolve(`${WASM_PACKAGE}/package.json`);
  return readFileSync(join(dirname(packageJsonPath), binaryName));
}

/**
 * Loads and initializes the WebAssembly fallback for `profile`, normalized
 * through the same `createBindingFromWasmModule` `runtime/browser.ts` uses.
 *
 * The `import()` specifier is looked up in {@link WASM_FALLBACK} rather than
 * written as a string literal at the call site, so a bundler that only
 * follows literal specifiers — the same behavior `runtime/browser.ts` and
 * `browser-common.ts` already rely on to keep their own two profiles from
 * bundling into each other — does not statically discover or inline this
 * browser-oriented glue and `.wasm` binary into a Node build by default.
 * `@redact-secret/wasm` is still an ordinary (non-optional) `dependencies`
 * entry of this package, so it is always present in `node_modules` at
 * runtime regardless of what a consumer's bundler chose to inline.
 *
 * The generated `--target web` glue's `default()` normally `fetch`es its
 * `.wasm` binary relative to its own `import.meta.url`; passing
 * `{ module_or_path: <bytes> }` instead instantiates directly from the bytes
 * {@link readWasmBytes} already read from disk, which is what lets this
 * fallback reuse the browser artifact unmodified rather than requiring a
 * second, Node-targeted `wasm-bindgen` build.
 *
 * Exported so a test double can force this path the way `loadAddon` is
 * forced, without depending on the real artifact being present.
 */
export async function loadWasmFallback(
  profile: "full" | "common",
): Promise<NativeBinding> {
  const { specifier, binaryName } = WASM_FALLBACK[profile];
  let wasmModule: Partial<WasmModule>;
  try {
    wasmModule = (await import(specifier)) as unknown as Partial<WasmModule>;
  } catch {
    throw new SecretScanError("INITIALIZATION_FAILED");
  }
  assertWasmModuleShape(wasmModule);
  try {
    await wasmModule.default({ module_or_path: readWasmBytes(binaryName) });
  } catch (thrown) {
    if (thrown instanceof SecretScanError) throw thrown;
    throw new SecretScanError("INITIALIZATION_FAILED");
  }
  return createBindingFromWasmModule(wasmModule);
}

/**
 * Tries the native addon first and falls back to WebAssembly only once that
 * has already failed (`decision-add-node-wasm-fallback`): the addon remains
 * the only thing a supported host ever loads, and the fallback engages for
 * every reason {@link loadAddon} fails — an unsupported platform, a missing
 * optional dependency, or a corrupt addon — since none of those is
 * distinguishable from the others once caught.
 */
export const loadNativeBinding = async (): Promise<NativeBinding> => {
  try {
    return createBindingFromAddon(loadAddon());
  } catch {
    return loadWasmFallback("full");
  }
};
