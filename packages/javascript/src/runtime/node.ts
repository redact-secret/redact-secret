/**
 * The Node.js adapter: the N-API native addon, normalized to the internal
 * binding contract (`decision-define-runtime-bindings`).
 *
 * The package's `imports` map reaches this module only under the `node`
 * condition, so a browser build never resolves it and never pulls in the
 * `node:` module below.
 *
 * Node's own loading has nothing to await, so `initialize()` here is a fast
 * idempotent no-op in the addon. It stays part of the contract regardless, so
 * the usage model does not vary by runtime.
 */

import { createRequire } from "node:module";

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
 * `node-publish-targets` is six of the eight triples `napi.targets` builds
 * and qualifies: npm ships glibc only
 * (`decision-ship-first-release-artifact-set`), so the two musl triples have
 * no entry here and no libc dimension below — there is nothing for one to
 * select between. A musl host's `process.platform`/`process.arch` still
 * matches the `linux` glibc entry, and each manifest's `libc` field is not
 * reliably enforced by every npm version, so a musl install can still
 * resolve and install the glibc package (`docs/qualification.md`).
 * `loadAddon`'s `require` of a glibc-linked `.node` file then fails to load
 * under a musl runtime, caught the same way a missing optional dependency
 * on any platform is, reaching the same `INITIALIZATION_FAILED` an
 * explicitly unsupported host gets. `scripts/check-artifact-matrix.py`
 * requires this mapping, the six `bindings/node/npm/<platform>/package.json`
 * manifests, and this package's own `optionalDependencies` to name exactly
 * the same six packages.
 */
const PLATFORM_PACKAGES: Readonly<
  Partial<Record<string, Readonly<Partial<Record<string, string>>>>>
> = {
  darwin: {
    arm64: "@redact-secret/node-darwin-arm64",
    x64: "@redact-secret/node-darwin-x64",
  },
  linux: {
    arm64: "@redact-secret/node-linux-arm64-gnu",
    x64: "@redact-secret/node-linux-x64-gnu",
  },
  win32: {
    arm64: "@redact-secret/node-win32-arm64-msvc",
    x64: "@redact-secret/node-win32-x64-msvc",
  },
};

/**
 * The addon package this host should have installed, or `undefined` on a
 * platform/architecture this package ships no addon for at all — the
 * runtime fallback that keeps an unsupported host's failure identical to a
 * supported host whose optional dependency did not install: both reach
 * `loadAddon`'s own `INITIALIZATION_FAILED`, never a raw `require` error.
 *
 * Exported so `scripts/qualify-node-addon.mjs` and
 * `scripts/qualify-package-consumer.mjs` compute the same host-to-package
 * mapping this module actually loads from, instead of restating it.
 */
export function resolveAddonSpecifier(): string | undefined {
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

export const loadNativeBinding = async (): Promise<NativeBinding> =>
  createBindingFromAddon(loadAddon());
