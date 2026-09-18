/**
 * The runtime-neutral half of the package: the initialization contract and
 * the operations it gates.
 *
 * {@link createRedactSecretRuntime} takes the loader for one runtime and returns
 * the public operations bound to it. `index.ts` supplies the loader the
 * package's `imports` map selected; tests supply their own. Nothing here
 * inspects the host, imports a `node:` module, or touches a global.
 */

import {
  SecretScanError,
  toSecretScanError,
  type SecretScanErrorCode,
} from "./errors.js";
import { defaultPlaceholderFormatter } from "./formatters.js";
import {
  NATIVE_HANDLE,
  type NativeBinding,
  type NativeBindingLoader,
  type NativeDetectedFinding,
  type NativeFinding,
  type NativeFormatterCallback,
  type NativeIncrementalOptions,
  type NativeIncrementalPolicyCallback,
  type NativeIncrementalSanitizer,
  type NativePolicyCallback,
} from "./native.js";
import { VERSION } from "./version.js";
import type {
  DetectedSecretFinding,
  IncrementalSanitizer,
  IncrementalSanitizerOptions,
  IncrementalSanitizerResult,
  PlaceholderFormatter,
  RedactOptions,
  ScanAndRedactOptions,
  ScanOptions,
  ScanResult,
  SecretFinding,
} from "./types.js";

/** Freezes the five documented fields a policy callback is allowed to see. */
function toDetectedSecretFinding(
  finding: NativeDetectedFinding,
): DetectedSecretFinding {
  return Object.freeze({
    id: finding.id,
    type: finding.type,
    detector: finding.detector,
    confidence: finding.confidence as DetectedSecretFinding["confidence"],
    start: finding.start,
    end: finding.end,
  });
}

/** Freezes the seven documented fields, preserving any binding handle. */
function toSecretFinding(finding: NativeFinding): SecretFinding {
  const published: SecretFinding = {
    id: finding.id,
    type: finding.type,
    detector: finding.detector,
    confidence: finding.confidence as SecretFinding["confidence"],
    action: finding.action as SecretFinding["action"],
    start: finding.start,
    end: finding.end,
  };
  const handle = finding[NATIVE_HANDLE];
  if (handle !== undefined) {
    Object.defineProperty(published, NATIVE_HANDLE, {
      value: handle,
      enumerable: false,
      writable: false,
      configurable: false,
    });
  }
  return Object.freeze(published);
}

function toSecretFindings(
  findings: readonly NativeFinding[],
): readonly SecretFinding[] {
  return Object.freeze(findings.map(toSecretFinding));
}

/**
 * Re-presents a public finding to the binding that produced it, carrying the
 * binding handle back across when the finding has one.
 *
 * The WebAssembly binding's `redact` accepts only the opaque findings its own
 * `scan` returned; that adapter rejects a finding that arrives without one
 * rather than reinterpreting it. The Node addon reads the plain fields.
 */
function toNativeFinding(finding: SecretFinding): NativeFinding {
  const handle = (finding as { [NATIVE_HANDLE]?: unknown })[NATIVE_HANDLE];
  if (handle === undefined) return finding;
  return { ...finding, [NATIVE_HANDLE]: handle };
}

/**
 * Matches a JavaScript string containing a lone (unpaired) UTF-16 surrogate:
 * a high surrogate not immediately followed by a low surrogate, or a low
 * surrogate not immediately preceded by a high surrogate. Such a code unit
 * has no UTF-8 representation, so it cannot cross into either binding's Rust
 * `&str` (`errors.ts`'s `UNPAIRED_SURROGATE` documentation).
 */
const LONE_SURROGATE =
  /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/;

function requireString(value: unknown): string {
  if (typeof value !== "string") throw new SecretScanError("INVALID_INPUT");
  if (LONE_SURROGATE.test(value)) {
    throw new SecretScanError("UNPAIRED_SURROGATE");
  }
  return value;
}

function toPolicyCallback(
  policy: ScanOptions["policy"],
): NativePolicyCallback | undefined {
  if (policy === undefined) return undefined;
  if (typeof policy !== "object" || typeof policy.evaluate !== "function") {
    throw new SecretScanError("INVALID_OPTIONS");
  }
  return (finding, context) =>
    policy.evaluate(toDetectedSecretFinding(finding), context);
}

/**
 * Routes the exported default formatter back to the binding's own built-in
 * rather than calling across the boundary for every placeholder, so the
 * default path stays exactly the core's.
 */
function toFormatterCallback(
  formatter: PlaceholderFormatter | undefined,
): NativeFormatterCallback | undefined {
  if (formatter === undefined || formatter === defaultPlaceholderFormatter) {
    return undefined;
  }
  if (typeof formatter !== "function") {
    throw new SecretScanError("INVALID_OPTIONS");
  }
  return (finding, context) => formatter(toSecretFinding(finding), context);
}

function toNativeIncrementalOptions(
  options: IncrementalSanitizerOptions,
): NativeIncrementalOptions {
  if (typeof options !== "object" || options === null) {
    throw new SecretScanError("INVALID_OPTIONS");
  }
  const { limits, policy, placeholderFormatter } = options;
  if (typeof limits !== "object" || limits === null) {
    throw new SecretScanError("INVALID_LIMITS");
  }
  const formatter = toFormatterCallback(placeholderFormatter);
  if (
    policy !== undefined &&
    (typeof policy !== "object" || typeof policy.evaluate !== "function")
  ) {
    throw new SecretScanError("INVALID_OPTIONS");
  }
  const policyCallback: NativeIncrementalPolicyCallback | undefined =
    policy === undefined
      ? undefined
      : (finding, context) =>
          policy.evaluate(toDetectedSecretFinding(finding), context);
  return {
    limits: {
      maxInputCodeUnits: limits.maxInputCodeUnits,
      maxBufferedCodeUnits: limits.maxBufferedCodeUnits,
      maxTokenCodeUnits: limits.maxTokenCodeUnits,
      maxMultilineCodeUnits: limits.maxMultilineCodeUnits,
    },
    ...(policyCallback === undefined ? {} : { policy: policyCallback }),
    ...(formatter === undefined ? {} : { formatter }),
  };
}

export interface RedactSecretRuntime {
  initialize(): Promise<void>;
  scan(input: string, options?: ScanOptions): readonly SecretFinding[];
  redact(
    input: string,
    findings: readonly SecretFinding[],
    options?: RedactOptions,
  ): string;
  scanAndRedact(input: string, options?: ScanAndRedactOptions): ScanResult;
  createIncrementalSanitizer(
    options: IncrementalSanitizerOptions,
  ): IncrementalSanitizer;
}

/**
 * Binds the public operations to one runtime's loader.
 *
 * `initialize` is the whole lifecycle contract: it may be awaited any number
 * of times from any number of call sites and loads at most once, it verifies
 * that the loaded artifact reports this package's version
 * (`decision-release-bindings-in-lockstep`) and the expected detector profile
 * (`decision-define-detector-profile-and-pack-contract`), and every
 * synchronous operation below fails with `NOT_INITIALIZED` until exactly one
 * call has succeeded. A failed attempt is not cached: a caller may retry.
 */
export function createRedactSecretRuntime(
  loadNativeBinding: NativeBindingLoader,
  expectedProfile: "full" | "common",
): RedactSecretRuntime {
  let binding: NativeBinding | undefined;
  let pending: Promise<void> | undefined;

  async function load(): Promise<void> {
    let loaded: NativeBinding;
    try {
      loaded = await loadNativeBinding();
      if (loaded.version() !== VERSION) {
        throw new SecretScanError("INITIALIZATION_FAILED");
      }
      if (loaded.profile() !== expectedProfile) {
        throw new SecretScanError("INITIALIZATION_FAILED");
      }
      loaded.initialize();
    } catch (thrown) {
      throw toSecretScanError(thrown, "INITIALIZATION_FAILED");
    }
    binding = loaded;
  }

  function initialize(): Promise<void> {
    if (binding !== undefined) return Promise.resolve();
    pending ??= load().finally(() => {
      pending = undefined;
    });
    return pending;
  }

  function active(): NativeBinding {
    if (binding === undefined) throw new SecretScanError("NOT_INITIALIZED");
    return binding;
  }

  function scan(
    input: string,
    options?: ScanOptions,
  ): readonly SecretFinding[] {
    const native = active();
    const text = requireString(input);
    const policy = toPolicyCallback(options?.policy);
    try {
      return toSecretFindings(native.scan(text, policy));
    } catch (thrown) {
      throw toSecretScanError(thrown, "DETECTOR_FAILURE");
    }
  }

  function redact(
    input: string,
    findings: readonly SecretFinding[],
    options?: RedactOptions,
  ): string {
    const native = active();
    const text = requireString(input);
    if (!Array.isArray(findings)) {
      throw new SecretScanError("INVALID_FINDINGS");
    }
    const formatter = toFormatterCallback(options?.placeholderFormatter);
    try {
      return native.redact(text, findings.map(toNativeFinding), formatter);
    } catch (thrown) {
      throw toSecretScanError(thrown, "INVALID_FINDINGS");
    }
  }

  function scanAndRedact(
    input: string,
    options?: ScanAndRedactOptions,
  ): ScanResult {
    const native = active();
    const text = requireString(input);
    const policy = toPolicyCallback(options?.policy);
    const formatter = toFormatterCallback(options?.placeholderFormatter);
    let result;
    try {
      result = native.scanAndRedact(text, policy, formatter);
    } catch (thrown) {
      throw toSecretScanError(thrown, "DETECTOR_FAILURE");
    }
    return Object.freeze({
      text: result.text,
      findings: toSecretFindings(result.findings),
    });
  }

  function createIncrementalSanitizer(
    options: IncrementalSanitizerOptions,
  ): IncrementalSanitizer {
    const native = active();
    let session: NativeIncrementalSanitizer;
    try {
      session = native.createIncrementalSanitizer(
        toNativeIncrementalOptions(options),
      );
    } catch (thrown) {
      throw toSecretScanError(thrown, "INVALID_LIMITS");
    }

    // Host validation cannot reach the core; abort releases its buffer and index.
    let inputFailed = false;

    function requireAccepting(): void {
      if (inputFailed || session.state !== "accepting") {
        throw new SecretScanError("INVALID_STATE");
      }
    }

    function run(
      operation: () => {
        readonly text: string;
        readonly findings: readonly NativeFinding[];
      },
      fallback: SecretScanErrorCode,
    ): IncrementalSanitizerResult {
      let result;
      try {
        result = operation();
      } catch (thrown) {
        throw toSecretScanError(thrown, fallback);
      }
      return Object.freeze({
        text: result.text,
        findings: toSecretFindings(result.findings),
      });
    }

    return Object.freeze({
      get state() {
        return inputFailed ? "failed" : session.state;
      },
      append: (chunk: string) => {
        requireAccepting();
        let text;
        try {
          text = requireString(chunk);
        } catch (thrown) {
          inputFailed = true;
          try {
            session.abort();
          } finally {
            throw toSecretScanError(thrown, "INVALID_INPUT");
          }
        }
        return run(() => session.append(text), "DETECTOR_FAILURE");
      },
      finalize: () => {
        requireAccepting();
        return run(() => session.finalize(), "DETECTOR_FAILURE");
      },
      abort: () => {
        requireAccepting();
        try {
          session.abort();
        } catch (thrown) {
          throw toSecretScanError(thrown, "INVALID_STATE");
        }
      },
    });
  }

  return {
    initialize,
    scan,
    redact,
    scanAndRedact,
    createIncrementalSanitizer,
  };
}
