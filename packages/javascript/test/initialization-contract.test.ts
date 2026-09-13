import { describe, expect, it } from "vitest";

import { SecretScanError } from "../src/errors.js";
import { createRedactSecretRuntime } from "../src/runtime.js";
import { VERSION } from "../src/version.js";
import { createFakeBinding, sampleFinding } from "./fake-binding.js";

const LIMITS = {
  maxInputCodeUnits: 1_024,
  maxBufferedCodeUnits: 384,
  maxTokenCodeUnits: 128,
  maxMultilineCodeUnits: 256,
};

describe("initialization contract", () => {
  it("refuses every synchronous operation before initialize succeeds", () => {
    const runtime = createRedactSecretRuntime(async () => createFakeBinding());

    for (const call of [
      () => runtime.scan("SYNTHETIC_REVOKED_VALUE"),
      () => runtime.redact("SYNTHETIC_REVOKED_VALUE", []),
      () => runtime.scanAndRedact("SYNTHETIC_REVOKED_VALUE"),
      () => runtime.createIncrementalSanitizer({ limits: LIMITS }),
    ]) {
      expect(call).toThrowError(
        expect.objectContaining({
          name: "SecretScanError",
          code: "NOT_INITIALIZED",
        }),
      );
    }
  });

  it("does not inspect its input before initialize succeeds", () => {
    const binding = createFakeBinding();
    const runtime = createRedactSecretRuntime(async () => binding);

    expect(() => runtime.scan(undefined as unknown as string)).toThrowError(
      expect.objectContaining({ code: "NOT_INITIALIZED" }),
    );
    expect(binding.calls).toEqual([]);
  });

  it("loads at most once no matter how many callers await it", async () => {
    let loads = 0;
    const binding = createFakeBinding();
    const runtime = createRedactSecretRuntime(async () => {
      loads += 1;
      return binding;
    });

    await Promise.all([
      runtime.initialize(),
      runtime.initialize(),
      runtime.initialize(),
    ]);
    await runtime.initialize();

    expect(loads).toBe(1);
    expect(binding.calls).toEqual(["initialize"]);
  });

  it("does not cache a failed attempt, so a caller may retry", async () => {
    let attempts = 0;
    const runtime = createRedactSecretRuntime(async () => {
      attempts += 1;
      if (attempts === 1) throw new Error("artifact is missing");
      return createFakeBinding();
    });

    await expect(runtime.initialize()).rejects.toThrowError(
      expect.objectContaining({
        name: "SecretScanError",
        code: "INITIALIZATION_FAILED",
      }),
    );
    await expect(runtime.initialize()).resolves.toBeUndefined();
    expect(attempts).toBe(2);
  });

  it("never surfaces a loader's own failure message", async () => {
    const runtime = createRedactSecretRuntime(async () => {
      throw new Error("/private/path/to/redact-secret.darwin-arm64.node");
    });

    await expect(runtime.initialize()).rejects.toThrowError(
      new SecretScanError("INITIALIZATION_FAILED"),
    );
  });

  it("rejects an artifact built from a different product version", async () => {
    const runtime = createRedactSecretRuntime(async () =>
      createFakeBinding({ version: "0.0.0-other" }),
    );

    await expect(runtime.initialize()).rejects.toThrowError(
      expect.objectContaining({ code: "INITIALIZATION_FAILED" }),
    );
    expect(() => runtime.scan("SYNTHETIC_REVOKED_VALUE")).toThrowError(
      expect.objectContaining({ code: "NOT_INITIALIZED" }),
    );
  });

  it("accepts the artifact that reports this package's version", async () => {
    const binding = createFakeBinding({ version: VERSION });
    const runtime = createRedactSecretRuntime(async () => binding);

    await runtime.initialize();

    expect(runtime.scan("API_KEY=SYNTHETIC")).toEqual([]);
  });
});

describe("finding normalization", () => {
  it("freezes every finding and exposes only the documented fields", async () => {
    const runtime = createRedactSecretRuntime(async () =>
      createFakeBinding({ findings: [sampleFinding] }),
    );
    await runtime.initialize();

    const [finding] = runtime.scan("API_KEY=SYNTHETIC_REVOKED_CONTEXT_VALUE");

    expect(finding).toEqual({
      id: "finding-1",
      type: "contextual_secret",
      detector: "generic-token",
      confidence: "high",
      action: "redact",
      start: 8,
      end: 39,
    });
    expect(Object.isFrozen(finding)).toBe(true);
    expect(() => {
      (finding as { action: string }).action = "allow";
    }).toThrowError(TypeError);
  });

  it("freezes the findings list a scan returns", async () => {
    const runtime = createRedactSecretRuntime(async () =>
      createFakeBinding({ findings: [sampleFinding] }),
    );
    await runtime.initialize();

    const findings = runtime.scan("API_KEY=SYNTHETIC_REVOKED_CONTEXT_VALUE");

    expect(Object.isFrozen(findings)).toBe(true);
  });

  it("routes the exported default formatter to the binding's own built-in", async () => {
    const { defaultPlaceholderFormatter, typedPlaceholderFormatter } =
      await import("../src/formatters.js");
    const binding = createFakeBinding({ findings: [sampleFinding] });
    const runtime = createRedactSecretRuntime(async () => binding);
    await runtime.initialize();

    runtime.redact("API_KEY=x", [], {
      placeholderFormatter: defaultPlaceholderFormatter,
    });
    runtime.redact("API_KEY=x", [], {
      placeholderFormatter: typedPlaceholderFormatter,
    });

    expect(binding.calls).toEqual([
      "initialize",
      "redact:API_KEY=x:0:builtin",
      "redact:API_KEY=x:0:custom",
    ]);
  });
});

describe("incremental sessions", () => {
  async function openSession() {
    const binding = createFakeBinding({ findings: [sampleFinding] });
    const runtime = createRedactSecretRuntime(async () => binding);
    await runtime.initialize();
    return {
      binding,
      session: runtime.createIncrementalSanitizer({ limits: LIMITS }),
    };
  }

  it("reports the binding's own lifecycle state", async () => {
    const { session } = await openSession();

    expect(session.state).toBe("accepting");
    session.finalize();
    expect(session.state).toBe("finalized");
  });

  it("freezes every result and every finding it carries", async () => {
    const { session } = await openSession();

    const appended = session.append("first line\n");
    const finalized = session.finalize();

    expect(Object.isFrozen(appended)).toBe(true);
    expect(appended.text).toBe("first line\n");
    expect(Object.isFrozen(finalized.findings)).toBe(true);
    expect(finalized.findings.every(Object.isFrozen)).toBe(true);
  });

  it("passes the session's limits through to the binding", async () => {
    const { binding } = await openSession();

    expect(binding.calls).toEqual([
      "initialize",
      `createIncrementalSanitizer:${LIMITS.maxInputCodeUnits}`,
    ]);
  });

  it("keeps the binding's terminal-state error", async () => {
    const { session } = await openSession();
    session.finalize();

    for (const call of [
      () => session.append("more"),
      () => session.finalize(),
      () => session.abort(),
    ]) {
      expect(call).toThrowError(
        expect.objectContaining({
          name: "SecretScanError",
          code: "INVALID_STATE",
        }),
      );
    }
  });

  it("aborts without emitting anything further", async () => {
    const { binding, session } = await openSession();

    session.abort();

    expect(session.state).toBe("aborted");
    expect(binding.calls.at(-1)).toBe("abort");
  });

  it("rejects a session created before initialize succeeds", () => {
    const runtime = createRedactSecretRuntime(async () => createFakeBinding());

    expect(() => runtime.createIncrementalSanitizer({ limits: LIMITS })).toThrowError(
      expect.objectContaining({ code: "NOT_INITIALIZED" }),
    );
  });
});

describe("binding handles", () => {
  it("returns the handle a scan produced back to redact", async () => {
    const { NATIVE_HANDLE } = await import("../src/native.js");
    const handle = { opaque: true };
    const binding = createFakeBinding({
      findings: [{ ...sampleFinding, [NATIVE_HANDLE]: handle }],
    });
    const runtime = createRedactSecretRuntime(async () => binding);
    await runtime.initialize();

    const input = "API_KEY=SYNTHETIC_REVOKED_CONTEXT_VALUE";
    const findings = runtime.scan(input);
    const [finding] = findings;

    expect(finding).toEqual({
      id: "finding-1",
      type: "contextual_secret",
      detector: "generic-token",
      confidence: "high",
      action: "redact",
      start: 8,
      end: 39,
    });
    expect(Object.keys(finding ?? {})).not.toContain("opaque");
    expect(
      (finding as unknown as Record<symbol, unknown>)[NATIVE_HANDLE],
    ).toBe(handle);
    expect(runtime.redact(input, findings)).toBe("<SECRET_1>");
  });
});

describe("error normalization", () => {
  it("rewrites a binding's coded error as a SecretScanError", async () => {
    const nativeError = Object.assign(new Error("Redaction findings are invalid."), {
      code: "INVALID_FINDINGS",
    });
    const runtime = createRedactSecretRuntime(async () =>
      createFakeBinding({ throwOnScan: nativeError }),
    );
    await runtime.initialize();

    expect(() => runtime.scan("API_KEY=x")).toThrowError(SecretScanError);
    expect(() => runtime.scan("API_KEY=x")).toThrowError(
      expect.objectContaining({ code: "INVALID_FINDINGS" }),
    );
  });

  it("replaces an uncoded failure rather than surfacing its message", async () => {
    const runtime = createRedactSecretRuntime(async () =>
      createFakeBinding({ throwOnScan: new Error("segfault at 0xdeadbeef") }),
    );
    await runtime.initialize();

    expect(() => runtime.scan("API_KEY=x")).toThrowError(
      new SecretScanError("DETECTOR_FAILURE"),
    );
  });

  it("rejects a non-string input once initialized", async () => {
    const runtime = createRedactSecretRuntime(async () => createFakeBinding());
    await runtime.initialize();

    expect(() => runtime.scan(42 as unknown as string)).toThrowError(
      new SecretScanError("INVALID_INPUT"),
    );
  });
});

describe("unpaired surrogates", () => {
  it("rejects a lone high surrogate before it reaches the binding", async () => {
    const binding = createFakeBinding();
    const runtime = createRedactSecretRuntime(async () => binding);
    await runtime.initialize();

    for (const call of [
      () => runtime.scan("\uD800key"),
      () => runtime.redact("\uD800key", []),
      () => runtime.scanAndRedact("\uD800key"),
    ]) {
      expect(call).toThrowError(new SecretScanError("UNPAIRED_SURROGATE"));
    }
    expect(binding.calls).toEqual(["initialize"]);
  });

  it("rejects a lone low surrogate", async () => {
    const runtime = createRedactSecretRuntime(async () => createFakeBinding());
    await runtime.initialize();

    expect(() => runtime.scan("key\uDC00")).toThrowError(
      new SecretScanError("UNPAIRED_SURROGATE"),
    );
  });

  it("rejects a surrogate pair reversed into two lone surrogates", async () => {
    const runtime = createRedactSecretRuntime(async () => createFakeBinding());
    await runtime.initialize();

    // \uDC00\uD800 is a low surrogate followed by a high surrogate — the
    // opposite of a valid pair, so both code units are lone.
    expect(() => runtime.scan("\uDC00\uD800")).toThrowError(
      new SecretScanError("UNPAIRED_SURROGATE"),
    );
  });

  it("does not reject a well-formed surrogate pair", async () => {
    const binding = createFakeBinding();
    const runtime = createRedactSecretRuntime(async () => binding);
    await runtime.initialize();

    expect(() => runtime.scan("\u{1F511}key")).not.toThrow();
    expect(binding.calls).toEqual(["initialize", "scan:\u{1F511}key:builtin"]);
  });

  it.each([42, "\uD800", "\uDC00"])(
    "discards the native session on invalid incremental input (%j)",
    async (chunk) => {
      const binding = createFakeBinding();
      const runtime = createRedactSecretRuntime(async () => binding);
      await runtime.initialize();
      const session = runtime.createIncrementalSanitizer({ limits: LIMITS });
      session.append("🔑SYNTHETIC_REVOKED_RETAINED_TEXT");

      expect(() => session.append(chunk as string)).toThrowError(
        new SecretScanError(typeof chunk === "string" ? "UNPAIRED_SURROGATE" : "INVALID_INPUT"),
      );
      expect(binding.calls.filter((call) => call === "abort")).toHaveLength(1);
      expect(session.state).toBe("failed");
      for (const operation of [
        () => session.append("x"), () => session.append(chunk as string),
        () => session.finalize(), () => session.abort(),
      ]) {
        expect(operation).toThrowError(new SecretScanError("INVALID_STATE"));
        expect(session.state).toBe("failed");
      }
      expect(binding.calls.filter((call) => call === "abort")).toHaveLength(1);
    },
  );
});
