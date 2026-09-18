/**
 * The profile-agnostic body of the published package's browser qualification
 * checks (`decision-define-detector-profile-and-pack-contract`).
 *
 * `scripts/browser-package-harness.mjs` and
 * `scripts/browser-package-harness-common.mjs` are the two thin, per-profile
 * entry points that import their own package entry (`@redact-secret/core` or
 * `@redact-secret/core/common`) with a literal specifier — required so a
 * bundler resolves and includes the right compiled artifact — and hand the
 * resulting bindings to `qualify` here. Every check below is otherwise
 * identical between profiles: `common`'s findings differ from `full`'s by
 * design (fewer built-in detectors), and `fixtures` already carries the
 * right per-profile expectations (`scripts/qualify-browser-artifact.mjs`'s
 * `buildFixtures`), so this file does not need to know which profile it is
 * running against.
 *
 * `api.WebStreamSanitizer` is optional. `@redact-secret/core/web-stream`'s
 * convenience export, `createWebStreamSanitizer`, is not profile-aware — it
 * always opens its session against the `full` registry
 * (`packages/javascript/src/adapters/web-stream.ts` imports `runtime` from
 * `../session.js`, unconditionally) — and merely importing anything from that
 * module pulls in `full`'s WebAssembly artifact loader, which would defeat
 * `common`'s entire bundle-size purpose if the common harness imported it too.
 * `scripts/browser-package-harness-common.mjs` therefore omits it, and every
 * check that needs it is skipped rather than failed. This is a real, recorded
 * limitation (see the issue #382 evidence record), not a gap in this harness.
 */

import { qualifyIncrementalInput } from "./qualify-incremental-input.mjs";

const results = [];
let failures = 0;

async function checkAsync(name, run) {
  try {
    await run();
    results.push({ name, ok: true });
  } catch (error) {
    failures += 1;
    results.push({
      name,
      ok: false,
      detail: error instanceof Error ? error.message : String(error),
    });
  }
}

function check(name, run) {
  try {
    run();
    results.push({ name, ok: true });
  } catch (error) {
    failures += 1;
    results.push({
      name,
      ok: false,
      detail: error instanceof Error ? error.message : String(error),
    });
  }
}

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

function assertEqual(actual, expected, message) {
  const left = JSON.stringify(actual);
  const right = JSON.stringify(expected);
  if (left !== right) throw new Error(`${message}: expected ${right}, got ${left}`);
}

const encoder = new TextEncoder();
const decoder = new TextDecoder();

/** Independent of the binding under test, as in the artifact harness. */
function byteOffsetToCodeUnitOffset(text, byteOffset) {
  return decoder.decode(encoder.encode(text).slice(0, byteOffset)).length;
}

function expectedTuples(text, expected) {
  return expected.map((item) => [
    item.detector,
    item.type,
    item.confidence,
    byteOffsetToCodeUnitOffset(text, item.start),
    byteOffsetToCodeUnitOffset(text, item.end),
  ]);
}

function actualTuples(findings) {
  return findings.map((finding) => [
    finding.detector,
    finding.type,
    finding.confidence,
    finding.start,
    finding.end,
  ]);
}

/**
 * Runs every check against `api`, the one package entry's exports
 * (`{ RANGE_UNIT, SecretScanError, VERSION, createIncrementalSanitizer,
 * initialize, redact, scan, scanAndRedact, WebStreamSanitizer? }`).
 * `WebStreamSanitizer` is optional; see this file's module comment.
 */
export async function qualify(fixtures, api) {
  const {
    RANGE_UNIT,
    SecretScanError,
    VERSION,
    createIncrementalSanitizer,
    initialize,
    redact,
    scan,
    scanAndRedact,
    WebStreamSanitizer,
  } = api;

  // The gate first: nothing below is reachable until one `initialize()` has
  // resolved, and it must resolve against a real artifact, not a double.
  check("operations before initialize fail with NOT_INITIALIZED", () => {
    let thrown;
    try {
      scan("AKIASYNTHETICEXAMPLE0");
    } catch (error) {
      thrown = error;
    }
    assert(thrown !== undefined, "scan resolved before initialize()");
    assert(thrown instanceof SecretScanError, "a foreign error escaped the package");
    assertEqual(thrown.code, "NOT_INITIALIZED", "pre-initialize code");
  });

  await initialize();
  await initialize();

  check("the package reports its documented identity", () => {
    assertEqual(RANGE_UNIT, "utf16-code-units", "RANGE_UNIT");
    assertEqual(VERSION, fixtures.version, "VERSION");
  });

  check("invalid incremental input is terminal with fixed diagnostics", () => {
    qualifyIncrementalInput(createIncrementalSanitizer, SecretScanError);
  });

  const synchronous = fixtures.synchronous;
  check("the package matches the canonical synchronous corpus", () => {
    const mismatched = [];
    for (const fixture of synchronous) {
      const actual = actualTuples(scan(fixture.input));
      const expected = expectedTuples(fixture.input, fixture.expected);
      if (JSON.stringify(actual) !== JSON.stringify(expected)) {
        mismatched.push({ id: fixture.id, expected, actual });
      }
    }
    assert(
      mismatched.length === 0,
      `${mismatched.length} fixture(s) disagreed: ${JSON.stringify(mismatched.slice(0, 5))}`,
    );
  });

  check("every published finding is frozen and carries no extra key", () => {
    const fixture = synchronous.find((entry) => entry.expected.length > 0);
    const [finding] = scan(fixture.input);
    assert(Object.isFrozen(finding), "the package returned a mutable finding");
    assertEqual(
      Object.keys(finding).sort(),
      ["action", "confidence", "detector", "end", "id", "start", "type"],
      "published finding keys",
    );
  });

  check("scanAndRedact equals scan then redact and removes every match", () => {
    for (const fixture of synchronous) {
      if (fixture.expected.length === 0) continue;
      const { text, findings } = scanAndRedact(fixture.input);
      assertEqual(
        text,
        redact(fixture.input, scan(fixture.input)),
        `fixture ${fixture.id} scanAndRedact disagreed with scan + redact`,
      );

      // Reconstruct the exact expected output from the fixture's own
      // findings, rather than searching the output for leftover matched
      // text: some fixtures (e.g. `contextual-positive-remaining-declared-
      // names`) legitimately repeat the same synthetic value across several
      // findings that resolve to different actions, so a `warn`/`allow`
      // finding can leave a byte-identical copy of a `redact`/`block`
      // finding's value elsewhere in the output. A blanket "does the output
      // still contain this value" search cannot tell that apart from an
      // actual redaction failure; an exact positional reconstruction can.
      let placeholderIndex = 0;
      let cursor = 0;
      const pieces = [];
      for (const finding of findings) {
        if (finding.action !== "redact" && finding.action !== "block") continue;
        placeholderIndex += 1;
        pieces.push(fixture.input.slice(cursor, finding.start));
        pieces.push(`<SECRET_${placeholderIndex}>`);
        cursor = finding.end;
      }
      pieces.push(fixture.input.slice(cursor));
      assertEqual(
        text,
        pieces.join(""),
        `fixture ${fixture.id} did not produce the exact expected redacted output`,
      );
    }
  });

  check("a policy callback sees a frozen finding with numeric offsets", () => {
    const fixture = synchronous.find((entry) => entry.expected.length > 0);
    const seen = [];
    const findings = scan(fixture.input, {
      policy: {
        evaluate(finding) {
          seen.push(finding);
          return "warn";
        },
      },
    });
    for (const finding of findings) {
      assertEqual(finding.action, "warn", "the custom policy's action");
    }
    assert(seen.length > 0, "the policy was never called");
    for (const finding of seen) {
      assert(Object.isFrozen(finding), "a policy callback saw a mutable finding");
      assert(typeof finding.start === "number", "start is not a number");
      assert(typeof finding.end === "number", "end is not a number");
    }
  });

  // `bindings/wasm` builds a real session on the real artifact
  // (`decision-define-runtime-bindings`): a value split across chunks,
  // including one that only closes on the next chunk, must sanitize the
  // same way the whole-input API does and never leave the marker in its
  // output.
  check("createIncrementalSanitizer opens a real session on the real artifact", () => {
    const MARKER = "SYNTHETIC_REVOKED_BROWSER_QUALIFICATION_MARKER";
    const session = createIncrementalSanitizer({
      limits: {
        maxInputCodeUnits: 1_000_000,
        maxBufferedCodeUnits: 16_512,
        maxTokenCodeUnits: 8_192,
        maxMultilineCodeUnits: 16_384,
      },
    });
    assertEqual(session.state, "accepting", "a fresh session's state");

    let sanitized = "";
    for (const chunk of [
      `api_key=${MARKER.slice(0, 10)}`,
      `${MARKER.slice(10)}\n`,
      "tail",
    ]) {
      sanitized += session.append(chunk).text;
    }
    sanitized += session.finalize().text;
    assertEqual(session.state, "finalized", "a finalized session's state");
    assert(!sanitized.includes(MARKER), "the session left the marker in its output");
    assert(sanitized.endsWith("tail"), "the session dropped trailing plaintext");
  });

  check("a session outside accepting rejects further operations with INVALID_STATE", () => {
    const session = createIncrementalSanitizer({
      limits: {
        maxInputCodeUnits: 1_000_000,
        maxBufferedCodeUnits: 16_512,
        maxTokenCodeUnits: 8_192,
        maxMultilineCodeUnits: 16_384,
      },
    });
    session.finalize();

    let thrown;
    try {
      session.append("ignored");
    } catch (error) {
      thrown = error;
    }
    assert(thrown !== undefined, "a finalized session accepted another append");
    assert(thrown instanceof SecretScanError, "a foreign error escaped the package");
    assertEqual(thrown.code, "INVALID_STATE", "post-finalize append code");
  });

  // The Web `TransformStream` adapter, wrapped around the same real session
  // as the checks above, on the real WebAssembly artifact. Skipped when the
  // caller omitted `WebStreamSanitizer` (see this file's module comment).
  if (WebStreamSanitizer === undefined) {
    return { ok: failures === 0, failures, checks: results };
  }

  // `fixture` is one canonical, single-finding corpus entry: real enough that
  // an actual detector must decide it, synthetic enough to publish. It is
  // wrapped in astral-plane padding on its own lines so byte-partitioning
  // also exercises a decoder split mid-character without disturbing the
  // fixture's own line-start context. Every expectation below is
  // self-consistent — computed from one whole-input operation on the same
  // real artifact rather than a hardcoded string.
  const STREAM_LIMITS = {
    maxInputCodeUnits: 1_000_000,
    maxBufferedCodeUnits: 16_512,
    maxTokenCodeUnits: 8_192,
    maxMultilineCodeUnits: 16_384,
  };
  const streamEncoder = new TextEncoder();
  const streamFixture = synchronous.find((entry) => entry.expected.length === 1);
  assert(
    streamFixture !== undefined,
    "no single-finding fixture available for the stream adapter checks",
  );

  function openStreamSession() {
    return createIncrementalSanitizer({ limits: STREAM_LIMITS });
  }

  function oracle(text) {
    return scanAndRedact(text);
  }

  async function sanitizeChunks(chunks) {
    const transform = new WebStreamSanitizer(openStreamSession());
    const writer = transform.writable.getWriter();
    const reader = transform.readable.getReader();
    const output = [];
    const writing = (async () => {
      for (const chunk of chunks) await writer.write(chunk);
      await writer.close();
    })();
    const reading = (async () => {
      for (;;) {
        const result = await reader.read();
        if (result.done) break;
        output.push(result.value);
      }
    })();
    await Promise.all([writing, reading]);
    return { text: output.join(""), findings: transform.findings };
  }

  /** Writes `input` and returns the one value the reader receives for it. */
  async function writeAndRead(writer, reader, input) {
    const writing = writer.write(streamEncoder.encode(input));
    const result = await reader.read();
    await writing;
    assert(result.done === false, "expected data, not an early close");
    return result.value ?? "";
  }

  const FULL = streamFixture.input;
  const FINALIZED = `${FULL}\n`;
  // Deliberately short of a complete match: this construct can never close in
  // these checks, so it stays retained/undecided the whole time.
  const UNRESOLVED = FULL.slice(0, -5);
  const wrapped = `🔑 lead\n${FINALIZED}🔒 tail`;
  const wrappedBytes = streamEncoder.encode(wrapped);
  const expectedWrapped = oracle(wrapped);
  const finalizedOracle = oracle(FINALIZED).text;

  await checkAsync(
    "the Web stream adapter matches the whole-input result at every byte boundary on the real artifact",
    async () => {
      assert(
        expectedWrapped.text !== wrapped,
        "the real artifact left a known secret unredacted",
      );
      const diverged = [];
      for (let boundary = 0; boundary <= wrappedBytes.length; boundary += 1) {
        const actual = await sanitizeChunks([
          wrappedBytes.slice(0, boundary),
          wrappedBytes.slice(boundary),
        ]);
        if (
          actual.text !== expectedWrapped.text ||
          JSON.stringify(actual.findings) !== JSON.stringify(expectedWrapped.findings)
        ) {
          diverged.push(boundary);
        }
      }
      assert(
        diverged.length === 0,
        `${diverged.length} boundary(ies) had output or findings diverge: ${diverged.slice(0, 5).join(", ")}`,
      );
    },
  );

  await checkAsync(
    "the Web stream adapter preserves BOMs while matching whole-input scanning on the real artifact",
    async () => {
      const bomCases = [
        "﻿",
        `﻿${FINALIZED}`,
        `ordinary prefix ﻿ ${FINALIZED}`,
      ];
      const diverged = [];
      for (const bomCase of bomCases) {
        const bomBytes = streamEncoder.encode(bomCase);
        const bomExpected = oracle(bomCase);
        for (let boundary = 0; boundary <= bomBytes.length; boundary += 1) {
          const actual = await sanitizeChunks([
            bomBytes.slice(0, boundary),
            bomBytes.slice(boundary),
          ]);
          if (
            actual.text !== bomExpected.text ||
            JSON.stringify(actual.findings) !== JSON.stringify(bomExpected.findings)
          ) {
            diverged.push(`${JSON.stringify(bomCase)}@${boundary}`);
          }
        }
      }
      assert(
        diverged.length === 0,
        `${diverged.length} BOM boundary case(s) diverged: ${diverged.slice(0, 5).join(", ")}`,
      );
    },
  );

  await checkAsync(
    "the Web stream adapter's findings are frozen on the real artifact",
    async () => {
      const { findings } = await sanitizeChunks([wrappedBytes]);
      assert(
        Object.isFrozen(findings),
        "the real artifact returned a mutable findings array through the stream adapter",
      );
      assert(findings.length > 0, "expected at least one finding from the wrapped fixture");
      assert(
        Object.isFrozen(findings[0]),
        "the real artifact returned a mutable finding through the stream adapter",
      );
    },
  );

  await checkAsync(
    "an explicit abort() on the real artifact discards retained plaintext and wins over a later close",
    async () => {
      const session = openStreamSession();
      const transform = new WebStreamSanitizer(session);
      const writer = transform.writable.getWriter();
      const reader = transform.readable.getReader();
      await writer.write(streamEncoder.encode(UNRESOLVED));

      transform.abort();
      transform.abort();
      const closing = writer.close();
      const reading = reader.read();

      let closeRejection;
      try {
        await closing;
      } catch (error) {
        closeRejection = error;
      }
      assert(
        closeRejection instanceof SecretScanError,
        "close() did not reject after an explicit abort()",
      );

      let readRejection;
      try {
        await reading;
      } catch (error) {
        readRejection = error;
      }
      assert(
        readRejection instanceof SecretScanError &&
          readRejection.code === "INVALID_STATE" &&
          !readRejection.message.includes(UNRESOLVED),
        "the reader did not observe an input-free INVALID_STATE after abort()",
      );
      assertEqual(
        [...transform.findings],
        [],
        "abort() reported a finding that was never finalized",
      );
      assertEqual(session.state, "aborted", "abort() did not abort the real artifact's session");
    },
  );

  await checkAsync(
    "malformed UTF-8 on the real artifact rejects with INVALID_UTF8 and flushes no retained plaintext",
    async () => {
      const transform = new WebStreamSanitizer(openStreamSession());
      const writer = transform.writable.getWriter();
      const reader = transform.readable.getReader();
      const output = await writeAndRead(writer, reader, FINALIZED + UNRESOLVED);
      const reading = reader.read();

      let thrown;
      try {
        await writer.write(Uint8Array.of(0xc3, 0x28));
      } catch (error) {
        thrown = error;
      }
      assert(thrown instanceof SecretScanError, "the writer accepted malformed UTF-8");
      assertEqual(thrown.code, "INVALID_UTF8", "malformed UTF-8 error code");

      let readRejection;
      try {
        await reading;
      } catch (error) {
        readRejection = error;
      }
      assert(
        readRejection instanceof SecretScanError,
        "the reader did not observe the malformed UTF-8 failure",
      );
      assertEqual(
        output,
        finalizedOracle,
        "output flushed before malformed UTF-8 diverged from the oracle",
      );
      assertEqual(
        transform.findings.length,
        1,
        "expected exactly one finalized finding before the failure",
      );
    },
  );

  await checkAsync(
    "truncated UTF-8 on the real artifact rejects with INVALID_UTF8",
    async () => {
      const transform = new WebStreamSanitizer(openStreamSession());
      const writer = transform.writable.getWriter();
      const reader = transform.readable.getReader();
      const reading = reader.read().catch((error) => error);

      await writer.write(streamEncoder.encode("🔑").slice(0, 2));
      let thrown;
      try {
        await writer.close();
      } catch (error) {
        thrown = error;
      }
      assert(thrown instanceof SecretScanError, "close() accepted truncated UTF-8");
      assertEqual(thrown.code, "INVALID_UTF8", "truncated UTF-8 error code");

      const readOutcome = await reading;
      assert(
        readOutcome instanceof SecretScanError,
        "the reader did not observe the truncated UTF-8 failure",
      );
      assertEqual(readOutcome.code, "INVALID_UTF8", "truncated UTF-8 error code");
    },
  );

  await checkAsync(
    "readable backpressure on the real artifact stalls a write until a pull resumes it",
    async () => {
      const transform = new WebStreamSanitizer(openStreamSession());
      const writer = transform.writable.getWriter();
      const reader = transform.readable.getReader();
      let settled = false;
      const writing = writer.write(streamEncoder.encode("ordinary line\n")).then(() => {
        settled = true;
      });

      await Promise.resolve();
      await Promise.resolve();
      assert(!settled, "the write settled before the readable side was ever read");

      const pulled = await reader.read();
      assertEqual(pulled.value, "ordinary line\n", "the pulled value");
      await writing;
      assert(settled, "the write never settled after a pull");

      const closing = writer.close();
      const closingRead = await reader.read();
      assertEqual(closingRead.done, true, "the readable side did not close with the writable side");
      await closing;
    },
  );

  await checkAsync(
    "cancelling the readable side on the real artifact discards retained plaintext",
    async () => {
      const session = openStreamSession();
      const transform = new WebStreamSanitizer(session);
      const writer = transform.writable.getWriter();
      const reader = transform.readable.getReader();
      const pendingRead = reader.read();

      await writer.write(streamEncoder.encode(UNRESOLVED));
      await reader.cancel();

      const settled = await pendingRead;
      assertEqual(settled.done, true, "the pending read did not resolve with done after cancellation");
      assertEqual([...transform.findings], [], "cancellation reported a finding that was never finalized");
      assertEqual(session.state, "aborted", "cancellation did not abort the real artifact's session");
    },
  );

  await checkAsync(
    "aborting the writable side on the real artifact keeps finalized output but discards retained plaintext",
    async () => {
      const session = openStreamSession();
      const transform = new WebStreamSanitizer(session);
      const writer = transform.writable.getWriter();
      const reader = transform.readable.getReader();
      const output = await writeAndRead(writer, reader, FINALIZED + UNRESOLVED);
      const pendingRead = reader.read();
      const reason = new Error("Synthetic writable abort.");

      await writer.abort(reason);

      let rejection;
      try {
        await pendingRead;
      } catch (error) {
        rejection = error;
      }
      assert(rejection === reason, "the pending read did not reject with the abort reason");
      assertEqual(output, finalizedOracle, "finalized output was not preserved on writable abort");
      assertEqual(session.state, "aborted", "writable abort did not abort the real artifact's session");
    },
  );

  await checkAsync(
    "a throwing placeholder formatter on the real artifact propagates PLACEHOLDER_FAILURE and releases no plaintext",
    async () => {
      const transform = new WebStreamSanitizer(
        createIncrementalSanitizer({
          limits: STREAM_LIMITS,
          placeholderFormatter() {
            throw new Error(FULL);
          },
        }),
      );
      const writer = transform.writable.getWriter();
      const reader = transform.readable.getReader();
      const reading = reader.read().catch((error) => error);

      // `FINALIZED` closes on its own trailing newline, so the formatter can
      // run — and throw — inside this `write()` rather than waiting for
      // `close()`'s flush; either is a valid place for the real artifact to
      // surface it.
      let thrown;
      try {
        await writer.write(streamEncoder.encode(FINALIZED));
        await writer.close();
      } catch (error) {
        thrown = error;
      }
      assert(
        thrown instanceof SecretScanError,
        "no operation rejected on a formatter failure",
      );
      assertEqual(thrown.code, "PLACEHOLDER_FAILURE", "formatter failure code");

      const readOutcome = await reading;
      assert(
        readOutcome instanceof SecretScanError,
        "the reader did not observe the formatter failure",
      );
      assertEqual(readOutcome.code, "PLACEHOLDER_FAILURE", "formatter failure code");
      assert(
        !String(readOutcome).includes(FULL),
        "the formatter failure leaked the plaintext value",
      );
    },
  );

  return { ok: failures === 0, failures, checks: results };
}
