import { once } from "node:events";
import { Readable, Writable } from "node:stream";
import { pipeline } from "node:stream/promises";
import { describe, expect, it } from "vitest";

import { NodeStreamSanitizer } from "../../src/adapters/node-stream.js";
import { SecretScanError } from "../../src/errors.js";
import { bytes, LIMITS, openSession, oracle, partitionCorpus } from "./support.js";

const FINALIZED_INPUT = "api_key=SYNTHETIC_REVOKED_NODE_FINALIZED\n";
const FINALIZED_OUTPUT = "api_key=<SECRET_1>\n";
const UNRESOLVED_INPUT = "api_key=SYNTHETIC_REVOKED_NODE_UNRESOLVED";

async function sanitize(chunks: readonly Uint8Array[]) {
  const transform = new NodeStreamSanitizer(await openSession());
  const output: Buffer[] = [];
  for await (const chunk of Readable.from(chunks).pipe(transform)) {
    output.push(chunk as Buffer);
  }
  return {
    text: Buffer.concat(output).toString("utf8"),
    findings: transform.findings,
  };
}

describe("Node stream adapter", () => {
  it("sanitizes identically at every UTF-8 byte boundary", async () => {
    for (const fixture of partitionCorpus) {
      const expected = await oracle(fixture.input);
      const encoded = bytes(fixture.input);
      for (let boundary = 0; boundary <= encoded.length; boundary += 1) {
        const result = await sanitize([encoded.slice(0, boundary), encoded.slice(boundary)]);
        expect({ ...result, findings: [...result.findings] }, `${fixture.id}@${boundary}`).toEqual(expected);
      }
    }
  });

  it("carries one decoder across chunks that split a character", async () => {
    const encoded = bytes("🔑");
    const result = await sanitize([encoded.slice(0, 1), encoded.slice(1, 3), encoded.slice(3)]);

    expect(result.text).toBe("🔑");
  });

  it("flushes an empty stream and exposes frozen findings", async () => {
    await expect(sanitize([])).resolves.toEqual({ text: "", findings: [] });

    const result = await sanitize([bytes("api_key=SYNTHETIC_REVOKED_FINDING")]);

    expect(Object.isFrozen(result.findings)).toBe(true);
    expect(result.findings).toHaveLength(1);
    expect(Object.isFrozen(result.findings[0])).toBe(true);
    expect(() => {
      (result.findings as SecretFindingList)[0] = undefined;
    }).toThrowError(TypeError);
  });

  it("reports absolute offsets into the whole stream, not into a chunk", async () => {
    const input = "🔑 lead\napi_key=SYNTHETIC_REVOKED_ABSOLUTE\n";
    const encoded = bytes(input);
    const split = encoded.indexOf(0x0a) + 1;

    const { findings } = await sanitize([encoded.slice(0, split), encoded.slice(split)]);

    const [finding] = findings;
    expect(finding).toBeDefined();
    expect(input.slice(finding?.start, finding?.end)).toBe("SYNTHETIC_REVOKED_ABSOLUTE");
  });

  it("stalls the producer at backpressure and resumes on drain", async () => {
    const transform = new NodeStreamSanitizer(await openSession());
    const output: Buffer[] = [];
    const written: Buffer[] = [];
    let stalled = false;

    for (let index = 0; index < 512; index += 1) {
      const chunk = Buffer.from(`line-${index}-${"x".repeat(1_000)}\n`);
      written.push(chunk);
      if (!transform.write(chunk)) {
        stalled = true;
        break;
      }
    }

    expect(stalled).toBe(true);
    expect(transform.writableNeedDrain).toBe(true);
    expect(transform.readableLength).toBeGreaterThan(0);

    const drained = once(transform, "drain");
    transform.on("data", (chunk: Buffer) => output.push(chunk));
    await drained;

    const ended = once(transform, "end");
    transform.end();
    await ended;
    expect(Buffer.concat(output)).toEqual(Buffer.concat(written));
  });

  it("destroys early without releasing retained plaintext", async () => {
    const session = await openSession();
    const transform = new NodeStreamSanitizer(session);
    const output: Buffer[] = [];
    transform.on("data", (chunk: Buffer) => output.push(chunk));

    transform.write(Buffer.from(UNRESOLVED_INPUT));
    transform.destroy();
    await once(transform, "close");

    expect(Buffer.concat(output).toString("utf8")).toBe("");
    expect(transform.findings).toEqual([]);
    expect(session.state).toBe("aborted");
  });

  it("keeps finalized output but discards retained plaintext on downstream failure", async () => {
    const session = await openSession();
    const transform = new NodeStreamSanitizer(session);
    const output: Buffer[] = [];
    let supplied = false;
    const source = new Readable({
      read() {
        if (supplied) return;
        supplied = true;
        this.push(Buffer.from(FINALIZED_INPUT + UNRESOLVED_INPUT));
      },
    });
    const downstreamError = new Error("Synthetic downstream failure.");
    const sink = new Writable({
      write(chunk: Buffer, _encoding, callback) {
        output.push(chunk);
        callback(downstreamError);
      },
    });

    await expect(pipeline(source, transform, sink)).rejects.toBe(downstreamError);

    expect(Buffer.concat(output).toString("utf8")).toBe(FINALIZED_OUTPUT);
    expect(transform.destroyed).toBe(true);
    expect(session.state).toBe("aborted");
    expect(Object.isFrozen(transform.findings)).toBe(true);
    expect(transform.findings).toHaveLength(1);
  });

  it("makes destroy idempotently win over a later end", async () => {
    const transform = new NodeStreamSanitizer(await openSession());
    const output: Buffer[] = [];
    let closeCount = 0;
    transform.on("data", (chunk: Buffer) => output.push(chunk));
    transform.on("close", () => {
      closeCount += 1;
    });
    transform.write(Buffer.from(UNRESOLVED_INPUT));

    transform.destroy();
    transform.destroy();
    transform.end();
    await once(transform, "close");

    expect(closeCount).toBe(1);
    expect(Buffer.concat(output).toString("utf8")).toBe("");
    expect(transform.findings).toEqual([]);
  });

  it("propagates a fixed error and releases no retained plaintext", async () => {
    const input = "api_key=SYNTHETIC_REVOKED_NODE_FAILURE";
    const session = await openSession({
      limits: LIMITS,
      placeholderFormatter() {
        throw new Error(input);
      },
    });
    const transform = new NodeStreamSanitizer(session);
    const output: Buffer[] = [];
    transform.on("data", (chunk: Buffer) => output.push(chunk));

    transform.end(Buffer.from(input));
    const [error] = (await once(transform, "error")) as [SecretScanError];

    expect(error).toBeInstanceOf(SecretScanError);
    expect(error.code).toBe("PLACEHOLDER_FAILURE");
    expect(String(error)).not.toContain(input);
    expect(Buffer.concat(output).toString("utf8")).toBe("");
  });

  it("rejects malformed UTF-8 with a fixed error", async () => {
    const session = await openSession();
    const transform = new NodeStreamSanitizer(session);

    transform.end(Uint8Array.of(0xc3, 0x28));
    const [error] = (await once(transform, "error")) as [SecretScanError];

    expect(error).toBeInstanceOf(SecretScanError);
    expect(error.code).toBe("INVALID_UTF8");
    expect(error.message).toBe("Stream sanitizer input is not valid UTF-8.");
    expect(error).not.toHaveProperty("cause");
    expect(session.state).toBe("aborted");
  });

  it("keeps only finalized output when malformed UTF-8 follows retained plaintext", async () => {
    const transform = new NodeStreamSanitizer(await openSession());
    const output: Buffer[] = [];
    transform.on("data", (chunk: Buffer) => output.push(chunk));
    transform.write(Buffer.from(FINALIZED_INPUT + UNRESOLVED_INPUT));

    transform.end(Uint8Array.of(0xc3, 0x28));
    const [error] = (await once(transform, "error")) as [SecretScanError];

    expect(error.code).toBe("INVALID_UTF8");
    expect(Buffer.concat(output).toString("utf8")).toBe(FINALIZED_OUTPUT);
    expect(transform.findings).toHaveLength(1);
  });

  it("rejects a stream that ends mid-character", async () => {
    const transform = new NodeStreamSanitizer(await openSession());

    transform.end(bytes("🔑").slice(0, 2));
    const [error] = (await once(transform, "error")) as [SecretScanError];

    expect(error.code).toBe("INVALID_UTF8");
  });

  it("refuses to open a stream before initialize succeeds", async () => {
    const { createNodeStreamSanitizer } = await import("../../src/adapters/node-stream.js");

    expect(() => createNodeStreamSanitizer({ limits: LIMITS })).toThrowError(
      expect.objectContaining({
        name: "SecretScanError",
        code: "NOT_INITIALIZED",
      }),
    );
  });
});

type SecretFindingList = { [index: number]: unknown };
