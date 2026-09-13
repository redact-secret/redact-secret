import { describe, expect, it } from "vitest";

import { WebStreamSanitizer } from "../../src/adapters/web-stream.js";
import { SecretScanError } from "../../src/errors.js";
import {
  bytes,
  LIMITS,
  openSession,
  oracle,
  partitionCorpus,
} from "./support.js";

const FINALIZED_INPUT = "api_key=SYNTHETIC_REVOKED_WEB_FINALIZED\n";
const FINALIZED_OUTPUT = "api_key=<SECRET_1>\n";
const UNRESOLVED_INPUT = "api_key=SYNTHETIC_REVOKED_WEB_UNRESOLVED";

async function writeAndRead(
  writer: WritableStreamDefaultWriter<Uint8Array>,
  reader: ReadableStreamDefaultReader<string>,
  input: string,
): Promise<string> {
  const writing = writer.write(bytes(input));
  const result = await reader.read();
  await writing;
  expect(result.done).toBe(false);
  return result.value ?? "";
}

async function sanitize(chunks: readonly Uint8Array[]) {
  const transform = new WebStreamSanitizer(await openSession());
  const writer = transform.writable.getWriter();
  const reader = transform.readable.getReader();
  const output: string[] = [];
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

describe("Web stream adapter", () => {
  it("sanitizes identically at every UTF-8 byte boundary", async () => {
    for (const fixture of partitionCorpus) {
      const expected = await oracle(fixture.input);
      const encoded = bytes(fixture.input);
      for (let boundary = 0; boundary <= encoded.length; boundary += 1) {
        const result = await sanitize([
          encoded.slice(0, boundary),
          encoded.slice(boundary),
        ]);
        expect({ ...result, findings: [...result.findings] }, `${fixture.id}@${boundary}`)
          .toEqual(expected);
      }
    }
  });

  it("carries one decoder across chunks that split a character", async () => {
    const encoded = bytes("🔑");

    const result = await sanitize([
      encoded.slice(0, 1),
      encoded.slice(1, 3),
      encoded.slice(3),
    ]);

    expect(result.text).toBe("🔑");
  });

  it("flushes an empty stream and exposes frozen findings", async () => {
    await expect(sanitize([])).resolves.toEqual({ text: "", findings: [] });

    const result = await sanitize([bytes("api_key=SYNTHETIC_REVOKED_FINDING")]);

    expect(Object.isFrozen(result.findings)).toBe(true);
    expect(result.findings).toHaveLength(1);
    expect(Object.isFrozen(result.findings[0])).toBe(true);
  });

  it("reports absolute offsets into the whole stream, not into a chunk", async () => {
    const input = "🔑 lead\napi_key=SYNTHETIC_REVOKED_ABSOLUTE\n";
    const encoded = bytes(input);
    const split = encoded.indexOf(0x0a) + 1;

    const { findings } = await sanitize([
      encoded.slice(0, split),
      encoded.slice(split),
    ]);

    const [finding] = findings;
    expect(finding).toBeDefined();
    expect(input.slice(finding?.start, finding?.end)).toBe(
      "SYNTHETIC_REVOKED_ABSOLUTE",
    );
  });

  it("stalls writes at readable backpressure and resumes after a pull", async () => {
    const transform = new WebStreamSanitizer(await openSession());
    const writer = transform.writable.getWriter();
    const reader = transform.readable.getReader();
    let settled = false;
    const writing = writer.write(bytes("ordinary line\n")).then(() => {
      settled = true;
    });

    await Promise.resolve();
    await Promise.resolve();
    expect(settled).toBe(false);
    expect(writer.desiredSize).toBe(0);

    await expect(reader.read()).resolves.toEqual({
      value: "ordinary line\n",
      done: false,
    });
    await writing;
    expect(settled).toBe(true);

    const closing = writer.close();
    await expect(reader.read()).resolves.toEqual({
      value: undefined,
      done: true,
    });
    await closing;
  });

  it("cancels the readable side without releasing retained plaintext", async () => {
    const session = await openSession();
    const transform = new WebStreamSanitizer(session);
    const writer = transform.writable.getWriter();
    const reader = transform.readable.getReader();
    const pendingRead = reader.read();
    await writer.write(bytes(UNRESOLVED_INPUT));

    await reader.cancel();

    await expect(pendingRead).resolves.toEqual({
      value: undefined,
      done: true,
    });
    expect(transform.findings).toEqual([]);
    expect(session.state).toBe("aborted");
  });

  it("keeps finalized output but discards retained plaintext on cancellation", async () => {
    const session = await openSession();
    const transform = new WebStreamSanitizer(session);
    const writer = transform.writable.getWriter();
    const reader = transform.readable.getReader();
    const output = await writeAndRead(
      writer,
      reader,
      FINALIZED_INPUT + UNRESOLVED_INPUT,
    );
    const pendingRead = reader.read();

    await reader.cancel(new Error("Synthetic readable cancellation."));

    await expect(pendingRead).resolves.toEqual({
      value: undefined,
      done: true,
    });
    await expect(writer.close()).rejects.toBeInstanceOf(TypeError);
    expect(output).toBe(FINALIZED_OUTPUT);
    expect(session.state).toBe("aborted");
    expect(Object.isFrozen(transform.findings)).toBe(true);
    expect(transform.findings).toHaveLength(1);
  });

  it("keeps finalized output but discards retained plaintext on writable abort", async () => {
    const session = await openSession();
    const transform = new WebStreamSanitizer(session);
    const writer = transform.writable.getWriter();
    const reader = transform.readable.getReader();
    const output = await writeAndRead(
      writer,
      reader,
      FINALIZED_INPUT + UNRESOLVED_INPUT,
    );
    const pendingRead = reader.read();
    const reason = new Error("Synthetic writable abort.");

    await writer.abort(reason);

    await expect(pendingRead).rejects.toBe(reason);
    expect(output).toBe(FINALIZED_OUTPUT);
    expect(session.state).toBe("aborted");
    expect(transform.findings).toHaveLength(1);
  });

  it("makes explicit abort idempotently win when it precedes close", async () => {
    const session = await openSession();
    const transform = new WebStreamSanitizer(session);
    const writer = transform.writable.getWriter();
    const reader = transform.readable.getReader();
    await writer.write(bytes(UNRESOLVED_INPUT));

    transform.abort();
    transform.abort();
    const closing = writer.close();
    const reading = reader.read();

    await expect(closing).rejects.toBeInstanceOf(SecretScanError);
    await expect(reading).rejects.toSatisfy(
      (error: unknown) =>
        error instanceof SecretScanError &&
        error.code === "INVALID_STATE" &&
        !error.message.includes(UNRESOLVED_INPUT),
    );
    expect(transform.findings).toEqual([]);
    expect(session.state).toBe("aborted");
  });

  it("lets close finalize safely when it precedes explicit abort", async () => {
    const transform = new WebStreamSanitizer(await openSession());
    const writer = transform.writable.getWriter();
    const reader = transform.readable.getReader();
    await writer.write(bytes(UNRESOLVED_INPUT));

    const closing = writer.close();
    transform.abort();

    await expect(reader.read()).resolves.toEqual({
      value: "api_key=<SECRET_1>",
      done: false,
    });
    await expect(reader.read()).resolves.toEqual({
      value: undefined,
      done: true,
    });
    await closing;
    expect(transform.findings).toHaveLength(1);
  });

  it("propagates a fixed error and releases no retained plaintext", async () => {
    const input = "api_key=SYNTHETIC_REVOKED_WEB_FAILURE";
    const transform = new WebStreamSanitizer(
      await openSession({
        limits: LIMITS,
        placeholderFormatter() {
          throw new Error(input);
        },
      }),
    );
    const writer = transform.writable.getWriter();
    const reader = transform.readable.getReader();
    const reading = reader.read().catch((error: unknown) => error);

    await writer.write(bytes(input));

    await expect(writer.close()).rejects.toBeInstanceOf(SecretScanError);
    await expect(reading).resolves.toSatisfy(
      (error: unknown) =>
        error instanceof SecretScanError &&
        error.code === "PLACEHOLDER_FAILURE" &&
        !String(error).includes(input),
    );
  });

  it("rejects malformed UTF-8 and a chunk that is not bytes", async () => {
    const invalid = new WebStreamSanitizer(await openSession());
    const invalidWriter = invalid.writable.getWriter();
    const invalidReader = invalid.readable.getReader();
    const invalidReading = invalidReader.read().catch((error: unknown) => error);

    await expect(
      invalidWriter.write(Uint8Array.of(0xc3, 0x28)),
    ).rejects.toSatisfy(
      (error: unknown) =>
        error instanceof SecretScanError &&
        error.code === "INVALID_UTF8" &&
        !("cause" in error),
    );
    await expect(invalidReading).resolves.toBeInstanceOf(SecretScanError);

    const wrongType = new WebStreamSanitizer(await openSession());
    const wrongTypeWriter = wrongType.writable.getWriter();
    const wrongTypeReader = wrongType.readable.getReader();
    const wrongTypeReading = wrongTypeReader
      .read()
      .catch((error: unknown) => error);

    await expect(
      wrongTypeWriter.write("plain text" as unknown as Uint8Array),
    ).rejects.toSatisfy(
      (error: unknown) =>
        error instanceof SecretScanError && error.code === "INVALID_CHUNK",
    );
    await expect(wrongTypeReading).resolves.toBeInstanceOf(SecretScanError);
  });

  it("keeps only finalized output when malformed UTF-8 follows retained plaintext", async () => {
    const transform = new WebStreamSanitizer(await openSession());
    const writer = transform.writable.getWriter();
    const reader = transform.readable.getReader();
    const output = await writeAndRead(
      writer,
      reader,
      FINALIZED_INPUT + UNRESOLVED_INPUT,
    );
    const reading = reader.read();

    await expect(writer.write(Uint8Array.of(0xc3, 0x28))).rejects.toSatisfy(
      (error: unknown) =>
        error instanceof SecretScanError && error.code === "INVALID_UTF8",
    );
    await expect(reading).rejects.toBeInstanceOf(SecretScanError);
    expect(output).toBe(FINALIZED_OUTPUT);
    expect(transform.findings).toHaveLength(1);
  });

  it("rejects a stream that ends mid-character", async () => {
    const transform = new WebStreamSanitizer(await openSession());
    const writer = transform.writable.getWriter();
    const reader = transform.readable.getReader();
    const reading = reader.read().catch((error: unknown) => error);

    await expect(writer.write(bytes("🔑").slice(0, 2))).resolves.toBeUndefined();
    await expect(writer.close()).rejects.toSatisfy(
      (error: unknown) =>
        error instanceof SecretScanError && error.code === "INVALID_UTF8",
    );
    await expect(reading).resolves.toSatisfy(
      (error: unknown) =>
        error instanceof SecretScanError && error.code === "INVALID_UTF8",
    );
  });

  it("refuses to open a stream before initialize succeeds", async () => {
    const { createWebStreamSanitizer } = await import(
      "../../src/adapters/web-stream.js"
    );

    expect(() => createWebStreamSanitizer({ limits: LIMITS })).toThrowError(
      expect.objectContaining({
        name: "SecretScanError",
        code: "NOT_INITIALIZED",
      }),
    );
  });
});
