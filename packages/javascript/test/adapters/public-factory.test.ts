import { Readable, Writable } from "node:stream";
import { pipeline } from "node:stream/promises";
import { afterEach, expect, it, vi } from "vitest";

import { SecretScanError } from "../../src/errors.js";
import type { NativeIncrementalSanitizer } from "../../src/native.js";
import { createRedactSecretRuntime } from "../../src/runtime.js";
import type { IncrementalSanitizerOptions } from "../../src/types.js";
import { createSanitizingBinding } from "../sanitizing-binding.js";
import { LIMITS } from "./support.js";

const INPUT = "api_key=SYNTHETIC_REVOKED_FACTORY\n";
const EXPECTED = "api_key=<SECRET_1>\n";
const rows = [
  ["node", "full", "../../src/adapters/node-stream.js"],
  ["node", "common", "../../src/adapters/node-stream-common.js"],
  ["web", "full", "../../src/adapters/web-stream.js"],
  ["web", "common", "../../src/adapters/web-stream-common.js"],
] as const;

afterEach(() => {
  vi.doUnmock("../../src/session.js");
  vi.doUnmock("../../src/session-common.js");
  vi.resetModules();
});

it.each(rows)("%s/%s public factory rejects keys synchronously before pipeline setup", async (kind, profile, path) => {
  vi.resetModules();
  const binding = createSanitizingBinding();
  const allocate = vi.spyOn(binding, "createIncrementalSanitizer");
  const runtime = createRedactSecretRuntime(async () => ({ ...binding, profile: () => profile }), profile);
  vi.doMock(profile === "full" ? "../../src/session.js" : "../../src/session-common.js", () => ({ runtime }));
  const module = await import(path);
  const open = kind === "node" ? module.createNodeStreamSanitizer : module.createWebStreamSanitizer;
  const evaluate = vi.fn(() => "redact" as const);
  const policy = { evaluate };
  const formatter = vi.fn(() => "<SECRET_1>");
  let getterReads = 0;
  const options = [
    { limits: LIMITS, ruleset: "SYNTHETIC_REVOKED_RULESET" },
    { limits: LIMITS, ruleset: undefined },
    Object.assign(Object.create({ ruleset: "SYNTHETIC_REVOKED_RULESET" }), { limits: LIMITS }),
    Object.assign(Object.create({ ruleset: undefined }), { limits: LIMITS }),
    Object.assign(
      Object.create(
        Object.defineProperty({}, "ruleset", {
          get() {
            getterReads += 1;
            throw new Error("must not read");
          },
        }),
      ),
      { limits: LIMITS },
    ),
  ].map((option) => Object.assign(option, { policy, placeholderFormatter: formatter }) as IncrementalSanitizerOptions);
  for (const option of options) {
    expect(() => open(option)).toThrowError(expect.objectContaining({ code: "NOT_INITIALIZED" }));
  }
  await runtime.initialize();
  for (const option of options) {
    let sourceReads = 0;
    const destination = vi.fn();
    const nodeSource = Readable.from(
      (async function* () {
        sourceReads += 1;
        yield Buffer.from(INPUT);
      })(),
    );
    const webSource = new ReadableStream<Uint8Array>(
      {
        pull(controller) {
          sourceReads += 1;
          controller.enqueue(new TextEncoder().encode(INPUT));
          controller.close();
        },
      },
      { highWaterMark: 0 },
    );
    const constructAndConnect = () =>
      kind === "node"
        ? pipeline(
            nodeSource,
            open(option),
            new Writable({
              write(chunk, _encoding, done) {
                destination(chunk);
                done();
              },
            }),
          )
        : webSource.pipeThrough(open(option)).pipeTo(new WritableStream({ write: destination }));
    let error: unknown;
    try {
      constructAndConnect();
    } catch (caught) {
      error = caught;
    }
    expect(error).toBeInstanceOf(SecretScanError);
    expect(error).toMatchObject({ code: "INVALID_OPTIONS", message: new SecretScanError("INVALID_OPTIONS").message });
    expect(sourceReads).toBe(0);
    expect(destination).not.toHaveBeenCalled();
    nodeSource.destroy();
    await webSource.cancel();
  }
  expect(getterReads).toBe(0);
  expect(allocate).not.toHaveBeenCalled();
  expect(evaluate).not.toHaveBeenCalled();
  expect(formatter).not.toHaveBeenCalled();
});

it.each(rows)(
  "%s/%s public factory processes absent-key input and aborts on a source failure",
  async (kind, profile, path) => {
    vi.resetModules();
    const binding = createSanitizingBinding();
    const sessions: NativeIncrementalSanitizer[] = [];
    const create = binding.createIncrementalSanitizer;
    binding.createIncrementalSanitizer = (options) => {
      const session = create(options);
      sessions.push(session);
      return session;
    };
    const runtime = createRedactSecretRuntime(async () => ({ ...binding, profile: () => profile }), profile);
    vi.doMock(profile === "full" ? "../../src/session.js" : "../../src/session-common.js", () => ({ runtime }));
    const module = await import(path);
    const open = kind === "node" ? module.createNodeStreamSanitizer : module.createWebStreamSanitizer;
    await runtime.initialize();
    const output: string[] = [];
    const sanitizer = open({ limits: LIMITS });
    if (kind === "node") {
      await pipeline(
        Readable.from([Buffer.from(INPUT)]),
        sanitizer,
        new Writable({
          write(chunk, _encoding, done) {
            output.push(chunk.toString());
            done();
          },
        }),
      );
    } else {
      await new ReadableStream<Uint8Array>({
        start(controller) {
          controller.enqueue(new TextEncoder().encode(INPUT));
          controller.close();
        },
      })
        .pipeThrough(sanitizer)
        .pipeTo(
          new WritableStream<string>({
            write(chunk) {
              output.push(chunk);
            },
          }),
        );
    }
    expect(output.join("")).toBe(EXPECTED);
    expect(sanitizer.findings).toHaveLength(1);
    expect(sessions[0]?.state).toBe("finalized");
    const failure = new Error("synthetic source failure");
    const failed = open({ limits: LIMITS });
    const rejected =
      kind === "node"
        ? pipeline(
            Readable.from(
              (async function* () {
                yield Buffer.from("api_key=SYNTHETIC_REVOKED_PENDING");
                throw failure;
              })(),
            ),
            failed,
            new Writable({
              write(_chunk, _encoding, done) {
                done();
              },
            }),
          )
        : new ReadableStream<Uint8Array>({
            pull(controller) {
              controller.error(failure);
            },
          })
            .pipeThrough(failed)
            .pipeTo(new WritableStream());
    await expect(rejected).rejects.toBe(failure);
    expect(sessions[1]?.state).toBe("aborted");
    expect(failed.findings).toEqual([]);
  },
);
