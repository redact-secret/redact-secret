import { once } from "node:events";
import { Readable } from "node:stream";
import { describe, expect, it } from "vitest";

import { NodeStreamSanitizer } from "../../src/adapters/node-stream.js";
import { createStreamSanitizerRuntime } from "../../src/adapters/shared.js";
import { WebStreamSanitizer } from "../../src/adapters/web-stream.js";
import { SecretScanError } from "../../src/errors.js";
import type {
  IncrementalSanitizer,
  IncrementalSanitizerResult,
  SecretFinding,
} from "../../src/types.js";
import { bytes, openSession } from "./support.js";

const FINDINGS_ABOVE_ARGUMENT_CEILING = 150_000;
const STREAM_FINDING_COUNT = 130_000;

function finding(index: number, start = index * 2): SecretFinding {
  return Object.freeze({
    id: `finding-${index + 1}`,
    type: "contextual_secret",
    detector: "synthetic-regression",
    confidence: "high",
    action: "redact",
    start,
    end: start + 1,
  });
}

function findingList(count: number): readonly SecretFinding[] {
  return Object.freeze(Array.from({ length: count }, (_, index) => finding(index)));
}

function result(findings: readonly SecretFinding[]): IncrementalSanitizerResult {
  return Object.freeze({ text: "", findings });
}

function sessionWithResults(
  appendFindings: readonly SecretFinding[],
  finalFindings: readonly SecretFinding[] = [],
): IncrementalSanitizer & { readonly aborts: number } {
  let state: IncrementalSanitizer["state"] = "accepting";
  let aborts = 0;
  return {
    get state() {
      return state;
    },
    get aborts() {
      return aborts;
    },
    append: () => result(appendFindings),
    finalize: () => {
      state = "finalized";
      return result(finalFindings);
    },
    abort: () => {
      aborts += 1;
      state = "aborted";
    },
  };
}

function manyFindingInput(count: number): string {
  let input = "";
  for (let index = 0; index < count; index += 1) {
    input += `api_key=SYNTHETIC_${index}\n`;
  }
  return input;
}

function directIncremental(input: string) {
  return openSession({
    limits: {
      maxInputCodeUnits: input.length + 1,
      maxBufferedCodeUnits: 16_512,
      maxTokenCodeUnits: 8_192,
      maxMultilineCodeUnits: 16_384,
    },
  }).then((session) => {
    const appended = session.append(input);
    const finalized = session.finalize();
    return {
      text: appended.text + finalized.text,
      findings: [...appended.findings, ...finalized.findings],
    };
  });
}

async function nodeStream(input: string) {
  const transform = new NodeStreamSanitizer(
    await openSession({
      limits: {
        maxInputCodeUnits: input.length + 1,
        maxBufferedCodeUnits: 16_512,
        maxTokenCodeUnits: 8_192,
        maxMultilineCodeUnits: 16_384,
      },
    }),
  );
  const output: Buffer[] = [];
  for await (const chunk of Readable.from([bytes(input)]).pipe(transform)) {
    output.push(chunk as Buffer);
  }
  return {
    text: Buffer.concat(output).toString("utf8"),
    findings: transform.findings,
  };
}

async function webStream(input: string) {
  const transform = new WebStreamSanitizer(
    await openSession({
      limits: {
        maxInputCodeUnits: input.length + 1,
        maxBufferedCodeUnits: 16_512,
        maxTokenCodeUnits: 8_192,
        maxMultilineCodeUnits: 16_384,
      },
    }),
  );
  const writer = transform.writable.getWriter();
  const reader = transform.readable.getReader();
  const output: string[] = [];
  const writing = (async () => {
    await writer.write(bytes(input));
    await writer.close();
  })();
  const reading = (async () => {
    for (;;) {
      const chunk = await reader.read();
      if (chunk.done) break;
      output.push(chunk.value);
    }
  })();
  await Promise.all([writing, reading]);
  return { text: output.join(""), findings: transform.findings };
}

describe("stream adapter finding accumulation", () => {
  it("accumulates append findings above the engine argument ceiling", () => {
    const findings = findingList(FINDINGS_ABOVE_ARGUMENT_CEILING);
    const runtime = createStreamSanitizerRuntime(sessionWithResults(findings));

    runtime.append(bytes(""));

    expect(runtime.findings).toHaveLength(FINDINGS_ABOVE_ARGUMENT_CEILING);
    expect(runtime.findings[0]).toEqual(findings[0]);
    expect(runtime.findings.at(-1)).toEqual(findings.at(-1));
  });

  it("accumulates flushed and finalized findings above the engine argument ceiling", () => {
    const flushed = findingList(75_000);
    const finalized = findingList(75_000);
    const runtime = createStreamSanitizerRuntime(
      sessionWithResults(flushed, finalized),
    );

    runtime.finalize();

    expect(runtime.findings).toHaveLength(FINDINGS_ABOVE_ARGUMENT_CEILING);
    expect(runtime.findings[0]).toEqual(flushed[0]);
    expect(runtime.findings.at(-1)).toEqual(finalized.at(-1));
  });

  it("sanitizes the same many-finding input through direct, Node, and Web paths", async () => {
    const input = manyFindingInput(STREAM_FINDING_COUNT);
    const expected = await directIncremental(input);

    const node = await nodeStream(input);
    const web = await webStream(input);

    expect(node.text).toBe(expected.text);
    expect(web.text).toBe(expected.text);
    expect([...node.findings]).toEqual(expected.findings);
    expect([...web.findings]).toEqual(expected.findings);
    expect(node.findings).toHaveLength(STREAM_FINDING_COUNT);
    expect(web.findings).toHaveLength(STREAM_FINDING_COUNT);
  });

  it("aborts and reports a fixed error when adapter-local accumulation fails", async () => {
    const raw = new RangeError("Synthetic raw engine failure.");
    const badFindings = {
      [Symbol.iterator]() {
        throw raw;
      },
    } as unknown as readonly SecretFinding[];
    const session = sessionWithResults(badFindings);
    const transform = new NodeStreamSanitizer(session);

    transform.end(bytes(""));
    const [error] = (await once(transform, "error")) as [SecretScanError];

    expect(error).toBeInstanceOf(SecretScanError);
    expect(error.code).toBe("INVALID_STATE");
    expect(String(error)).not.toContain(raw.message);
    expect(session.state).toBe("aborted");
    expect(session.aborts).toBe(1);
  });
});
