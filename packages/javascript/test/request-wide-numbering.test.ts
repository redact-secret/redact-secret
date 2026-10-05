/**
 * Request-wide placeholder numbering across several leaves (issue #1180).
 *
 * Every call numbers placeholders from 1, so a host that scans the string
 * leaves of one request needs request-wide unique numbers.
 * `docs/guides/javascript.md` ("Request-wide placeholder numbering")
 * documents a recipe that adds a running offset to
 * `context.placeholderIndex` inside a custom `placeholderFormatter`. This file
 * runs that exact recipe against the real engine, through the built package's
 * public API (resolved by its own `exports` map), and pins every claim the
 * guide makes. It adds no public API.
 *
 * A source checkout has neither the N-API addon nor the WebAssembly artifact
 * (the other tests use doubles for that reason), so when `initialize()` cannot
 * load one the suite is skipped with an explicit marker rather than passing
 * vacuously. Set `REDACT_SECRET_NUMBERING_REQUIRE_ARTIFACT=1` (CI, release
 * qualification) to turn that skip into a failure.
 *
 * Every input is synthetic.
 */

import { beforeAll, describe, expect, it } from "vitest";

type Core = typeof import("@redact-secret/core");
type PlaceholderFormatter = import("@redact-secret/core").PlaceholderFormatter;

const REQUIRE_ARTIFACT = process.env.REDACT_SECRET_NUMBERING_REQUIRE_ARTIFACT === "1";

const TOKEN_A = "ghp_SYNTHETICxREVOKEDxTESTx0000000000000";
const TOKEN_B = "ghp_SYNTHETICxREVOKEDxTESTx1111111111111";
const WARN_LINE = "password=hunter2xyz";
const PRIVATE_KEY = "-----BEGIN PRIVATE KEY-----\nU1lOVEhFVElDX1JFVk9LRURfQ09ORk9STUFOQ0U=\n-----END PRIVATE KEY-----";

let core: Core | undefined;

beforeAll(async () => {
  try {
    const loaded = await import("@redact-secret/core");
    await loaded.initialize();
    core = loaded;
  } catch {
    if (REQUIRE_ARTIFACT) {
      throw new Error(
        "request-wide numbering requires a real artifact: no usable addon or WebAssembly in this checkout",
      );
    }
  }
});

/** The documented recipe: only an integer offset survives from leaf to leaf. */
function createRequestNumbering(api: Core) {
  let replacedSoFar = 0;
  return {
    get replacedSoFar(): number {
      return replacedSoFar;
    },
    redactLeaf(leaf: string): string {
      const base = replacedSoFar;
      let used = 0;
      const placeholderFormatter: PlaceholderFormatter = (_finding, context) => {
        used = context.placeholderIndex;
        return `<SECRET_${base + context.placeholderIndex}>`;
      };
      const { text } = api.scanAndRedact(leaf, { placeholderFormatter });
      // Reached only when the call returned: a throw leaves the offset alone
      // and the host fails the whole request.
      replacedSoFar = base + used;
      return text;
    },
  };
}

function run(name: string, body: (api: Core) => void): void {
  it(name, (context) => {
    if (core === undefined) {
      context.skip();
      return;
    }
    body(core);
  });
}

describe("request-wide placeholder numbering recipe", () => {
  run("a bare call restarts at one, which is why a request needs an offset", (api) => {
    expect(api.scanAndRedact(`token=${TOKEN_A}`).text).toBe("token=<SECRET_1>");
    expect(api.scanAndRedact(`token=${TOKEN_B}`).text).toBe("token=<SECRET_1>");
  });

  run("leaves of one request are numbered uniquely in visit order", (api) => {
    const numbering = createRequestNumbering(api);
    const texts = [
      numbering.redactLeaf(`first ${TOKEN_A} and second ${TOKEN_B}`),
      numbering.redactLeaf("nothing sensitive here"),
      numbering.redactLeaf(`again ${TOKEN_A}`),
      numbering.redactLeaf(PRIVATE_KEY),
    ];
    // Several findings in one leaf take consecutive numbers, a leaf with no
    // finding consumes none, and the same value in a later leaf is a new
    // occurrence with a new number. A `block` finding is numbered like `redact`.
    expect(texts).toEqual([
      "first <SECRET_1> and second <SECRET_2>",
      "nothing sensitive here",
      "again <SECRET_3>",
      "<SECRET_4>",
    ]);
    expect(numbering.replacedSoFar).toBe(4);

    // A second request has its own offset and restarts at 1.
    expect(createRequestNumbering(api).redactLeaf(`t ${TOKEN_B}`)).toBe("t <SECRET_1>");
  });

  run("identical values in one leaf are numbered per occurrence", (api) => {
    const numbering = createRequestNumbering(api);
    expect(numbering.redactLeaf(`x ${TOKEN_A} y ${TOKEN_A}`)).toBe("x <SECRET_1> y <SECRET_2>");
    expect(numbering.replacedSoFar).toBe(2);
  });

  run("warn consumes no number and block does", (api) => {
    const actionOf = (text: string) => api.scanAndRedact(text).findings[0]?.action;
    expect(actionOf(WARN_LINE)).toBe("warn");
    expect(actionOf(PRIVATE_KEY)).toBe("block");
    expect(actionOf(TOKEN_A)).toBe("redact");

    const numbering = createRequestNumbering(api);
    expect(numbering.redactLeaf(WARN_LINE)).toBe(WARN_LINE);
    expect(numbering.replacedSoFar).toBe(0);
    expect(numbering.redactLeaf(PRIVATE_KEY)).toBe("<SECRET_1>");
    expect(numbering.redactLeaf(`t ${TOKEN_A}`)).toBe("t <SECRET_2>");
  });

  run("the offset equals the count of redact and block findings", (api) => {
    const leaf = `a ${TOKEN_A} b ${WARN_LINE} c ${TOKEN_B}`;
    const replaced = api
      .scanAndRedact(leaf)
      .findings.filter((finding) => finding.action === "redact" || finding.action === "block").length;
    const numbering = createRequestNumbering(api);
    numbering.redactLeaf(leaf);
    expect(numbering.replacedSoFar).toBe(replaced);
    expect(replaced).toBe(2);
  });

  run("a failing leaf throws and does not advance the offset", (api) => {
    const numbering = createRequestNumbering(api);
    numbering.redactLeaf(`t ${TOKEN_A}`);
    expect(() =>
      api.scanAndRedact(`t ${TOKEN_B}`, {
        placeholderFormatter: () => {
          throw new Error("synthetic formatter failure");
        },
      }),
    ).toThrow(expect.objectContaining({ code: "PLACEHOLDER_FAILURE" }));
    expect(numbering.replacedSoFar).toBe(1);
  });

  run("the same recipe numbers an incremental session per leaf", (api) => {
    // Each streamed leaf is its own session whose `placeholderIndex` counts
    // across that session's appends. The offset is read after `finalize`.
    const limits = {
      maxInputBytes: 1_000_000,
      maxBufferedBytes: 16_512,
      maxTokenBytes: 8_192,
      maxMultilineBytes: 16_384,
    };
    const leaves: ReadonlyArray<readonly [string, string]> = [
      [`first ${TOKEN_A} then `, `${TOKEN_B} end`],
      ["clean ", "tail"],
      [`again ${TOKEN_A}`, ""],
    ];
    let replacedSoFar = 0;
    const texts: string[] = [];
    for (const [head, tail] of leaves) {
      const base = replacedSoFar;
      let used = 0;
      const session = api.createIncrementalSanitizer({
        limits,
        placeholderFormatter: (_finding, context) => {
          used = context.placeholderIndex;
          return `<SECRET_${base + context.placeholderIndex}>`;
        },
      });
      texts.push(session.append(head).text + session.append(tail).text + session.finalize().text);
      replacedSoFar = base + used;
    }
    expect(texts).toEqual(["first <SECRET_1> then <SECRET_2> end", "clean tail", "again <SECRET_3>"]);
  });
});
