import { describe, expect, it } from "vitest";

import { NodeStreamSanitizer as FullNodeStreamSanitizer } from "../../src/adapters/node-stream.js";
import { LIMITS } from "./support.js";

/**
 * `./node-stream-common.ts` only adds a `common`-bound
 * `createNodeStreamSanitizer` factory: the `NodeStreamSanitizer` class itself
 * is the exact same session-free class `./node-stream.ts` re-exports from
 * `./node-stream-core.ts` (issue #416), and every byte-boundary/UTF-8/
 * lifecycle behavior for it is already covered by `node-stream.test.ts`
 * against that one class.
 */
describe("Node stream adapter (common profile)", () => {
  it("re-exports the identical NodeStreamSanitizer class as the full-profile module", async () => {
    const { NodeStreamSanitizer } = await import(
      "../../src/adapters/node-stream-common.js"
    );

    expect(NodeStreamSanitizer).toBe(FullNodeStreamSanitizer);
  });

  it("refuses to open a stream before initialize succeeds", async () => {
    const { createNodeStreamSanitizer } = await import(
      "../../src/adapters/node-stream-common.js"
    );

    expect(() => createNodeStreamSanitizer({ limits: LIMITS })).toThrowError(
      expect.objectContaining({
        name: "SecretScanError",
        code: "NOT_INITIALIZED",
      }),
    );
  });
});
