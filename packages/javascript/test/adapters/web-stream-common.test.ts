import { describe, expect, it } from "vitest";

import { WebStreamSanitizer as FullWebStreamSanitizer } from "../../src/adapters/web-stream.js";
import { LIMITS } from "./support.js";

/**
 * `./web-stream-common.ts` only adds a `common`-bound
 * `createWebStreamSanitizer` factory: the `WebStreamSanitizer` class itself
 * is the exact same session-free class `./web-stream.ts` re-exports from
 * `./web-stream-core.ts` (issue #416), and every byte-boundary/UTF-8/
 * lifecycle behavior for it is already covered by `web-stream.test.ts`
 * against that one class.
 */
describe("Web stream adapter (common profile)", () => {
  it("re-exports the identical WebStreamSanitizer class as the full-profile module", async () => {
    const { WebStreamSanitizer } = await import(
      "../../src/adapters/web-stream-common.js"
    );

    expect(WebStreamSanitizer).toBe(FullWebStreamSanitizer);
  });

  it("refuses to open a stream before initialize succeeds", async () => {
    const { createWebStreamSanitizer } = await import(
      "../../src/adapters/web-stream-common.js"
    );

    expect(() => createWebStreamSanitizer({ limits: LIMITS })).toThrowError(
      expect.objectContaining({
        name: "SecretScanError",
        code: "NOT_INITIALIZED",
      }),
    );
  });
});
