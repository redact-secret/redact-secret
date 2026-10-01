import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    include: ["test/**/*.test.ts"],
    // Only applies under `--coverage` (`npm run js:coverage`). The tests import
    // `src/*.ts` directly, so v8 coverage is already source-level and needs no
    // `dist` mapping. The 80% floor is the OpenSSF silver
    // `test_statement_coverage80` bar, not the current level.
    coverage: {
      provider: "v8",
      include: ["src/**/*.ts"],
      exclude: ["src/**/*.d.ts"],
      reporter: ["text-summary", "text"],
      thresholds: { statements: 80, lines: 80 },
    },
  },
});
