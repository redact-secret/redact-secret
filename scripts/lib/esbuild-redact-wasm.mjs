// A thin esbuild plugin for a generated custom artifact: esbuild bundles the glue but not the `.wasm` it
// loads relative to its own URL, so the plugin copies the artifact's binary next to the bundle.
import { copyFileSync, mkdirSync, readdirSync } from "node:fs";
import { dirname, join } from "node:path";

export function copyRedactWasm({ artifactDir }) {
  return {
    name: "redact-secret-wasm",
    setup(build) {
      build.onEnd((result) => {
        if (result.errors.length > 0) return;
        const outfile = build.initialOptions.outfile ?? join(build.initialOptions.outdir, "index.js");
        mkdirSync(dirname(outfile), { recursive: true });
        for (const name of readdirSync(artifactDir).filter((file) => file.endsWith("_bg.wasm"))) {
          copyFileSync(join(artifactDir, name), join(dirname(outfile), name));
        }
      });
    },
  };
}
