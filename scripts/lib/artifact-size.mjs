import { brotliCompressSync, gzipSync, constants as zlibConstants } from "node:zlib";

// Compressed-size helpers shared by the artifact measurement scripts
// (`scripts/measure-wasm-profiles.mjs`, `scripts/measure-detector-cost.mjs`).
// Levels match what the ADRs quote: gzip -9 and brotli quality 11.

export function gzipSize(buffer) {
  return gzipSync(buffer, { level: 9 }).length;
}

export function brotliSize(buffer) {
  return brotliCompressSync(buffer, {
    params: { [zlibConstants.BROTLI_PARAM_QUALITY]: 11 },
  }).length;
}
