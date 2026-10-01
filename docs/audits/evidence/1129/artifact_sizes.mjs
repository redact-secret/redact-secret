#!/usr/bin/env node
// Raw, gzip -9 and brotli -11 byte sizes of the given files (deterministic).
// Usage: node artifact_sizes.mjs <file>...
import { readFileSync } from "node:fs";
import { gzipSync, brotliCompressSync, constants } from "node:zlib";
for (const file of process.argv.slice(2)) {
  const bytes = readFileSync(file);
  const gz = gzipSync(bytes, { level: 9 }).length;
  const br = brotliCompressSync(bytes, { params: { [constants.BROTLI_PARAM_QUALITY]: 11, [constants.BROTLI_PARAM_LGWIN]: 24, [constants.BROTLI_PARAM_SIZE_HINT]: bytes.length } }).length;
  console.log(`${file}\traw ${bytes.length}\tgzip9 ${gz}\tbrotli11 ${br}`);
}
