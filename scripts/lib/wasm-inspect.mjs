/**
 * Reachability and size evidence for a built WebAssembly artifact (issue
 * #1253). Manifest metadata says what a build asked for; this reads the
 * produced binary, so a claim that excluded detector code is gone is checked
 * against the bytes, not against a list.
 *
 * Three independent observations, each a pure function of the bytes:
 *
 * - the export surface (`WebAssembly.Module.exports`);
 * - which literal byte strings the binary contains: a provider token prefix
 *   such as a detector's required literal lives only in that detector's data,
 *   so its absence means the detector's grammar is not linked;
 * - the set of identifier-like words the binary holds, compared with a `full`
 *   build of the same source: words the custom artifact lacks are code and data
 *   that were removed. Words are compared one by one because the linker lays
 *   neighbouring constants out as one run, so whole runs differ between two
 *   builds even where every constant is shared; the count is a magnitude, not
 *   a proof, and the probes below are the proof for named detectors.
 *
 * None of this is a guarantee about size or speed: the engine floor (the
 * pipeline, overlap resolution, redaction, the incremental retention logic
 * and the dependency code) stays in every artifact.
 */

import { brotliCompressSync, constants, gzipSync } from "node:zlib";

/** Printable ASCII runs of at least `minimum` bytes, as a set of strings. */
export function printableRuns(bytes, minimum = 8) {
  const runs = new Set();
  let start = -1;
  for (let index = 0; index <= bytes.length; index += 1) {
    const printable = index < bytes.length && bytes[index] >= 0x20 && bytes[index] < 0x7f;
    if (printable) {
      if (start < 0) start = index;
    } else if (start >= 0) {
      if (index - start >= minimum) runs.add(Buffer.from(bytes.subarray(start, index)).toString("latin1"));
      start = -1;
    }
  }
  return runs;
}

/** Identifier-like words (letters, digits and `_ . : / -`) of at least `minimum` bytes. */
export function words(bytes, minimum = 6) {
  const found = new Set();
  const text = Buffer.from(bytes).toString("latin1");
  for (const match of text.matchAll(/[A-Za-z0-9_.:/-]+/gu)) {
    if (match[0].length >= minimum) found.add(match[0]);
  }
  return found;
}

/** Whether `bytes` contains the ASCII `literal`. */
export function containsLiteral(bytes, literal) {
  return Buffer.from(bytes).includes(Buffer.from(literal, "latin1"));
}

/** The export names of a WebAssembly binary, sorted. */
export function wasmExports(bytes) {
  const module = new WebAssembly.Module(bytes);
  return WebAssembly.Module.exports(module)
    .map((entry) => entry.name)
    .sort();
}

/** Raw, gzip and brotli sizes of a binary. */
export function sizes(bytes) {
  return {
    raw: bytes.length,
    gzip: gzipSync(bytes, { level: 9 }).length,
    brotli: brotliCompressSync(bytes, {
      params: { [constants.BROTLI_PARAM_QUALITY]: 11, [constants.BROTLI_PARAM_SIZE_HINT]: bytes.length },
    }).length,
  };
}

/**
 * Compares a custom binary with a `full` baseline built from the same source.
 *
 * @param {Uint8Array} custom
 * @param {Uint8Array} full
 * @param {{ probes?: { id: string, literals: string[], selected: boolean }[] }} [options]
 *   Detector probe literals: the strings only that detector carries, and
 *   whether the composition selected it.
 */
export function measureElimination(custom, full, { probes = [] } = {}) {
  const customWords = words(custom);
  const fullWords = words(full);
  let absent = 0;
  for (const word of fullWords) if (!customWords.has(word)) absent += 1;
  const customSizes = sizes(custom);
  const fullSizes = sizes(full);
  return {
    custom: customSizes,
    full: fullSizes,
    ratio: {
      raw: customSizes.raw / fullSizes.raw,
      brotli: customSizes.brotli / fullSizes.brotli,
    },
    words: { full: fullWords.size, custom: customWords.size, inFullButNotInCustom: absent },
    probes: probes.map((probe) => ({
      id: probe.id,
      selected: probe.selected,
      inFull: probe.literals.every((literal) => containsLiteral(full, literal)),
      inCustom: probe.literals.some((literal) => containsLiteral(custom, literal)),
    })),
  };
}
