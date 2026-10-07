import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { typedPlaceholderFormatter } from "../src/formatters.js";
import type { PlaceholderContext, SecretFinding } from "../src/types.js";

const INVENTORY = JSON.parse(
  readFileSync(fileURLToPath(new URL("../../../docs/coverage/detector-inventory.json", import.meta.url)), "utf8"),
) as { types: { type: string }[] };

/**
 * The core's `typed_placeholder_formatter` rule, restated without
 * `toUpperCase`: ASCII `a`-`z` only (`to_ascii_uppercase`), then `.` and `-`
 * become `_`. Anything else, including non-ASCII letters, is left unchanged.
 */
function coreTypedPlaceholder(type: string, index: number): string {
  let out = "";
  for (const char of type) {
    const code = char.charCodeAt(0);
    if (char.length === 1 && code >= 0x61 && code <= 0x7a) out += String.fromCharCode(code - 0x20);
    else if (char === "." || char === "-") out += "_";
    else out += char;
  }
  return `<${out}_${index}>`;
}

function format(type: string, index: number): string {
  return typedPlaceholderFormatter({ type } as SecretFinding, { placeholderIndex: index } as PlaceholderContext);
}

describe("typedPlaceholderFormatter", () => {
  const names = [...new Set(INVENTORY.types.map((entry) => entry.type))];

  it("reads a non-trivial built-in type inventory", () => {
    expect(names.length).toBeGreaterThan(100);
  });

  it.each(names)("agrees with the core for built-in type %s", (type) => {
    expect(format(type, 7)).toBe(coreTypedPlaceholder(type, 7));
  });

  it("matches the documented examples", () => {
    expect(format("jwt", 1)).toBe("<JWT_1>");
    expect(format("aws_access_key_id", 2)).toBe("<AWS_ACCESS_KEY_ID_2>");
    expect(format("a.b-c", 3)).toBe("<A_B_C_3>");
  });

  it("folds case over ASCII only, like the core, for non-ASCII type names", () => {
    expect(format("straße", 1)).toBe("<STRAßE_1>");
    expect(format("ıd", 1)).toBe("<ıD_1>");
    expect(format("ǆx", 1)).toBe("<ǆX_1>");
    expect(format("ß", 1)).not.toBe("<SS_1>");
    for (const type of ["straße", "ıd", "ǆx", "café.key-é", "键"]) {
      expect(format(type, 4)).toBe(coreTypedPlaceholder(type, 4));
    }
  });
});
