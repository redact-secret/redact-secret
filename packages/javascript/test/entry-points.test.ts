import { describe, expect, it } from "vitest";

import * as common from "../src/common.js";
import { defaultPlaceholderFormatter, typedPlaceholderFormatter } from "../src/formatters.js";
import * as full from "../src/index.js";
import type { SecretFinding } from "../src/types.js";

const OPERATIONS = [
  "initialize",
  "piiActivation",
  "status",
  "artifact",
  "scan",
  "redact",
  "scanAndRedact",
  "createIncrementalSanitizer",
] as const;

describe("entry points", () => {
  it("declares the detector profile each entry point is built from", () => {
    expect(full.PROFILE).toBe("full");
    expect(common.PROFILE).toBe("common");
  });

  it.each([
    ["full", full],
    ["common", common],
  ] as const)("exposes every operation on the %s entry point", (_name, entry) => {
    for (const operation of OPERATIONS) {
      expect(typeof entry[operation]).toBe("function");
    }
  });
});

describe("placeholder formatters", () => {
  const finding = { type: "aws.access-key-id" } as unknown as SecretFinding;
  const context = { placeholderIndex: 2 } as Parameters<typeof defaultPlaceholderFormatter>[1];

  it("formats the default placeholder by replacement order", () => {
    expect(defaultPlaceholderFormatter(finding, context)).toBe("<SECRET_2>");
  });

  it("formats the typed placeholder with an upper-cased type", () => {
    expect(typedPlaceholderFormatter(finding, context)).toBe("<AWS_ACCESS_KEY_ID_2>");
  });
});
