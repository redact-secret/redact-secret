import * as core from "@redact-secret/core";

await core.initialize();

// `status`, `actionPolicy`, `defaultPolicy` and `compareActionPolicies` were
// added in 0.1.0-beta.14. A namespace import of an older release has no such
// property, where a named import of a missing export fails to link.
const hasStatus = typeof core.status === "function";
const hasActionPolicy = typeof core.compareActionPolicies === "function" && typeof core.defaultPolicy === "object";

const TEXT = "API_KEY=" + ["ghp", "_SYNTHETICREVOKED", "0".repeat(20)].join("");

console.log("status:", hasStatus ? JSON.stringify(core.status()) : "not available before 0.1.0-beta.14");

// Keep GitHub tokens and redact the rest. A release with action policies takes
// a declarative document; an older release takes a callback, which must itself
// spell out what the default would have done for every other finding.
const keepGithub = hasActionPolicy
  ? {
      actionPolicy: {
        actionPolicyRevision: 1,
        base: "default",
        rules: [{ id: "keep-github", match: { type: ["github_token"] }, action: "warn" }],
      },
    }
  : { policy: { evaluate: (finding) => (finding.type === "github_token" ? "warn" : "redact") } };

console.log("default:", core.scanAndRedact(TEXT).text === TEXT ? "unchanged" : "redacted");
console.log("keep-github:", core.scanAndRedact(TEXT, keepGithub).text === TEXT ? "unchanged" : "redacted");
