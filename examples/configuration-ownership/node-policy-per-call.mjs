import { compareActionPolicies, initialize, scanAndRedact } from "@redact-secret/core";

await initialize();

// The action policy is an argument of each call. Nothing is configured once,
// and a second policy in the same thread never affects the first.
const TEXT = "API_KEY=" + ["ghp", "_SYNTHETICREVOKED", "0".repeat(20)].join("");
const keepGithub = {
  actionPolicyRevision: 1,
  base: "default",
  rules: [{ id: "keep-github", match: { type: ["github_token"] }, action: "warn" }],
};

console.log("default:", scanAndRedact(TEXT).text === TEXT ? "unchanged" : "redacted");
console.log("keep-github:", scanAndRedact(TEXT, { actionPolicy: keepGithub }).text === TEXT ? "unchanged" : "redacted");

// A policy change is previewed over one detection pass before it is adopted.
const comparison = compareActionPolicies(TEXT, {
  policies: [{ kind: "default" }, { kind: "action-policy", actionPolicy: keepGithub }],
});
const [finding] = comparison.findings;
console.log(finding.decisions.map((decision) => decision.action).join(" -> "), "changed:", comparison.changedCount);
