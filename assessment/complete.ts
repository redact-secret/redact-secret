import type { AssessmentResult, AssessmentSurface } from "./schema.js";

export const COMPLETE_ASSESSMENT_SCHEMA_VERSION = "1";
export const REQUIRED_ASSESSMENT_SURFACES = [
  "rust-core",
  "python",
  "node",
  "browser-wasm",
  "cli",
] as const satisfies readonly AssessmentSurface[];

export type AssessmentRunKind = "accuracy" | "performance";
export type AssessmentRunPath = "whole-input" | "incremental" | "standard-input";
export type AssessmentRunStatus = "complete" | "failed" | "missing" | "invalid";

export interface CompleteAssessmentProfile {
  readonly id: string;
  readonly chunkProfile: string;
}

export interface AssessmentAttempt {
  readonly surface: AssessmentSurface;
  readonly kind: AssessmentRunKind;
  readonly profileId: string;
  readonly resultPath: string;
  readonly markdownPath: string;
  readonly mismatchesPath?: string;
  readonly result?: AssessmentResult;
  readonly failureCode?: "runner-failed" | "result-missing" | "invalid-result";
}

export interface CompleteAssessmentRun extends AssessmentAttempt {
  readonly path: AssessmentRunPath;
  readonly status: AssessmentRunStatus;
}

export interface CompleteAssessment {
  readonly schemaVersion: typeof COMPLETE_ASSESSMENT_SCHEMA_VERSION;
  readonly status: "complete" | "incomplete";
  readonly sourceCommit?: string;
  readonly accuracyCorpus?: { readonly version: string; readonly hash: string };
  readonly workloadProfiles?: { readonly version: string; readonly hash: string };
  readonly repetitions: number;
  readonly performanceProfiles: readonly CompleteAssessmentProfile[];
  readonly requiredSurfaces: typeof REQUIRED_ASSESSMENT_SURFACES;
  readonly runs: readonly CompleteAssessmentRun[];
  readonly validationFailures: readonly string[];
}

function key(surface: AssessmentSurface, kind: AssessmentRunKind, profileId: string): string {
  return `${surface}:${kind}:${profileId}`;
}

function pathFor(surface: AssessmentSurface, profile: CompleteAssessmentProfile | undefined): AssessmentRunPath {
  if (profile === undefined || profile.chunkProfile === "whole") return "whole-input";
  return surface === "cli" ? "standard-input" : "incremental";
}

function resultKind(result: AssessmentResult): AssessmentRunKind | "mixed" {
  if (result.accuracy !== undefined && result.performance === undefined) return "accuracy";
  if (result.performance !== undefined && result.accuracy === undefined) return "performance";
  return "mixed";
}

export function buildCompleteAssessment(input: {
  readonly attempts: readonly AssessmentAttempt[];
  readonly performanceProfiles: readonly CompleteAssessmentProfile[];
  readonly repetitions: number;
  readonly validateResult: (result: AssessmentResult) => void;
}): CompleteAssessment {
  const failures: string[] = [];
  const attempts = new Map<string, AssessmentAttempt>();

  for (const attempt of input.attempts) {
    const attemptKey = key(attempt.surface, attempt.kind, attempt.profileId);
    if (attempts.has(attemptKey)) failures.push(`${attemptKey}:duplicate-run`);
    else attempts.set(attemptKey, attempt);
  }

  if (!Number.isSafeInteger(input.repetitions) || input.repetitions < 2 || input.repetitions > 100) {
    failures.push("suite:invalid-repetitions");
  }
  if (input.performanceProfiles.length === 0) failures.push("suite:no-performance-profiles");
  if (!input.performanceProfiles.some((profile) => profile.chunkProfile === "whole")) {
    failures.push("suite:missing-whole-input-profile");
  }
  if (!input.performanceProfiles.some((profile) => profile.chunkProfile !== "whole")) {
    failures.push("suite:missing-incremental-profile");
  }

  const expected = REQUIRED_ASSESSMENT_SURFACES.flatMap((surface) => [
    { surface, kind: "accuracy" as const, profileId: "accuracy-corpus", profile: undefined },
    ...input.performanceProfiles.map((profile) => ({
      surface, kind: "performance" as const, profileId: profile.id, profile,
    })),
  ]);

  const runs = expected.map(({ surface, kind, profileId, profile }): CompleteAssessmentRun => {
    const runKey = key(surface, kind, profileId);
    const attempt = attempts.get(runKey);
    if (attempt === undefined) {
      failures.push(`${runKey}:missing-run`);
      return {
        surface, kind, profileId, path: pathFor(surface, profile), status: "missing",
        resultPath: "", markdownPath: "", failureCode: "result-missing",
      };
    }

    if (attempt.failureCode !== undefined || attempt.result === undefined) {
      failures.push(`${runKey}:${attempt.failureCode ?? "result-missing"}`);
      return {
        ...attempt, path: pathFor(surface, profile),
        status: attempt.failureCode === "invalid-result" ? "invalid" : "failed",
      };
    }

    try {
      input.validateResult(attempt.result);
    } catch {
      failures.push(`${runKey}:invalid-result`);
      return { ...attempt, path: pathFor(surface, profile), status: "invalid" };
    }

    if (
      attempt.result.surface !== surface || attempt.result.profileId !== profileId ||
      resultKind(attempt.result) !== kind
    ) {
      failures.push(`${runKey}:result-identity-mismatch`);
      return { ...attempt, path: pathFor(surface, profile), status: "invalid" };
    }
    if (
      kind === "performance" &&
      attempt.result.performance?.processing.samples.length !== input.repetitions
    ) {
      failures.push(`${runKey}:repetition-count-mismatch`);
      return { ...attempt, path: pathFor(surface, profile), status: "invalid" };
    }
    return { ...attempt, path: pathFor(surface, profile), status: "complete" };
  });

  const completedResults = runs.flatMap((run) => run.status === "complete" && run.result !== undefined ? [run.result] : []);
  const commits = new Set(completedResults.map((result) => result.provenance.commit));
  if (commits.size > 1) failures.push("suite:source-commit-mismatch");

  const accuracyResults = completedResults.filter((result) => result.accuracy !== undefined);
  const accuracyIdentities = new Set(accuracyResults.map((result) =>
    `${result.provenance.corpusVersion}:${result.provenance.corpusHash}`,
  ));
  if (accuracyIdentities.size > 1) failures.push("suite:accuracy-corpus-identity-mismatch");

  const performanceResults = completedResults.filter((result) => result.performance !== undefined);
  const workloadIdentities = new Set(performanceResults.map((result) =>
    `${result.provenance.corpusVersion}:${result.provenance.corpusHash}`,
  ));
  if (workloadIdentities.size > 1) failures.push("suite:workload-profile-identity-mismatch");

  const [accuracyIdentity] = accuracyResults;
  const [workloadIdentity] = performanceResults;
  return {
    schemaVersion: COMPLETE_ASSESSMENT_SCHEMA_VERSION,
    status: failures.length === 0 ? "complete" : "incomplete",
    sourceCommit: completedResults[0]?.provenance.commit,
    accuracyCorpus: accuracyIdentity === undefined ? undefined : {
      version: accuracyIdentity.provenance.corpusVersion,
      hash: accuracyIdentity.provenance.corpusHash,
    },
    workloadProfiles: workloadIdentity === undefined ? undefined : {
      version: workloadIdentity.provenance.corpusVersion,
      hash: workloadIdentity.provenance.corpusHash,
    },
    repetitions: input.repetitions,
    performanceProfiles: input.performanceProfiles,
    requiredSurfaces: REQUIRED_ASSESSMENT_SURFACES,
    runs,
    validationFailures: failures,
  };
}

function markdownLink(path: string, label: string): string {
  return path.length === 0 ? "—" : `[${label}](${path})`;
}

export function renderCompleteAssessmentMarkdown(assessment: CompleteAssessment): string {
  const lines = [
    "# Complete cross-language assessment baseline",
    "",
    `- Status: **${assessment.status.toUpperCase()}**`,
    `- Source commit: \`${assessment.sourceCommit ?? "unavailable"}\``,
    `- Accuracy corpus: ${assessment.accuracyCorpus === undefined ? "unavailable" : `version \`${assessment.accuracyCorpus.version}\`, SHA-256 \`${assessment.accuracyCorpus.hash}\``}`,
    `- Workload profiles: ${assessment.workloadProfiles === undefined ? "unavailable" : `version \`${assessment.workloadProfiles.version}\`, SHA-256 \`${assessment.workloadProfiles.hash}\``}`,
    `- Performance repetitions: ${assessment.repetitions}`,
    "",
    "A complete status requires accuracy and every named performance profile for Rust, Python, Node, browser WebAssembly, and CLI, all from one source revision and identical corpus/profile identities. Timing samples are expected to vary; identities and repetition counts are not.",
    "",
    "## Run inventory",
    "",
    "| Surface | Kind | Profile | Path | Status | Raw JSON | Markdown |",
    "| --- | --- | --- | --- | --- | --- | --- |",
  ];
  for (const run of assessment.runs) {
    lines.push(`| ${run.surface} | ${run.kind} | ${run.profileId} | ${run.path} | ${run.status} | ${markdownLink(run.resultPath, "JSON")} | ${markdownLink(run.markdownPath, "report")} |`);
  }

  lines.push("", "## Accuracy", "", "| Surface | TP | FP | FN | Policy mismatches |", "| --- | ---: | ---: | ---: | ---: |");
  for (const run of assessment.runs.filter((candidate) => candidate.kind === "accuracy")) {
    const accuracy = run.result?.accuracy;
    lines.push(`| ${run.surface} | ${accuracy?.truePositives ?? "—"} | ${accuracy?.falsePositives ?? "—"} | ${accuracy?.falseNegatives ?? "—"} | ${accuracy?.policyMismatches ?? "—"} |`);
  }

  lines.push("", "## Performance", "", "| Surface | Profile | Processing median (ms) | Throughput median (bytes/s) |", "| --- | --- | ---: | ---: |");
  for (const run of assessment.runs.filter((candidate) => candidate.kind === "performance")) {
    const performance = run.result?.performance;
    lines.push(`| ${run.surface} | ${run.profileId} | ${performance?.processing.median ?? "—"} | ${performance?.throughput.median ?? "—"} |`);
  }

  lines.push(
    "", "## Metric limitations", "",
    "Memory categories are separate and may overlap; they must not be summed. Observed maxima remain sampled observations, not guaranteed true peaks.",
    "", "| Surface | Profile | Category | Availability / sampling limit |", "| --- | --- | --- | --- |",
  );
  for (const run of assessment.runs.filter((candidate) => candidate.result?.performance !== undefined)) {
    for (const [category, metric] of Object.entries(run.result!.performance!.memory)) {
      lines.push(`| ${run.surface} | ${run.profileId} | ${category} | ${metric.unavailableReason ?? "available"}; ${metric.samplingLimit} |`);
    }
  }

  if (assessment.validationFailures.length > 0) {
    lines.push("", "## Incomplete-run diagnostics", "");
    for (const failure of assessment.validationFailures) lines.push(`- \`${failure}\``);
  }
  return `${lines.join("\n")}\n`;
}
