import type { CompleteAssessment } from "./complete.js";
import type { AssessmentMemoryMetrics, AssessmentSurface } from "./schema.js";

type MemoryCategory = keyof AssessmentMemoryMetrics;

export interface PerformanceCriterion {
  readonly surface: AssessmentSurface;
  readonly profileId: string;
  readonly maxInitializationP95Ms: number;
  readonly maxProcessingP95Ms: number;
  readonly minThroughputBytesPerSecond: number;
  readonly memoryCapsBytes: Readonly<Partial<Record<MemoryCategory, number>>>;
}

export interface AcceptanceCriteria {
  readonly schemaVersion: "1";
  readonly criteriaId: string;
  readonly fixedAt: string;
  readonly baseline: {
    readonly summaryPath: string;
    readonly sourceCommit: string;
    readonly accuracyCorpusVersion: string;
    readonly accuracyCorpusHash: string;
    readonly workloadProfilesVersion: string;
    readonly workloadProfilesHash: string;
  };
  readonly minimumRepetitions: number;
  readonly environment: {
    readonly id: string;
    readonly osPrefixes: readonly string[];
    readonly cpus: readonly string[];
    readonly runtimePrefixes: Readonly<Record<AssessmentSurface, readonly string[]>>;
  };
  readonly accuracy: {
    readonly truePositives: number;
    readonly falsePositives: number;
    readonly falseNegatives: number;
    readonly policyMismatches: number;
  };
  readonly performance: readonly PerformanceCriterion[];
}

export interface AcceptanceCheck {
  readonly key: string;
  readonly observed: number;
  readonly operator: "<=" | ">=";
  readonly threshold: number;
  readonly passed: boolean;
}

export interface AcceptanceEvaluation {
  readonly schemaVersion: "1";
  readonly status: "accepted" | "rejected";
  readonly criteriaId: string;
  readonly criteriaFixedAt: string;
  readonly environmentId: string;
  readonly sourceCommit?: string;
  readonly summaryPath: string;
  readonly checks: readonly AcceptanceCheck[];
  readonly failures: readonly string[];
}

function finitePositive(value: unknown): value is number {
  return typeof value === "number" && Number.isFinite(value) && value > 0;
}

export function validateAcceptanceCriteria(value: AcceptanceCriteria): AcceptanceCriteria {
  if (
    value.schemaVersion !== "1" || value.criteriaId.length === 0 ||
    !/^\d{4}-\d{2}-\d{2}$/.test(value.fixedAt) ||
    !/^[0-9a-f]{40}$/.test(value.baseline.sourceCommit) ||
    !/^[0-9a-f]{64}$/.test(value.baseline.accuracyCorpusHash) ||
    !/^[0-9a-f]{64}$/.test(value.baseline.workloadProfilesHash) ||
    !Number.isSafeInteger(value.minimumRepetitions) || value.minimumRepetitions < 2 ||
    value.environment.osPrefixes.length === 0 || value.environment.cpus.length === 0
  ) throw new TypeError("acceptance-criteria:invalid-metadata");

  const keys = new Set<string>();
  for (const criterion of value.performance) {
    const key = `${criterion.surface}:${criterion.profileId}`;
    if (
      keys.has(key) || !finitePositive(criterion.maxInitializationP95Ms) ||
      !finitePositive(criterion.maxProcessingP95Ms) ||
      !finitePositive(criterion.minThroughputBytesPerSecond) ||
      Object.values(criterion.memoryCapsBytes).some((cap) => !finitePositive(cap))
    ) throw new TypeError("acceptance-criteria:invalid-performance-threshold");
    keys.add(key);
  }
  if (keys.size === 0) throw new TypeError("acceptance-criteria:no-performance-thresholds");
  return value;
}

function check(
  checks: AcceptanceCheck[], failures: string[], key: string,
  observed: number, operator: "<=" | ">=", threshold: number,
): void {
  const passed = operator === "<=" ? observed <= threshold : observed >= threshold;
  checks.push({ key, observed, operator, threshold, passed });
  if (!passed) failures.push(`${key}:threshold-not-met`);
}

export function evaluateAcceptance(
  summary: CompleteAssessment, rawCriteria: AcceptanceCriteria,
): AcceptanceEvaluation {
  const criteria = validateAcceptanceCriteria(rawCriteria);
  const failures: string[] = [];
  const checks: AcceptanceCheck[] = [];
  if (summary.status !== "complete") failures.push("suite:assessment-incomplete");
  if (summary.repetitions < criteria.minimumRepetitions) failures.push("suite:insufficient-repetitions");
  if (
    summary.accuracyCorpus?.version !== criteria.baseline.accuracyCorpusVersion ||
    summary.accuracyCorpus.hash !== criteria.baseline.accuracyCorpusHash
  ) failures.push("suite:accuracy-corpus-identity-mismatch");
  if (
    summary.workloadProfiles?.version !== criteria.baseline.workloadProfilesVersion ||
    summary.workloadProfiles.hash !== criteria.baseline.workloadProfilesHash
  ) failures.push("suite:workload-profile-identity-mismatch");

  for (const run of summary.runs) {
    const result = run.result;
    if (run.status !== "complete" || result === undefined) continue;
    const prefix = `${run.surface}:${run.kind}:${run.profileId}`;
    if (!criteria.environment.osPrefixes.some((candidate) => result.provenance.os.startsWith(candidate))) {
      failures.push(`${prefix}:environment-os-mismatch`);
    }
    if (!criteria.environment.cpus.includes(result.provenance.cpu)) {
      failures.push(`${prefix}:environment-cpu-mismatch`);
    }
    if (!criteria.environment.runtimePrefixes[run.surface].some((candidate) => result.provenance.runtime.startsWith(candidate))) {
      failures.push(`${prefix}:environment-runtime-mismatch`);
    }
    if (run.kind === "accuracy" && result.accuracy !== undefined) {
      for (const metric of ["truePositives", "falsePositives", "falseNegatives", "policyMismatches"] as const) {
        if (result.accuracy[metric] !== criteria.accuracy[metric]) failures.push(`${prefix}:${metric}-mismatch`);
      }
    }
  }

  for (const criterion of criteria.performance) {
    const run = summary.runs.find((candidate) =>
      candidate.surface === criterion.surface && candidate.kind === "performance" && candidate.profileId === criterion.profileId,
    );
    const prefix = `${criterion.surface}:performance:${criterion.profileId}`;
    const performance = run?.status === "complete" ? run.result?.performance : undefined;
    if (performance === undefined) {
      failures.push(`${prefix}:missing-performance-result`);
      continue;
    }
    if (criterion.surface === "rust-core" && run?.result?.provenance.buildProfile !== "release") {
      failures.push(`${prefix}:release-build-required`);
      continue;
    }
    check(checks, failures, `${prefix}:initialization-p95-ms`, performance.initialization.p95, "<=", criterion.maxInitializationP95Ms);
    check(checks, failures, `${prefix}:processing-p95-ms`, performance.processing.p95, "<=", criterion.maxProcessingP95Ms);
    check(checks, failures, `${prefix}:throughput-minimum-bytes-per-second`, performance.throughput.minimum, ">=", criterion.minThroughputBytesPerSecond);
    for (const [category, cap] of Object.entries(criterion.memoryCapsBytes) as [MemoryCategory, number][]) {
      const samples = performance.memory[category].samples;
      if (samples.length < criteria.minimumRepetitions) {
        failures.push(`${prefix}:memory-${category}:insufficient-samples`);
        continue;
      }
      check(checks, failures, `${prefix}:memory-${category}-maximum-bytes`, Math.max(...samples.map((sample) => sample.maximumObservedBytes)), "<=", cap);
    }
  }

  return {
    schemaVersion: "1",
    status: failures.length === 0 ? "accepted" : "rejected",
    criteriaId: criteria.criteriaId,
    criteriaFixedAt: criteria.fixedAt,
    environmentId: criteria.environment.id,
    sourceCommit: summary.sourceCommit,
    summaryPath: criteria.baseline.summaryPath,
    checks,
    failures,
  };
}

export function renderAcceptanceMarkdown(evaluation: AcceptanceEvaluation): string {
  const lines = [
    "# RC performance and resource acceptance",
    "",
    `- Status: **${evaluation.status.toUpperCase()}**`,
    `- Criteria: \`${evaluation.criteriaId}\` (fixed ${evaluation.criteriaFixedAt})`,
    `- Environment profile: \`${evaluation.environmentId}\``,
    `- Source commit: \`${evaluation.sourceCommit ?? "unavailable"}\``,
    `- Complete assessment: [summary](${evaluation.summaryPath})`,
    "",
    "## Threshold checks",
    "",
    "| Check | Observed | Requirement | Result |",
    "| --- | ---: | ---: | --- |",
  ];
  for (const item of evaluation.checks) {
    lines.push(`| ${item.key} | ${item.observed} | ${item.operator} ${item.threshold} | ${item.passed ? "pass" : "fail"} |`);
  }
  if (evaluation.failures.length > 0) {
    lines.push("", "## Failures", "", ...evaluation.failures.map((failure) => `- \`${failure}\``));
  }
  return `${lines.join("\n")}\n`;
}
