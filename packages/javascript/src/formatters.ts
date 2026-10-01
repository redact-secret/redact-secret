/**
 * The supported placeholder formatter helpers.
 *
 * Both are pure functions of safe finding metadata: they never see the input
 * or the matched value, and the binding validates whatever they return. Pass
 * {@link defaultPlaceholderFormatter} to name the built-in behavior
 * explicitly — the runtime recognizes it and lets the Rust core apply its own
 * formatter rather than calling back into JavaScript per placeholder.
 *
 * There is deliberately no exported default *policy*: the built-in policy's
 * type table lives in Rust, and re-declaring it here would create a second
 * source of truth (`decision-govern-cross-language-conformance`). Omit
 * `policy` to use it.
 */

import type { PlaceholderContext, PlaceholderFormatter, SecretFinding } from "./types.js";

/** Formats `<SECRET_1>`, `<SECRET_2>`, ... in replacement order. */
export const defaultPlaceholderFormatter: PlaceholderFormatter = (
  _finding: SecretFinding,
  context: PlaceholderContext,
): string => `<SECRET_${context.placeholderIndex}>`;

/**
 * Formats `<JWT_1>`, `<AWS_ACCESS_KEY_ID_2>`, ... naming the finding type,
 * upper-cased with `.` and `-` mapped to `_`, matching the core's own typed
 * formatter.
 */
export const typedPlaceholderFormatter: PlaceholderFormatter = (
  finding: SecretFinding,
  context: PlaceholderContext,
): string => `<${finding.type.toUpperCase().replace(/[.-]/g, "_")}_${context.placeholderIndex}>`;
