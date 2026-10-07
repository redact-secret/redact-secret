/**
 * Reads what the loaded artifact reports as the resolved configuration
 * (`config-resolution/v1`,
 * `decision-define-the-artifact-manifest-and-configuration-data-contracts`).
 *
 * The Rust core owns the truth table and the snapshot. This module only
 * parses the JSON a binding reports, checks that it is a resolution of this
 * artifact's manifest, and freezes it. It holds no precedence table, no
 * default and no detector list of its own: there is nothing here to drift
 * from the artifact, which is the point.
 *
 * Every failure is `INITIALIZATION_FAILED`, the fixed code an unusable
 * artifact already uses, and carries no document content.
 */

import { SecretScanError } from "./errors.js";
import type { ConfigResolution } from "./types.js";

const DIGEST = /^sha256:[0-9a-f]{64}$/;

function fail(): never {
  throw new SecretScanError("INITIALIZATION_FAILED");
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function deepFreeze<T>(value: T): T {
  if (typeof value === "object" && value !== null && !Object.isFrozen(value)) {
    for (const child of Object.values(value)) deepFreeze(child);
    Object.freeze(value);
  }
  return value;
}

/**
 * Parses the JSON text a binding reports and checks it is a
 * `config-resolution/v1` document: the schema, a boolean `ok` that agrees with
 * the snapshot, a snapshot whose digests are well formed and which is bound to
 * `manifestDigest` when the manifest is known, and a diagnostics list. The
 * result is deeply frozen, so a caller cannot change it and nothing derived
 * from a caller's later mutation reaches it.
 */
export function parseConfigResolution(text: unknown, manifestDigest: string | undefined): ConfigResolution {
  if (typeof text !== "string") return fail();
  let value: unknown;
  try {
    value = JSON.parse(text);
  } catch {
    return fail();
  }
  if (!isRecord(value) || value.schema !== "config-resolution/v1" || typeof value.ok !== "boolean") {
    return fail();
  }
  const { snapshot, diagnostics } = value;
  if (!isRecord(diagnostics) || diagnostics.schema !== "config-diagnostics/v1" || !Array.isArray(diagnostics.items)) {
    return fail();
  }
  if (value.ok) {
    if (!isRecord(snapshot) || snapshot.schema !== "config-snapshot/v1") return fail();
    const { artifact, digest, detectionDigest } = snapshot;
    if (typeof digest !== "string" || !DIGEST.test(digest)) return fail();
    if (typeof detectionDigest !== "string" || !DIGEST.test(detectionDigest)) return fail();
    if (!isRecord(artifact) || typeof artifact.manifestDigest !== "string") return fail();
    if (manifestDigest !== undefined && artifact.manifestDigest !== manifestDigest) return fail();
  } else if (snapshot !== null) {
    return fail();
  }
  return deepFreeze(value as unknown as ConfigResolution);
}
