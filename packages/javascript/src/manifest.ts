/**
 * Reads the loaded artifact's `artifact-manifest/v1` document
 * (`decision-define-the-artifact-manifest-and-configuration-data-contracts`).
 *
 * The Rust core generates the document from the registration rows the
 * artifact links. This module only parses what the binding reports, checks
 * that it is the document of this entry point, and freezes it. It holds no
 * detector list, pack table or type vocabulary of its own: there is nothing
 * here to drift from the artifact.
 *
 * Every failure is `INITIALIZATION_FAILED`, the fixed code a profile or
 * version mismatch already uses, and carries no document content.
 */

import { SecretScanError } from "./errors.js";
import type { ArtifactManifest } from "./types.js";
import { VERSION } from "./version.js";

const SCHEMA = "artifact-manifest/v1";
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

const COMPOSITION_ID = /^custom:[0-9a-f]{64}$/;

/**
 * A custom artifact names its composition (`custom` kind and a
 * `custom:<sha256>` identity); a standard one has none. A manifest whose
 * composition does not match its variant is another artifact's document.
 */
function isCompositionOf(composition: unknown, expectedProfile: "full" | "common" | "custom"): boolean {
  if (!isRecord(composition) || composition.profile !== expectedProfile) return false;
  if (expectedProfile === "custom") {
    return composition.kind === "custom" && typeof composition.id === "string" && COMPOSITION_ID.test(composition.id);
  }
  return composition.kind === "standard" && composition.id === null;
}

/**
 * Parses the JSON text a binding reports and checks it describes this entry
 * point: the `artifact-manifest/v1` schema, this package's version, the
 * expected profile as its variant, and a well-formed digest. The result is
 * deeply frozen.
 */
export function parseArtifactManifest(text: unknown, expectedProfile: "full" | "common" | "custom"): ArtifactManifest {
  if (typeof text !== "string") return fail();
  let value: unknown;
  try {
    value = JSON.parse(text);
  } catch {
    return fail();
  }
  if (!isRecord(value) || value.schema !== SCHEMA || value.version !== VERSION) return fail();
  const { artifact, digest, detectors } = value;
  if (!isRecord(artifact) || artifact.variant !== expectedProfile) return fail();
  if (!isCompositionOf(value.composition, expectedProfile)) return fail();
  if (typeof digest !== "string" || !DIGEST.test(digest)) return fail();
  if (!Array.isArray(detectors)) return fail();
  return deepFreeze(value as unknown as ArtifactManifest);
}

/**
 * The canonical JSON of `value`: object members in bytewise order at every
 * depth, arrays in their stated order, no whitespace. Manifests hold only
 * ASCII strings, integers, booleans and null, so `JSON.stringify` of the
 * key-sorted copy is the contract's form.
 */
export function canonicalJson(value: unknown): string {
  return JSON.stringify(sortKeys(value));
}

function sortKeys(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(sortKeys);
  if (isRecord(value)) {
    const sorted: Record<string, unknown> = {};
    for (const key of Object.keys(value).sort()) sorted[key] = sortKeys(value[key]);
    return sorted;
  }
  return value;
}

interface DigestCrypto {
  readonly subtle?: {
    digest(algorithm: "SHA-256", data: Uint8Array): Promise<ArrayBuffer>;
  };
}

/**
 * Checks that `manifest.digest` is the SHA-256 of the canonical JSON of the
 * manifest without its `digest`. Uses the runtime's Web Crypto when it has
 * one (Node 20+, browsers and edge runtimes all do); a runtime without it
 * skips only this recomputation, the schema, version and profile checks
 * having already run. A mismatch throws `INITIALIZATION_FAILED`.
 */
export async function assertManifestDigest(manifest: ArtifactManifest): Promise<void> {
  const subtle = (globalThis as { crypto?: DigestCrypto }).crypto?.subtle;
  if (subtle === undefined) return;
  const { digest, ...rest } = manifest;
  const bytes = new TextEncoder().encode(canonicalJson(rest));
  let hex: string;
  try {
    const hash = new Uint8Array(await subtle.digest("SHA-256", bytes));
    hex = Array.from(hash, (byte) => byte.toString(16).padStart(2, "0")).join("");
  } catch {
    return fail();
  }
  if (digest !== `sha256:${hex}`) fail();
}
