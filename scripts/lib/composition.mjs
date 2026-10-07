/**
 * The `composition/v1` build input of a static custom artifact (issue #1253,
 * `decision-define-the-artifact-manifest-and-configuration-data-contracts`
 * section 4): parsing, strict validation, resolution against the detector
 * catalog and the generated leaf crate's source.
 *
 * This module is build tooling. It runs in a developer or CI process (and so
 * from a webpack or Vite build hook) and never in the core runtime. It reads
 * no file and runs no process: callers pass the parsed document and the
 * catalog, so every rule here is a pure function a unit test can exercise.
 *
 * An invalid input fails closed with a {@link CompositionError} that carries a
 * fixed code and a fixed-syntax path (`include[3]`). It never echoes an input
 * string: a user can paste a secret where an id belongs.
 */

import { createHash } from "node:crypto";

export const COMPOSITION_SCHEMA = "composition/v1";

/** The most ids one composition may name (the `detectorIdsMax` bound of the manifest). */
export const DETECTOR_IDS_MAX = 256;

const IDENTIFIER = /^[a-z](?:[a-z0-9]*)(?:[._-][a-z0-9]+)*$/u;
const MAX_IDENTIFIER_LENGTH = 64;

/** The fixed codes of this module. */
export const COMPOSITION_ERROR_CODES = Object.freeze([
  "INVALID_JSON",
  "UNKNOWN_SCHEMA",
  "UNKNOWN_FIELD",
  "WRONG_TYPE",
  "INVALID_IDENTIFIER",
  "TOO_MANY_DETECTOR_IDS",
  "EMPTY_COMPOSITION",
  "DUPLICATE_DETECTOR_ID",
  "UNKNOWN_DETECTOR_ID",
  "UNSUPPORTED_PII",
  "UNSUPPORTED_TARGET",
  "CATALOG_INVALID",
]);

/** A rejected composition input: a fixed code and a fixed-syntax path, never the input. */
export class CompositionError extends Error {
  /**
   * @param {string} code one of {@link COMPOSITION_ERROR_CODES}
   * @param {string} [path] a pointer such as `include[3]`
   */
  constructor(code, path = "") {
    super(path === "" ? code : `${code} at ${path}`);
    this.name = "CompositionError";
    this.code = code;
    this.path = path;
  }
}

/** Whether `value` is a Rust-side `is_identifier` (lowercase, at most 64 bytes). */
export function isIdentifier(value) {
  return typeof value === "string" && value.length <= MAX_IDENTIFIER_LENGTH && IDENTIFIER.test(value);
}

function isPlainObject(value) {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/**
 * Strictly validates the shape of a `composition/v1` document: exactly the
 * members `schema`, `name`, `include` and `pii`, with the types and
 * vocabularies of the contract. It does not look at the catalog.
 *
 * @param {unknown} document
 * @returns {{ name: string, include: string[], pii: "none" | "all" }}
 */
export function parseComposition(document) {
  if (!isPlainObject(document)) throw new CompositionError("WRONG_TYPE", "$");
  for (const key of Object.keys(document)) {
    if (!["schema", "name", "include", "pii"].includes(key)) throw new CompositionError("UNKNOWN_FIELD", "$");
  }
  if (document.schema !== COMPOSITION_SCHEMA) throw new CompositionError("UNKNOWN_SCHEMA", "schema");
  if (typeof document.name !== "string") throw new CompositionError("WRONG_TYPE", "name");
  if (!isIdentifier(document.name)) throw new CompositionError("INVALID_IDENTIFIER", "name");
  if (!Array.isArray(document.include)) throw new CompositionError("WRONG_TYPE", "include");
  if (document.include.length > DETECTOR_IDS_MAX) throw new CompositionError("TOO_MANY_DETECTOR_IDS", "include");
  if (document.include.length === 0) throw new CompositionError("EMPTY_COMPOSITION", "include");
  document.include.forEach((id, index) => {
    if (typeof id !== "string") throw new CompositionError("WRONG_TYPE", `include[${index}]`);
    if (!isIdentifier(id)) throw new CompositionError("INVALID_IDENTIFIER", `include[${index}]`);
  });
  if (typeof document.pii !== "string") throw new CompositionError("WRONG_TYPE", "pii");
  if (document.pii !== "none" && document.pii !== "all") throw new CompositionError("UNSUPPORTED_PII", "pii");
  return { name: document.name, include: [...document.include], pii: document.pii };
}

/**
 * Reads the catalog out of an `artifact-manifest/v1` document of the `full`
 * artifact: the ids in canonical order, each with its pack, emitted types and
 * aliases. The manifest is generated from the registration rows, so the
 * catalog is never a second hand-kept list.
 *
 * @param {string | object} manifest the document text or the parsed value
 * @returns {{ id: string, pack: string, types: string[], aliases: string[] }[]}
 */
export function readCatalog(manifest) {
  let value = manifest;
  if (typeof manifest === "string") {
    try {
      value = JSON.parse(manifest);
    } catch {
      throw new CompositionError("CATALOG_INVALID");
    }
  }
  if (!isPlainObject(value) || value.schema !== "artifact-manifest/v1" || !Array.isArray(value.detectors)) {
    throw new CompositionError("CATALOG_INVALID");
  }
  const seen = new Set();
  const catalog = value.detectors.map((entry) => {
    if (!isPlainObject(entry) || !isIdentifier(entry.id) || seen.has(entry.id)) {
      throw new CompositionError("CATALOG_INVALID");
    }
    seen.add(entry.id);
    const aliases = Array.isArray(entry.aliases) ? entry.aliases : [];
    return {
      id: entry.id,
      pack: typeof entry.pack === "string" ? entry.pack : "provider",
      types: Array.isArray(entry.types) ? [...entry.types] : [],
      aliases: [...aliases],
    };
  });
  if (catalog.length === 0) throw new CompositionError("CATALOG_INVALID");
  return catalog;
}

/**
 * The canonical form of a resolved composition: members in bytewise order, no
 * whitespace, ids in canonical order. The identity is taken over exactly this
 * text, and the Rust `Composition::new` derives the same one.
 */
export function canonicalCompositionDocument(name, ids, pii) {
  return JSON.stringify({ include: ids, name, pii, schema: COMPOSITION_SCHEMA });
}

/** `custom:` and the SHA-256 (lowercase hex) of the canonical document. */
export function compositionId(name, ids, pii) {
  const digest = createHash("sha256")
    .update(canonicalCompositionDocument(name, ids, pii), "utf8")
    .digest("hex");
  return `custom:${digest}`;
}

/**
 * Resolves a parsed composition against the catalog.
 *
 * Aliases resolve before duplicate checks; a repeated detector (an alias and
 * its canonical id included) and an id the catalog does not hold fail the
 * build. The order is canonical, never as written. An unsupported input fails
 * here, before any file is written or any artifact is built, so a mislabeled
 * artifact can never be emitted.
 *
 * @param {{ name: string, include: string[], pii: "none" | "all" }} composition
 * @param {{ id: string, pack: string, types: string[], aliases: string[] }[]} catalog
 */
export function resolveComposition(composition, catalog) {
  const canonicalIds = catalog.map((entry) => entry.id);
  const byName = new Map();
  for (const entry of catalog) {
    byName.set(entry.id, entry.id);
    for (const alias of entry.aliases) byName.set(alias, entry.id);
  }
  const chosen = new Set();
  const aliasesUsed = [];
  composition.include.forEach((requested, index) => {
    const id = byName.get(requested);
    if (id === undefined) throw new CompositionError("UNKNOWN_DETECTOR_ID", `include[${index}]`);
    if (chosen.has(id)) throw new CompositionError("DUPLICATE_DETECTOR_ID", `include[${index}]`);
    chosen.add(id);
    if (requested !== id) aliasesUsed.push(index);
  });
  const ids = canonicalIds.filter((id) => chosen.has(id));
  const notIncluded = canonicalIds.filter((id) => !chosen.has(id));
  return {
    name: composition.name,
    pii: composition.pii,
    ids,
    notIncluded,
    aliasesUsed,
    document: canonicalCompositionDocument(composition.name, ids, composition.pii),
    id: compositionId(composition.name, ids, composition.pii),
    detectors: catalog.filter((entry) => chosen.has(entry.id)),
  };
}

/** The Rust constructor name of a detector id: `-`, `.` and `_` written `_`. */
export function constructorName(id) {
  return id.replaceAll(/[-.]/gu, "_");
}

/**
 * The source of the generated leaf crate's `src/lib.rs`: a function that calls
 * exactly the selected per-detector constructors of
 * `redact_secret::composition`, in canonical order, and installs it into the
 * binding. No other detector constructor, and no table of all of them, is
 * named, so link-time reachability removes the rest.
 */
export function generateLeafLib(resolved, { source = "scripts/build-custom-artifact.mjs" } = {}) {
  const calls = resolved.ids.map((id) => `        composition::${constructorName(id)}(),`).join("\n");
  return `//! Generated by \`${source}\` for the custom composition \`${resolved.name}\`.
//! Do not edit: regenerate with the build script. The composition identity is
//! \`${resolved.id}\`.
//!
//! This crate names the per-detector constructors of \`redact_secret::composition\`
//! for the ${resolved.ids.length} selected detectors and no others, so the linked
//! artifact contains only their code. It adds no export of its own besides the
//! start function that installs the composition into \`redact_secret_wasm\`.

#![forbid(unsafe_code)]
#![allow(missing_docs)]

use redact_secret::SecretScanError;
use redact_secret::composition::{self, Composition};
use redact_secret_wasm::custom::{Provider, install};
use wasm_bindgen::prelude::wasm_bindgen;

pub use redact_secret_wasm::*;

/// The composition name, from the \`composition/v1\` input.
pub const COMPOSITION_NAME: &str = ${JSON.stringify(resolved.name)};

/// The exact bytes of \`artifact-manifest.custom.json\`, shipped beside the
/// artifact and compared with the manifest the artifact generates at
/// \`initialize()\`.
pub const PACKAGED_MANIFEST: &str = include_str!("../artifact-manifest.custom.json");

/// Builds the composition from the selected constructors only, in canonical
/// order.
///
/// # Errors
///
/// Never for a generated composition; the core validates order and identity.
pub fn composition() -> Result<Composition, SecretScanError> {
    Composition::new(
        COMPOSITION_NAME,
        ${resolved.pii === "all" ? "true" : "false"},
        [
${calls}
        ],
    )
}

static PROVIDER: Provider = Provider {
    composition,
    packaged_manifest: Some(PACKAGED_MANIFEST),
};

// Runs when the module is instantiated, before any export is callable.
// wasm-bindgen also lists a start function among the raw glue's exports; calling
// it again changes nothing (the install is idempotent), and the emitted wrapper
// does not re-export it.
#[wasm_bindgen(start)]
fn start() {
    install(&PROVIDER);
}
`;
}

/** The source of the generated native example that prints the manifest or the registry's ids. */
export function generateLeafExample() {
  return `//! Generated: prints what this composition actually builds, natively, so the
//! build can compare it with the resolved composition before it emits anything.

use redact_secret::{ArtifactKind, ArtifactManifest, DetectorRegistry};

fn main() {
    let which = std::env::args().nth(1).unwrap_or_default();
    let composition = redact_secret_custom_artifact::composition().expect("composition");
    match which.as_str() {
        "manifest" => {
            let revision = option_env!("REDACT_SECRET_SOURCE_REVISION");
            let manifest = ArtifactManifest::custom(ArtifactKind::Wasm, &composition, revision)
                .expect("manifest");
            print!("{}", manifest.as_json());
        }
        "registry" => {
            let registry = DetectorRegistry::with_composition(&composition, []).expect("registry");
            let ids: Vec<&str> = registry.ids().collect();
            print!("{}", ids.join("\\n"));
        }
        _ => std::process::exit(2),
    }
}
`;
}

/** The leaf crate's \`Cargo.toml\`. */
export function generateLeafManifest({ version, coreDir, wasmDir, bindgenRequirement, pii }) {
  const features = pii ? '["custom", "pii"]' : '["custom"]';
  return `# Generated by scripts/build-custom-artifact.mjs. Do not edit.
[package]
name = "redact-secret-custom-artifact"
version = ${JSON.stringify(version)}
edition = "2024"
publish = false

[lib]
crate-type = ["cdylib", "rlib"]

[dependencies]
redact-secret = { path = ${JSON.stringify(coreDir)} }
redact-secret-wasm = { path = ${JSON.stringify(wasmDir)}, default-features = false, features = ${features} }
wasm-bindgen = ${JSON.stringify(bindgenRequirement)}
`;
}
