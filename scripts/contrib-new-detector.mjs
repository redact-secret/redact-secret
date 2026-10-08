#!/usr/bin/env node
// Scaffold the structural skeleton of a new built-in detector (issue #1050,
// epic #999).
//
//   npm run contrib:new-detector -- <detector-id> [options]
//   npm run contrib:new-detector -- --handoff <file>.handoff.json
//
// Input is a detector id (plus optional finding type and policy class) or an
// implementation-ready handoff file
// (docs/contracts/contribution/implementation-ready-handoff.md). Output is the
// minimum set of repository files and table entries that a new detector needs,
// every one carrying a `TODO(scaffold)` marker where the contributor must act.
//
// The command is deterministic and non-interactive, and it is atomic: every
// target is read and every precondition checked before anything is written, so
// a refusal leaves the tree untouched. It never overwrites a file and never
// replaces an existing entry. It generates no credential-shaped material: the
// only literals are an obviously synthetic placeholder prefix and filler. It
// does no provider research, benchmark classification or support promotion.
//
// Exit codes: 0 scaffolded (or planned with --dry-run); 1 refused because a
// file or entry already exists or a repository anchor moved; 2 invalid usage or
// invalid handoff.

import { existsSync, readFileSync, renameSync, unlinkSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const SCHEMA_PATH = "docs/contracts/contribution/implementation-ready-handoff-v1.schema.json";

export const MARKER = "TODO(scaffold)";
export const PLACEHOLDER_PREFIX = "todo_scaffold_prefix_";
export const POLICY_CLASSES = ["always-redact", "confidence-gated"];
export const GROUPS = ["ai", "cloud", "devtools", "pkg-registry", "saas"];

const ID_PATTERN = /^[a-z0-9][a-z0-9-]*$/;
const TYPE_PATTERN = /^[a-z][a-z0-9_]*$/;
const FAMILY_PATTERN = /^[a-z0-9][a-z0-9-]*(:[a-z0-9][a-z0-9-]*)?$/;

const DETECTORS_DIR = "crates/secret-scan-core/src/detectors";
const FILES = {
  mod: `${DETECTORS_DIR}/mod.rs`,
  prefilter: `${DETECTORS_DIR}/prefilter.rs`,
  policy: "crates/secret-scan-core/src/policy.rs",
  inventory: "docs/coverage/detector-inventory.json",
  allowlist: "docs/coverage/detector-family-coverage-allowlist.json",
  corpus: "conformance/fixtures/synchronous-corpus.json",
  cost: "scripts/measure-detector-cost.mjs",
  spec: "docs/specs/detector-families.md",
  changelog: "CHANGELOG.md",
};

/** A refusal: an existing file or entry, or a repository anchor that moved. */
export class Refusal extends Error {}
/** Invalid usage or an invalid handoff. */
export class UsageError extends Error {}

// ---------------------------------------------------------------------------
// Handoff validation: the published schema, interpreted, plus the four lint
// rules the contract says a schema cannot express.

const SCHEMA_ANNOTATIONS = new Set(["$schema", "$id", "$comment", "$defs", "title", "description"]);
const SCHEMA_KEYWORDS = new Set([
  ...SCHEMA_ANNOTATIONS,
  "$ref",
  "allOf",
  "const",
  "enum",
  "items",
  "additionalProperties",
  "maxLength",
  "minItems",
  "minLength",
  "minimum",
  "pattern",
  "properties",
  "required",
  "type",
  "uniqueItems",
]);

function jsonType(value) {
  if (Array.isArray(value)) return "array";
  if (value === null) return "null";
  if (Number.isInteger(value)) return "integer";
  return typeof value;
}

function typeMatches(expected, value) {
  const actual = jsonType(value);
  return actual === expected || (expected === "number" && actual === "integer");
}

/**
 * Validates `value` against the JSON Schema subset the handoff schema uses.
 * A keyword outside that subset throws, so a schema change cannot silently
 * weaken validation.
 */
export function validateSchema(schema, value, root = schema, path = "$", errors = []) {
  for (const keyword of Object.keys(schema)) {
    if (!SCHEMA_KEYWORDS.has(keyword)) {
      throw new Error(`handoff schema uses unsupported keyword "${keyword}" at ${path}`);
    }
  }
  if (schema.$ref !== undefined) {
    const target = schema.$ref
      .replace(/^#\//, "")
      .split("/")
      .reduce((node, key) => node?.[key], root);
    if (!target) throw new Error(`unresolved $ref ${schema.$ref}`);
    validateSchema(target, value, root, path, errors);
  }
  for (const sub of schema.allOf ?? []) validateSchema(sub, value, root, path, errors);
  if ("const" in schema && value !== schema.const) {
    errors.push(`${path}: must be ${JSON.stringify(schema.const)}`);
  }
  if (schema.enum && !schema.enum.includes(value)) {
    errors.push(`${path}: must be one of ${schema.enum.map((entry) => JSON.stringify(entry)).join(", ")}`);
  }
  if (schema.type && !typeMatches(schema.type, value)) {
    errors.push(`${path}: must be ${schema.type}`);
    return errors;
  }
  if (typeof value === "string") {
    if (schema.pattern && !new RegExp(schema.pattern).test(value)) {
      errors.push(`${path}: does not match the required pattern`);
    }
    if (schema.minLength !== undefined && value.length < schema.minLength) {
      errors.push(`${path}: shorter than ${schema.minLength}`);
    }
    if (schema.maxLength !== undefined && value.length > schema.maxLength) {
      errors.push(`${path}: longer than ${schema.maxLength}`);
    }
  }
  if (typeof value === "number" && schema.minimum !== undefined && value < schema.minimum) {
    errors.push(`${path}: below ${schema.minimum}`);
  }
  if (Array.isArray(value)) {
    if (schema.minItems !== undefined && value.length < schema.minItems) {
      errors.push(`${path}: needs at least ${schema.minItems} item(s)`);
    }
    if (schema.uniqueItems && new Set(value.map((item) => JSON.stringify(item))).size !== value.length) {
      errors.push(`${path}: items must be unique`);
    }
    if (schema.items) {
      for (const [index, item] of value.entries()) {
        validateSchema(schema.items, item, root, `${path}[${index}]`, errors);
      }
    }
  }
  if (value !== null && typeof value === "object" && !Array.isArray(value)) {
    for (const key of schema.required ?? []) {
      if (!(key in value)) errors.push(`${path}: missing required field "${key}"`);
    }
    for (const [key, sub] of Object.entries(schema.properties ?? {})) {
      if (key in value) validateSchema(sub, value[key], root, `${path}.${key}`, errors);
    }
    if (schema.additionalProperties === false) {
      for (const key of Object.keys(value)) {
        if (!(key in (schema.properties ?? {}))) errors.push(`${path}: unknown field "${key}"`);
      }
    }
  }
  return errors;
}

// Shapes that look like a credential literal, for the lint the schema cannot
// express. Deliberately coarse: a false positive costs one edited sentence, a
// false negative costs a credential in a checked-in handoff.
const CREDENTIAL_SHAPES = [
  /\b(?:sk|pk|rk)[-_][A-Za-z0-9_-]{16,}/,
  /\bgh[pousr]_[A-Za-z0-9]{20,}/,
  /\bAKIA[0-9A-Z]{16}\b/,
  /\bxox[abprs]-[A-Za-z0-9-]{10,}/,
  /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}/,
];
const LONG_RUN = /[A-Za-z0-9+/_=-]{32,}/g;

function looksLikeCredential(text) {
  if (/^https:\/\//.test(text) || /^[0-9a-f]{40}$/.test(text)) return false;
  if (CREDENTIAL_SHAPES.some((shape) => shape.test(text))) return true;
  return (text.match(LONG_RUN) ?? []).some((run) => /[A-Za-z]/.test(run) && /[0-9]/.test(run));
}

function* proseStrings(value, path = "$") {
  // Paths, globs and command lines legitimately carry long digit-bearing runs.
  if (/^\$\.(surfaces|commands|schemaVersion)\b/.test(path)) return;
  if (typeof value === "string") yield [path, value];
  else if (Array.isArray(value)) {
    for (const [index, item] of value.entries()) yield* proseStrings(item, `${path}[${index}]`);
  } else if (value !== null && typeof value === "object") {
    for (const [key, item] of Object.entries(value)) yield* proseStrings(item, `${path}.${key}`);
  }
}

/** The handoff validation the contract names: schema plus four lint rules. */
export function validateHandoff(handoff, schema) {
  const errors = validateSchema(schema, handoff);
  for (const [path, text] of proseStrings(handoff)) {
    if (looksLikeCredential(text))
      errors.push(`${path}: contains a credential-shaped literal; describe the shape in words`);
  }
  if (handoff?.state !== "implementation-ready") errors.push("$.state: must be implementation-ready");
  const limitations = handoff?.research?.limitations ?? [];
  const exclusions = Array.isArray(handoff?.exclusions) ? handoff.exclusions : [];
  if (exclusions.length < limitations.length) {
    errors.push("$.exclusions: every research.limitations entry must be restated as an exclusion");
  }
  if (handoff?.evaluation?.supportStatus !== "separate") {
    errors.push("$.evaluation.supportStatus: must be separate");
  }
  return [...new Set(errors)];
}

// ---------------------------------------------------------------------------
// Naming

export function names(id) {
  const snake = id.replaceAll("-", "_");
  return {
    id,
    module: snake,
    constant: snake.toUpperCase(),
    struct: `${snake
      .split("_")
      .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
      .join("")}Detector`,
  };
}

// ---------------------------------------------------------------------------
// Text edits. Each takes the current text and returns the new text, or throws
// a Refusal when the entry exists or the anchor it needs is gone.

function insertBefore(text, anchor, insertion, what) {
  const index = text.indexOf(anchor);
  if (index === -1) throw new Refusal(`anchor not found for ${what}: ${JSON.stringify(anchor.trim())}`);
  return text.slice(0, index) + insertion + text.slice(index);
}

function blockEnd(text, openPattern, closePattern, what) {
  const open = openPattern.exec(text);
  if (!open) throw new Refusal(`anchor not found for ${what}: ${openPattern}`);
  const close = closePattern.exec(text.slice(open.index + open[0].length));
  if (!close) throw new Refusal(`end of block not found for ${what}`);
  return { start: open.index + open[0].length, end: open.index + open[0].length + close.index, open };
}

function modEdits(n) {
  return {
    [FILES.mod]: (text) => {
      if (new RegExp(`^mod ${n.module};$`, "m").test(text))
        throw new Refusal(`${FILES.mod}: mod ${n.module}; already declared`);
      if (text.includes(`row("${n.id}",`)) throw new Refusal(`${FILES.mod}: detector id ${n.id} is already registered`);
      // rustfmt keeps the contiguous `mod x;` block alphabetical.
      const block = /^mod [a-z0-9_]+;\n(?:mod [a-z0-9_]+;\n)*/m.exec(text);
      if (!block) throw new Refusal(`${FILES.mod}: module declaration block not found`);
      const lines = block[0].trimEnd().split("\n");
      const at = lines.findIndex((line) => line.slice(4, -1) > n.module);
      lines.splice(at === -1 ? lines.length : at, 0, `mod ${n.module};`);
      let out = text.slice(0, block.index) + `${lines.join("\n")}\n` + text.slice(block.index + block[0].length);
      out = insertBefore(
        out,
        '        row("jwt", &jwt::JwtDetector),\n',
        `        row("${n.id}", &${n.module}::${n.constant}),\n`,
        "the registration row",
      );
      const literals = blockEnd(
        out,
        /const DECLARED_LITERALS: &\[\(&str, &\[Literals\]\)\] = &\[\n/,
        /\n\];/,
        "the declared prefilter literals",
      );
      // rustfmt wraps a tuple whose contents pass 60 columns.
      const inner = `${n.module}::ID, &[Literals::Shapes(${n.module}::SHAPES)]`;
      const entry =
        inner.length <= 60
          ? `    (${inner}),\n`
          : `    (\n        ${n.module}::ID,\n        &[Literals::Shapes(${n.module}::SHAPES)],\n    ),\n`;
      out = out.slice(0, literals.end + 1) + entry + out.slice(literals.end + 1);
      out = insertBefore(out, '    ("jwt", Pack::Common),\n', `    ("${n.id}", Pack::Provider),\n`, "the pack table");
      const oracle =
        /(\n)( {16}"jwt",\n {16}"bearer-token",\n {16}"connection-string",\n {16}"otpauth-uri",\n {16}"generic-token",\n {12}\]\n {8}\);\n {4}\}\n\n {4}fn ids_of)/;
      if (!oracle.test(out)) throw new Refusal("anchor not found for the registration-order test list");
      return out.replace(oracle, (_, newline, rest) => `${newline}                "${n.id}",\n${rest}`);
    },
  };
}

function prefilterEdit(text) {
  const name = /fn full_declares_(\d+)_detectors_and_common_4\(\)/.exec(text);
  const count = /assert_eq!\(declared\(built_in_entries\(\)\), (\d+)\);/.exec(text);
  if (!name || !count || name[1] !== count[1])
    throw new Refusal(`${FILES.prefilter}: declared-detector count test not found`);
  const next = Number(name[1]) + 1;
  return text
    .replace(name[0], `fn full_declares_${next}_detectors_and_common_4()`)
    .replace(count[0], `assert_eq!(declared(built_in_entries()), ${next});`);
}

function policyEdit(types) {
  return (text) => {
    const list = /const ALWAYS_REDACT_TYPES: \[&str; (\d+)\] = \[\n/.exec(text);
    if (!list) throw new Refusal(`${FILES.policy}: ALWAYS_REDACT_TYPES not found`);
    const bodyStart = list.index + list[0].length;
    const bodyEnd = text.indexOf("\n];", bodyStart);
    const entries = text
      .slice(bodyStart, bodyEnd + 1)
      .split("\n")
      .filter(Boolean);
    for (const type of types) {
      if (entries.includes(`    "${type}",`))
        throw new Refusal(`${FILES.policy}: ${type} is already in ALWAYS_REDACT_TYPES`);
    }
    const merged = [...entries, ...types.map((type) => `    "${type}",`)].sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
    return (
      text.slice(0, list.index) +
      `const ALWAYS_REDACT_TYPES: [&str; ${merged.length}] = [\n${merged.join("\n")}\n` +
      text.slice(bodyEnd + 1)
    );
  };
}

function inventoryEdit(n, types, policyClass) {
  return (text) => {
    for (const type of types) {
      if (text.includes(`"type": "${type}"`))
        throw new Refusal(`${FILES.inventory}: finding type ${type} is already declared`);
    }
    if (text.includes(`"detector": "${n.id}"`))
      throw new Refusal(`${FILES.inventory}: detector ${n.id} is already declared`);
    const types_ = blockEnd(text, /\n {2}"types": \[\n/, /\n {2}\],\n/, "the inventory types array");
    const rows = types.map((type) =>
      JSON.stringify(
        {
          type,
          detector: n.id,
          policyClass,
          reconciliationTrigger: `${PLACEHOLDER_PREFIX}${"5e7c0ded".repeat(4)}`,
          schemes: null,
        },
        null,
        2,
      )
        .split("\n")
        .map((line) => `    ${line}`)
        .join("\n"),
    );
    return text.slice(0, types_.end) + `,\n${rows.join(",\n")}` + text.slice(types_.end);
  };
}

function allowlistEdit(n, issue, benchmarkIssue) {
  return (text) => {
    if (text.includes(`"${n.id}":`)) throw new Refusal(`${FILES.allowlist}: ${n.id} is already listed`);
    const counterpart = benchmarkIssue
      ? `its redact-secret-benchmarks arrival counterpart (${benchmarkIssue})`
      : `its redact-secret-benchmarks arrival counterpart (${MARKER}: issue)`;
    const reason = `Shipped by ${issue} (${MARKER}: one-line family description) before its benchmarks arrival evidence: the family joins the pinned support matrix with ${counterpart} and the next matrix refresh, which removes this entry. Listed as not yet measured; no support-status claim.`;
    const entry = `    ${JSON.stringify(n.id)}: ${JSON.stringify(reason)}`;
    const empty = /\n {2}"unmeasured": \{\}/;
    if (empty.test(text)) return text.replace(empty, `\n  "unmeasured": {\n${entry}\n  }`);
    const block = blockEnd(text, /\n {2}"unmeasured": \{\n/, /\n {2}\}/, "the unmeasured allowlist");
    const lines = text.slice(block.start, block.end).split("\n");
    const keyOf = (line) => /^ {4}"([^"]+)"/.exec(line)?.[1] ?? "";
    const at = lines.findIndex((line) => keyOf(line) > n.id);
    if (at === -1) {
      lines[lines.length - 1] = `${lines[lines.length - 1]},`;
      lines.push(entry);
    } else lines.splice(at, 0, `${entry},`);
    return text.slice(0, block.start) + lines.join("\n") + text.slice(block.end);
  };
}

// One placeholder fixture per evidence dimension the coverage declarations
// require of a detector (positive, overlap, adversarial, boundary, near-miss
// negative); a missing one leaves a pending dimension that coverage:check
// rejects. Inputs are the synthetic placeholder prefix and filler only.
export function fixtureStubs(n, types) {
  const filler = `${PLACEHOLDER_PREFIX}${"5e7c0ded".repeat(4)}`;
  const note = (what) => `${MARKER}: ${what}`;
  const hit = (start, end) => [
    { detector: n.id, type: types[0], confidence: "high", specificity: "provider", start, end },
  ];
  const stub = (suffix, kind, support, tier, input, expected, text, extra = {}) => ({
    id: `${n.id}-${suffix}`,
    detector: n.id,
    kind,
    support,
    tier,
    contexts: ["plain-text"],
    input,
    expected,
    note: note(text),
    ...extra,
  });
  return [
    stub(
      "positive-todo-scaffold",
      "positive",
      "supported",
      "canonical",
      filler,
      hit(0, filler.length),
      "replace with the reviewed synthetic positive; add one fixture per carrier context",
    ),
    stub(
      "overlap-todo-scaffold",
      "overlap",
      "supported",
      "contextual",
      `secret_key=${filler}`,
      hit(11, 11 + filler.length),
      "the provider type must win over a generic contextual secret at the same span",
    ),
    stub(
      "boundary-todo-scaffold",
      "boundary",
      "intentionally-unsupported",
      "malformed",
      `${PLACEHOLDER_PREFIX}${"5e7c0ded".repeat(3)}`,
      [],
      "a value just below the reviewed floor is not claimed",
    ),
    stub(
      "negative-todo-scaffold",
      "negative",
      "supported",
      "negative",
      `${PLACEHOLDER_PREFIX}${"*".repeat(32)}`,
      [],
      "a near-miss twin or benign sibling that must not be flagged",
    ),
    stub(
      "adversarial-todo-scaffold",
      "adversarial",
      "supported",
      "adversarial",
      `${PLACEHOLDER_PREFIX} `.repeat(10),
      [],
      "repeated prefixes stay linear and bounded",
      { resource: { maxInputBytes: 12000, maxFindings: 0, maxRuntimeMs: 250 } },
    ),
  ];
}

function corpusEdits(n, types) {
  const stubs = fixtureStubs(n, types);
  const tail = "\n  ]\n}";
  return {
    [FILES.corpus]: (text) => {
      if (text.includes(`"id": "${stubs[0].id}"`))
        throw new Refusal(`${FILES.corpus}: fixture ${stubs[0].id} already exists`);
      if (!text.trimEnd().endsWith(tail)) throw new Refusal(`${FILES.corpus}: fixtures array end not found`);
      const body = stubs
        .map((fixture) =>
          JSON.stringify(fixture, null, 2)
            .split("\n")
            .map((line) => `    ${line}`)
            .join("\n"),
        )
        .join(",\n");
      return bumpFixtureCount(
        text.trimEnd().slice(0, -tail.length) + `,\n${body}${tail}\n`,
        FILES.corpus,
        stubs.length,
      );
    },
  };
}

function bumpFixtureCount(text, file, added) {
  const count = /("fixtureCount": )(\d+)/.exec(text);
  if (!count) throw new Refusal(`${file}: fixtureCount not found`);
  return text.replace(count[0], `${count[1]}${Number(count[2]) + added}`);
}

function costEdit(n, group) {
  return (text) => {
    if (new RegExp(`^ {2}"${n.id}",$`, "m").test(text)) throw new Refusal(`${FILES.cost}: ${n.id} already listed`);
    const canonical = text.indexOf("export const CANONICAL_IDS = [");
    if (canonical === -1) throw new Refusal(`${FILES.cost}: CANONICAL_IDS not found`);
    const anchor = '\n  "jwt",\n  "bearer-token",';
    const at = text.indexOf(anchor, canonical);
    if (at === -1) throw new Refusal(`${FILES.cost}: canonical id order anchor not found`);
    let out = `${text.slice(0, at)}\n  "${n.id}",${text.slice(at)}`;
    const open = new RegExp(`\\n {2}"?${group}"?: \\[\\n`).exec(out.slice(out.indexOf("export const GROUPS = {")));
    if (!open) throw new Refusal(`${FILES.cost}: group ${group} not found`);
    const base = out.indexOf("export const GROUPS = {");
    const close = out.indexOf("\n  ],", base + open.index + open[0].length);
    if (close === -1) throw new Refusal(`${FILES.cost}: end of group ${group} not found`);
    out = `${out.slice(0, close)}\n    "${n.id}",${out.slice(close)}`;
    return out;
  };
}

const SPEC_HEADING = "## Scaffolded detector rows (not yet reviewed)";
const SPEC_TABLE_HEADER = "| Family | Detector | Grammar | Finding type | Tier |\n| --- | --- | --- | --- | --- |";

function specEdit(n, types, family) {
  return (text) => {
    const head = text.indexOf(SPEC_HEADING);
    if (head !== -1 && text.slice(head).includes(`| \`${n.id}\` |`)) {
      throw new Refusal(`${FILES.spec}: a scaffolded row for ${n.id} already exists`);
    }
    const row = `| \`${family}\` | \`${n.id}\` | ${MARKER}: grammar in words or character classes, exclusions, span rule | ${types.map((type) => `\`${type}\``).join(", ")} | ${MARKER}: tier and evidence link |`;
    if (head === -1) {
      return `${text.trimEnd()}\n\n${SPEC_HEADING}\n\nMove each row into the family table of its batch section when the detector is reviewed.\n\n${SPEC_TABLE_HEADER}\n${row}\n`;
    }
    const next = text.indexOf("\n## ", head + SPEC_HEADING.length);
    const end = next === -1 ? text.length : next;
    return `${text.slice(0, end).trimEnd()}\n${row}\n${text.slice(end)}`;
  };
}

function changelogEdit(n, types, issue) {
  return (text) => {
    const start = text.indexOf("## Unreleased");
    if (start === -1) throw new Refusal(`${FILES.changelog}: "## Unreleased" not found`);
    const nextH2 = text.indexOf("\n## ", start + 1);
    const end = nextH2 === -1 ? text.length : nextH2;
    const section = text.slice(start, end);
    if (section.includes(`\`${n.id}\``)) throw new Refusal(`${FILES.changelog}: Unreleased already mentions ${n.id}`);
    const bullet = `- \`${n.id}\` (${issue}): ${MARKER} describe the detector, its finding type(s) (${types.map((type) => `\`${type}\``).join(", ")}) and the exact supported grammar.`;
    const added = section.indexOf("\n### Added");
    if (added === -1) {
      const heading = text.indexOf("\n", start) + 1;
      return `${text.slice(0, heading)}\n### Added\n\n${bullet}\n${text.slice(heading)}`;
    }
    const subEnd = section.indexOf("\n### ", added + 1);
    const at = start + (subEnd === -1 ? section.length : subEnd);
    return `${text.slice(0, at).trimEnd()}\n${bullet}\n${at < text.length ? "\n" : ""}${text.slice(at).replace(/^\n+/, "")}`;
  };
}

// ---------------------------------------------------------------------------
// The generated Rust module.

export function renderModule(n, types, issue) {
  const typeList = types.map((type) => `"${type}"`).join(", ");
  return `//! ${MARKER}: ${n.id} detection (${issue}).
//!
//! Scaffolded by \`npm run contrib:new-detector\`. The shape below is a
//! placeholder that matches only a synthetic prefix. Replace the prefix, the
//! floor, the alphabet and the span rule with the reviewed contract, then
//! delete every \`${MARKER}\` marker in this file; the last test fails until
//! you do.

use crate::detectors::pattern::{self, PrefixShape};
use crate::error::DetectorFailure;
use crate::types::{ByteRange, Candidate, Confidence, Detector, DetectorContext, Specificity};

pub(super) const ID: &str = "${n.id}";
/// The finding types this detector emits; the inventory declares each one.
const TYPES: [&str; ${types.length}] = [${typeList}];

const BODY_MIN: usize = 32;
const SIGNALS: [&str; 1] = ["${n.id}-prefix"];

/// ${MARKER}: the reviewed prefix, floor and alphabet; also the detector's
/// literals for the shared prefilter.
pub(super) const SHAPES: &[PrefixShape<'static>] = &[PrefixShape::at_least(
    "${PLACEHOLDER_PREFIX}",
    BODY_MIN,
    pattern::is_alnum_dash,
    &SIGNALS,
)];

pub(super) struct ${n.struct};

pub(super) const ${n.constant}: ${n.struct} = ${n.struct};

impl Detector for ${n.struct} {
    fn id(&self) -> &str {
        ID
    }

    fn detect(
        &self,
        input: &str,
        _context: &DetectorContext,
    ) -> Result<Vec<Candidate>, DetectorFailure> {
        let mut candidates = Vec::new();
        for (start, end, signals) in
            pattern::scan_prefixed_shapes(input, SHAPES, pattern::is_alnum_dash)
        {
            let Some(range) = ByteRange::new(start, end) else {
                continue;
            };
            // ${MARKER}: choose the finding type per shape when more than one
            // is declared, and apply the reviewed span and boundary rules.
            candidates.push(
                Candidate::built_in(TYPES[0], Confidence::High, range)
                    .with_specificity(Specificity::Provider)
                    .with_signals(signals.iter().copied()),
            );
        }
        Ok(candidates)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn detect(input: &str) -> Vec<Candidate> {
        ${n.constant}
            .detect(input, &DetectorContext::new(input.len()))
            .unwrap()
    }

    #[test]
    fn positives_are_claimed_as_one_span() {
        // ${MARKER}: one case per reviewed positive. Build each value at run
        // time from repeated synthetic filler, never a realistic key literal.
        let token = format!("{}{}", "${PLACEHOLDER_PREFIX}", "5e7c0ded".repeat(4));
        let candidates = detect(&token);
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].type_name(), TYPES[0]);
        assert_eq!(
            candidates[0].range(),
            ByteRange::new(0, token.len()).unwrap()
        );
    }

    #[test]
    fn near_miss_twins_are_rejected() {
        // ${MARKER}: one case per reviewed near-miss twin and benign sibling.
        let short = format!("{}{}", "${PLACEHOLDER_PREFIX}", "5e7c0ded".repeat(3));
        assert!(detect(&short).is_empty());
    }

    #[test]
    fn scaffold_markers_are_gone() {
        // Fails until every placeholder in this file is replaced.
        let marker = concat!("TODO", "(scaffold)");
        assert!(
            !include_str!("${n.module}.rs").contains(marker),
            "replace every scaffold marker in ${n.module}.rs"
        );
    }
}
`;
}

// ---------------------------------------------------------------------------
// Planning

/** Builds the full plan in memory; touches no file. */
export function plan({ root, id, types, policyClass, group, family, issue, benchmarkIssue }) {
  const n = names(id);
  const issueRef = issue ? `#${issue}` : `#${MARKER}`;
  const creates = { [`${DETECTORS_DIR}/${n.module}.rs`]: renderModule(n, types, issueRef) };
  const edits = {
    ...modEdits(n),
    [FILES.prefilter]: prefilterEdit,
    [FILES.inventory]: inventoryEdit(n, types, policyClass),
    [FILES.allowlist]: allowlistEdit(n, issueRef, benchmarkIssue),
    ...corpusEdits(n, types),
    [FILES.cost]: costEdit(n, group),
    [FILES.spec]: specEdit(n, types, family),
    [FILES.changelog]: changelogEdit(n, types, issueRef),
  };
  if (policyClass === "always-redact") edits[FILES.policy] = policyEdit(types);

  const refusals = [];
  const writes = new Map();
  for (const [path, content] of Object.entries(creates)) {
    if (existsSync(join(root, path))) refusals.push(`${path}: already exists; refusing to overwrite`);
    else writes.set(path, { content, created: true });
  }
  for (const [path, edit] of Object.entries(edits)) {
    const file = join(root, path);
    if (!existsSync(file)) {
      refusals.push(`${path}: not found; run from a repository checkout`);
      continue;
    }
    try {
      writes.set(path, { content: edit(readFileSync(file, "utf8")), created: false });
    } catch (error) {
      if (!(error instanceof Refusal)) throw error;
      refusals.push(error.message);
    }
  }
  return { writes, refusals, names: n };
}

/** Writes every file through a temp file, so a failure leaves no half state. */
export function apply(root, writes) {
  const staged = [];
  try {
    for (const [path, { content }] of writes) {
      const temp = join(root, `${path}.contrib-new-detector.tmp`);
      writeFileSync(temp, content, { flag: "wx" });
      staged.push([temp, join(root, path)]);
    }
  } catch (error) {
    for (const [temp] of staged) unlinkSync(temp);
    throw error;
  }
  for (const [temp, target] of staged) renameSync(temp, target);
}

// ---------------------------------------------------------------------------
// CLI

const USAGE = `Usage: npm run contrib:new-detector -- <detector-id> [options]
       npm run contrib:new-detector -- --handoff <file>.handoff.json [options]

Scaffold the structural skeleton of a new built-in detector. Nothing is
written unless every target can be written; existing files and entries are
never overwritten.

Options:
  --handoff <file>        implementation-ready handoff (v1 schema); supplies the
                          detector id, finding types, policy class, family and issue
  --finding-type <name>   snake_case finding type; repeatable (default: id with _)
  --policy-class <class>  always-redact (default) or confidence-gated
  --group <group>         cost-measurement group: ${GROUPS.join(", ")} (default: saas)
  --family <id>           taxonomy id for the spec row (default: TODO marker)
  --issue <number>        core implementation issue, for changelog and notes
  --dry-run               print the plan and write nothing
  --help                  show this text

Exit codes: 0 done or planned, 1 refused (exists or anchor moved), 2 invalid input.`;

export function parseArgs(argv) {
  const options = { types: [], dryRun: false, positional: [] };
  const valued = new Set(["--handoff", "--finding-type", "--policy-class", "--group", "--family", "--issue", "--root"]);
  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    if (arg === "--dry-run") options.dryRun = true;
    else if (arg === "--help" || arg === "-h") options.help = true;
    else if (valued.has(arg)) {
      const value = argv[index + 1];
      if (value === undefined || value.startsWith("--")) throw new UsageError(`${arg} needs a value`);
      index += 1;
      if (arg === "--finding-type") options.types.push(value);
      else options[arg.slice(2).replace(/-(\w)/g, (_, c) => c.toUpperCase())] = value;
    } else if (arg.startsWith("--")) throw new UsageError(`unknown option ${arg}`);
    else options.positional.push(arg);
  }
  if (options.positional.length > 1) throw new UsageError("expected at most one detector id");
  return options;
}

const ACTION_TO_CLASS = { redact: "always-redact", warn: "confidence-gated" };

/** Resolves flags and an optional handoff into one validated input. */
export function resolveInput(options, root) {
  let handoff;
  if (options.handoff) {
    const file = resolve(options.handoff);
    if (!existsSync(file)) throw new UsageError(`${options.handoff}: no such file`);
    let parsed;
    try {
      parsed = JSON.parse(readFileSync(file, "utf8"));
    } catch (error) {
      throw new UsageError(`${options.handoff}: not valid JSON (${error.message})`);
    }
    const schema = JSON.parse(readFileSync(join(root, SCHEMA_PATH), "utf8"));
    const errors = validateHandoff(parsed, schema);
    if (errors.length > 0) throw new UsageError(`${options.handoff} is not a valid handoff:\n  ${errors.join("\n  ")}`);
    if (parsed.identity.route !== "new-detector") {
      throw new UsageError(
        `identity.route is "${parsed.identity.route}"; the scaffold only creates a new-detector (other routes edit an existing detector)`,
      );
    }
    handoff = parsed;
  }
  const id = options.positional[0] ?? handoff?.identity.detector;
  if (!id) throw new UsageError("a detector id is required (positional, or identity.detector in the handoff)");
  if (!ID_PATTERN.test(id)) throw new UsageError(`detector id "${id}" must match ${ID_PATTERN}`);
  if (handoff && handoff.identity.detector !== id) {
    throw new UsageError(
      `detector id "${id}" does not match the handoff identity.detector "${handoff.identity.detector}"`,
    );
  }

  let types = options.types;
  if (handoff) {
    if (
      types.length > 0 &&
      JSON.stringify([...types].sort()) !== JSON.stringify([...handoff.identity.findingTypes].sort())
    ) {
      throw new UsageError("--finding-type conflicts with the handoff identity.findingTypes");
    }
    types = handoff.identity.findingTypes;
  }
  if (types.length === 0) types = [id.replaceAll("-", "_")];
  for (const type of types) {
    if (!TYPE_PATTERN.test(type)) throw new UsageError(`finding type "${type}" must match ${TYPE_PATTERN}`);
  }
  if (new Set(types).size !== types.length) throw new UsageError("finding types must be unique");

  let policyClass = options.policyClass;
  if (handoff) {
    const fromHandoff = ACTION_TO_CLASS[handoff.policy.defaultAction];
    if (!fromHandoff) {
      throw new UsageError(
        `policy.defaultAction "${handoff.policy.defaultAction}" has no scaffold: only redact and warn map to a policy class; a block or none default is a policy change`,
      );
    }
    if (policyClass && policyClass !== fromHandoff)
      throw new UsageError(`--policy-class ${policyClass} conflicts with the handoff policy.defaultAction`);
    policyClass = fromHandoff;
  }
  policyClass ??= "always-redact";
  if (!POLICY_CLASSES.includes(policyClass)) {
    throw new UsageError(
      `--policy-class must be one of ${POLICY_CLASSES.join(", ")} (a block default is a policy change, not a scaffold)`,
    );
  }

  const group = options.group ?? "saas";
  if (!GROUPS.includes(group)) throw new UsageError(`--group must be one of ${GROUPS.join(", ")}`);
  const family = options.family ?? handoff?.identity.family ?? `${MARKER}: family`;
  if (options.family && !FAMILY_PATTERN.test(family))
    throw new UsageError(`--family "${family}" must match ${FAMILY_PATTERN}`);
  const issue = options.issue ?? (handoff ? String(handoff.issue.number) : undefined);
  if (issue !== undefined && !/^[1-9][0-9]*$/.test(issue)) throw new UsageError("--issue must be a positive integer");
  return {
    id,
    types,
    policyClass,
    group,
    family,
    issue,
    benchmarkIssue: handoff?.evaluation.benchmarkIssue,
    handoffCommands: handoff?.commands ?? [],
  };
}

export function nextSteps(input, n) {
  const lines = [
    "Next, in order:",
    `  1. git grep -n --untracked 'TODO(scaffold)' -- . ':!scripts/' ':!CONTRIBUTION.md'   # every marker; replace each`,
    `  2. edit ${DETECTORS_DIR}/${n.module}.rs and the synthetic fixture to the reviewed contract, then cargo fmt --all`,
    "  3. regenerate the derived files:",
    "       python3 -B scripts/generate-detector-inventory-docs.py",
    "       python3 -B scripts/generate-detector-families-table.py",
    "       python3 -B scripts/generate-coverage-inventory.py --out docs/coverage/inventory-report.json",
    "       python3 -B scripts/generate-coverage-declarations.py --out docs/coverage/coverage-declarations.json",
    "       python3 -B scripts/generate-coverage-report.py --out docs/coverage/coverage-report.md",
    "       npm run support-matrix:generate",
    "       REDACT_SECRET_UPDATE_COMMON_EXPECTATIONS=1 cargo test -p redact-secret --test common_profile_corpus",
    "  4. run the scoped checks (CONTRIBUTION.md, 'Before opening a change'):",
    "       npm run check:detector && npm run check:js && npm run check:rust",
    "       npm run check:docs",
  ];
  if (input.handoffCommands.length > 0)
    lines.push(`  5. the handoff's own commands: ${input.handoffCommands.join(" ; ")}`);
  lines.push("A new detector is a boundary change: read ARCHITECTURE.md and the decision router first.");
  return lines;
}

export function main(argv, { root = REPO_ROOT, out = console.log, err = console.error } = {}) {
  let options;
  try {
    options = parseArgs(argv);
    if (options.help) {
      out(USAGE);
      return 0;
    }
    const effectiveRoot = options.root ? resolve(options.root) : root;
    const input = resolveInput(options, effectiveRoot);
    const { writes, refusals, names: n } = plan({ root: effectiveRoot, ...input });
    if (refusals.length > 0) {
      err(`contrib:new-detector refused; nothing was written:\n  ${refusals.join("\n  ")}`);
      return 1;
    }
    out(`${options.dryRun ? "Plan (dry run, nothing written)" : "Scaffolded"} for detector ${input.id}:`);
    out(`  finding types: ${input.types.join(", ")}; policy class: ${input.policyClass}; group: ${input.group}`);
    for (const [path, { created }] of writes) out(`  ${created ? "create" : "edit  "} ${path}`);
    if (!options.dryRun) apply(effectiveRoot, writes);
    for (const line of nextSteps(input, n)) out(line);
    return 0;
  } catch (error) {
    if (error instanceof UsageError) {
      err(`contrib:new-detector: ${error.message}\n\n${USAGE}`);
      return 2;
    }
    throw error;
  }
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  process.exitCode = main(process.argv.slice(2));
}
