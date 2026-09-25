#!/usr/bin/env python3
"""Check the reviewed shadow scoring artifact against the compiled scorer (issue #798).

`docs/contracts/scoring/shadow-scoring-artifact.json` is the one reviewed,
versioned record of the beta.9 shadow evidence scorer: feature schema,
aggregation model, calibration provenance and review method
(`docs/specs/engine.md`, "Shadow scoring artifact"). It is a review and CI
artifact. Nothing loads it at runtime and no package ships it.

Core source may not read files, so the compiled side reaches this script
through one literal: `REVIEWED_MODEL_JSON` in
`crates/secret-scan-core/src/evidence/aggregate/artifact_drift.rs`, whose
test requires it to equal the rendering of the compiled `SHADOW_MODEL`,
feature schema and exclusion vocabulary. This script checks the other half:

1. the artifact validates against its JSON Schema;
2. the artifact's `model` equals `REVIEWED_MODEL_JSON`, so compiled and
   reviewed values agree in both directions;
3. `modelFingerprint` is the SHA-256 of `model`'s canonical JSON;
4. the identity ledger is append-only in shape: each model identity maps to
   one fingerprint, and the current identity maps to the current one. A
   changed constant under an unchanged model identity fails here;
5. every source hash (spec sections and scorer code) matches the tree;
6. no package manifest would ship the artifact.

With `--base <rev>` (the pull-request CI job), it also compares with the
artifact at `rev`: any change needs a higher `artifact.revision`, a changed
`model` needs a new model identity, a changed feature schema needs a new
feature schema identity, and the ledger may only grow.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path

ARTIFACT = "docs/contracts/scoring/shadow-scoring-artifact.json"
SCHEMA = "docs/contracts/scoring/shadow-scoring-artifact.schema.json"
DRIFT_TEST = "crates/secret-scan-core/src/evidence/aggregate/artifact_drift.rs"
LITERAL = re.compile(r'const REVIEWED_MODEL_JSON: &str = r(?P<hashes>#+)"(?P<body>.*?)"(?P=hashes);', re.S)
CORE_MANIFEST = "crates/secret-scan-core/Cargo.toml"
JS_PACKAGE = "packages/javascript/package.json"


def canonical(value) -> bytes:
    """Canonical JSON: sorted keys, no whitespace, UTF-8."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def fingerprint(model) -> str:
    return hashlib.sha256(canonical(model)).hexdigest()


# --- a JSON Schema (draft 2020-12) subset: the keywords the schema uses ------

TYPES = {
    "object": lambda v: isinstance(v, dict),
    "array": lambda v: isinstance(v, list),
    "string": lambda v: isinstance(v, str),
    "integer": lambda v: isinstance(v, int) and not isinstance(v, bool),
    "boolean": lambda v: isinstance(v, bool),
    "null": lambda v: v is None,
}
SUPPORTED = {
    "$schema", "$id", "$defs", "$ref", "title", "description", "type", "required", "properties",
    "additionalProperties", "items", "enum", "const", "pattern", "minimum", "maximum",
    "minItems", "maxItems", "minLength",
}


def validate_schema(value, schema: dict, root: dict, path: str = "$") -> list[str]:
    unknown = set(schema) - SUPPORTED
    if unknown:
        return [f"{path}: schema uses unsupported keywords {sorted(unknown)}"]
    if "$ref" in schema:
        ref = schema["$ref"]
        if not ref.startswith("#/$defs/"):
            return [f"{path}: unsupported $ref {ref}"]
        return validate_schema(value, root["$defs"][ref.removeprefix("#/$defs/")], root, path)
    errors: list[str] = []
    if "type" in schema:
        types = schema["type"] if isinstance(schema["type"], list) else [schema["type"]]
        if not any(TYPES[name](value) for name in types):
            return [f"{path}: expected {' or '.join(types)}"]
    if "const" in schema and (value != schema["const"] or type(value) is not type(schema["const"])):
        errors.append(f"{path}: must be {json.dumps(schema['const'])}")
    if "enum" in schema and value not in schema["enum"]:
        errors.append(f"{path}: must be one of {schema['enum']}")
    if isinstance(value, str):
        if "pattern" in schema and not re.search(schema["pattern"], value):
            errors.append(f"{path}: does not match {schema['pattern']}")
        if len(value) < schema.get("minLength", 0):
            errors.append(f"{path}: shorter than {schema['minLength']}")
    if isinstance(value, int) and not isinstance(value, bool):
        if "minimum" in schema and value < schema["minimum"]:
            errors.append(f"{path}: below {schema['minimum']}")
        if "maximum" in schema and value > schema["maximum"]:
            errors.append(f"{path}: above {schema['maximum']}")
    if isinstance(value, list):
        if len(value) < schema.get("minItems", 0):
            errors.append(f"{path}: fewer than {schema['minItems']} items")
        if "maxItems" in schema and len(value) > schema["maxItems"]:
            errors.append(f"{path}: more than {schema['maxItems']} items")
        if "items" in schema:
            for index, item in enumerate(value):
                errors.extend(validate_schema(item, schema["items"], root, f"{path}[{index}]"))
    if isinstance(value, dict):
        for key in schema.get("required", []):
            if key not in value:
                errors.append(f"{path}: missing {key}")
        properties = schema.get("properties", {})
        for key, item in value.items():
            if key in properties:
                errors.extend(validate_schema(item, properties[key], root, f"{path}.{key}"))
            elif schema.get("additionalProperties") is False:
                errors.append(f"{path}: unexpected key {key}")
    return errors


# --- checks -----------------------------------------------------------------


def reviewed_literal(source: str):
    """The parsed `REVIEWED_MODEL_JSON` literal, or an error string."""
    match = LITERAL.search(source)
    if match is None:
        return None, f"{DRIFT_TEST}: REVIEWED_MODEL_JSON raw-string literal not found"
    try:
        return json.loads(match.group("body")), None
    except json.JSONDecodeError as error:
        return None, f"{DRIFT_TEST}: REVIEWED_MODEL_JSON is not JSON ({error})"


def spec_section(text: str, title: str) -> str | None:
    """The text of the `## <title>` section, up to the next `## ` heading."""
    lines = text.replace("\r\n", "\n").split("\n")
    heading = f"## {title}"
    try:
        start = lines.index(heading)
    except ValueError:
        return None
    end = next((i for i in range(start + 1, len(lines)) if lines[i].startswith("## ")), len(lines))
    return "\n".join(lines[start:end]).rstrip("\n") + "\n"


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def check_model(artifact: dict, literal) -> list[str]:
    errors = []
    model = artifact.get("model")
    if literal is not None and model != literal:
        errors.append(
            f"{ARTIFACT}: model differs from the compiled scorer's rendering ({DRIFT_TEST}, REVIEWED_MODEL_JSON). "
            "A changed scorer value is a new model identity; see docs/specs/engine.md, 'Shadow scoring artifact'"
        )
    actual = fingerprint(model)
    if artifact.get("modelFingerprint") != actual:
        errors.append(f"{ARTIFACT}: modelFingerprint is {artifact.get('modelFingerprint')}, but model hashes to {actual}")
    features = model.get("featureSchema", {})
    aggregation = model.get("aggregation", {})
    if aggregation.get("featureSchema") != features.get("id"):
        errors.append(f"{ARTIFACT}: model.aggregation.featureSchema must equal model.featureSchema.id")
    width = len(features.get("features", []))
    for golden in features.get("goldenVectors", []):
        if len(golden.get("vector", [])) != width:
            errors.append(f"{ARTIFACT}: a golden vector does not have {width} features")
    bands = aggregation.get("bands", {})
    if not (0 < bands.get("low", 0) < bands.get("medium", 0) < bands.get("high", 0)):
        errors.append(f"{ARTIFACT}: bands must satisfy 0 < low < medium < high")
    calibration = artifact.get("calibration", {})
    if calibration.get("scoring", {}).get("featureSchemaVersion") != features.get("id"):
        errors.append(f"{ARTIFACT}: calibration.scoring.featureSchemaVersion must equal model.featureSchema.id")
    if calibration.get("featureDataset", {}).get("featureSchema") != features.get("id"):
        errors.append(f"{ARTIFACT}: calibration.featureDataset.featureSchema must equal model.featureSchema.id")
    return errors


def check_ledger(artifact: dict) -> list[str]:
    errors = []
    ledger = artifact.get("identityLedger", [])
    revision = artifact.get("artifact", {}).get("revision", 0)
    seen: dict[str, str] = {}
    for entry in ledger:
        model_id = entry.get("model")
        if model_id in seen:
            errors.append(f"{ARTIFACT}: identityLedger lists {model_id} twice; a model identity is never reused")
        seen[model_id] = entry.get("modelFingerprint")
        if entry.get("introducedInRevision", 0) > revision:
            errors.append(f"{ARTIFACT}: identityLedger entry {model_id} is newer than artifact.revision {revision}")
    model = artifact.get("model", {})
    current = model.get("aggregation", {}).get("id")
    matching = [entry for entry in ledger if entry.get("model") == current]
    if not matching:
        errors.append(f"{ARTIFACT}: identityLedger has no entry for the current model identity {current}")
    else:
        entry = matching[0]
        if entry.get("modelFingerprint") != artifact.get("modelFingerprint"):
            errors.append(
                f"{ARTIFACT}: model identity {current} is recorded with fingerprint {entry.get('modelFingerprint')}, "
                f"but the model now hashes to {artifact.get('modelFingerprint')}. Changed scorer values need a new "
                "model identity (and a new ledger entry), never a rewritten one"
            )
        if entry.get("featureSchema") != model.get("featureSchema", {}).get("id"):
            errors.append(f"{ARTIFACT}: identityLedger entry {current} names a different feature schema")
        if ledger[-1] is not entry:
            errors.append(f"{ARTIFACT}: the current model identity must be the last identityLedger entry")
    return errors


def check_tuning_manifest(artifact: dict) -> list[str]:
    tuning = artifact.get("tuningManifest", {})
    status, value = tuning.get("status"), tuning.get("hash")
    if status == "pending" and value is not None:
        return [f"{ARTIFACT}: a pending tuningManifest has hash null"]
    if status == "bound" and value is None:
        return [f"{ARTIFACT}: a bound tuningManifest records its hash"]
    return []


def check_sources(root: Path, artifact: dict) -> list[str]:
    errors = []
    sources = artifact.get("sources", {})
    for entry in sources.get("spec", []):
        path = root / entry["path"]
        if not path.is_file():
            errors.append(f"{ARTIFACT}: source {entry['path']} does not exist")
            continue
        section = spec_section(path.read_text(encoding="utf-8"), entry["section"])
        if section is None:
            errors.append(f"{ARTIFACT}: {entry['path']} has no section '## {entry['section']}'")
            continue
        actual = sha256_text(section)
        if actual != entry["sha256"]:
            errors.append(
                f"{ARTIFACT}: {entry['path']} '{entry['section']}' hashes to {actual}, not {entry['sha256']}. "
                "Review whether the change alters scorer semantics (a new identity) and record the new hash in a new artifact revision"
            )
    for entry in sources.get("code", []):
        path = root / entry["path"]
        if not path.is_file():
            errors.append(f"{ARTIFACT}: source {entry['path']} does not exist")
            continue
        actual = hashlib.sha256(path.read_bytes().replace(b"\r\n", b"\n")).hexdigest()
        if actual != entry["sha256"]:
            errors.append(
                f"{ARTIFACT}: {entry['path']} hashes to {actual}, not {entry['sha256']}. "
                "Review whether the change alters scorer semantics (a new identity) and record the new hash in a new artifact revision"
            )
    return errors


def check_not_packaged(root: Path) -> list[str]:
    """The artifact is not API: no package file list may include it."""
    errors = []
    js = json.loads((root / JS_PACKAGE).read_text(encoding="utf-8"))
    for entry in js.get("files", []):
        if "docs" in Path(entry).parts or entry.endswith(".json") and "scoring" in entry:
            errors.append(f"{JS_PACKAGE}: files entry {entry!r} could ship the scoring artifact")
    manifest = (root / CORE_MANIFEST).read_text(encoding="utf-8")
    include = re.search(r"^include\s*=\s*\[(?P<items>[^\]]*)\]", manifest, re.M)
    if include is None:
        errors.append(f"{CORE_MANIFEST}: [package] include not found")
    else:
        for item in re.findall(r'"([^"]+)"', include.group("items")):
            if not (item.startswith("src/") or item in {"README.md"}):
                errors.append(f"{CORE_MANIFEST}: include entry {item!r} could ship files beyond the core source")
    return errors


def compare_with_base(base: dict | None, head: dict) -> list[str]:
    """Identity rules between the base branch's artifact and this one."""
    if base is None or canonical(base) == canonical(head):
        return []
    errors = []
    base_revision = base.get("artifact", {}).get("revision", 0)
    head_revision = head.get("artifact", {}).get("revision", 0)
    if head_revision <= base_revision:
        errors.append(
            f"{ARTIFACT}: the artifact changed but artifact.revision stayed {head_revision}; any change is a new "
            "artifact revision and invalidates evidence keyed to the old one"
        )
    base_model, head_model = base.get("model", {}), head.get("model", {})
    base_features, head_features = base_model.get("featureSchema", {}), head_model.get("featureSchema", {})
    if canonical(base_features) != canonical(head_features) and base_features.get("id") == head_features.get("id"):
        errors.append(
            f"{ARTIFACT}: feature semantics changed under the same feature schema identity {head_features.get('id')}; "
            "bump FEATURE_SCHEMA_VERSION and the model identity"
        )
    base_id = base_model.get("aggregation", {}).get("id")
    head_id = head_model.get("aggregation", {}).get("id")
    if canonical(base_model) != canonical(head_model) and base_id == head_id:
        errors.append(
            f"{ARTIFACT}: scorer values changed under the same model identity {head_id}; "
            "a changed feature, aggregation, weight, threshold or band is a new model identity"
        )
    base_ledger = base.get("identityLedger", [])
    head_ledger = head.get("identityLedger", [])
    if [canonical(e) for e in head_ledger[: len(base_ledger)]] != [canonical(e) for e in base_ledger]:
        errors.append(f"{ARTIFACT}: identityLedger is append-only; an existing entry was changed or removed")
    return errors


def base_artifact(root: Path, rev: str) -> dict | None:
    result = subprocess.run(
        ["git", "show", f"{rev}:{ARTIFACT}"], cwd=root, capture_output=True, text=True, check=False
    )
    if result.returncode != 0:
        exists = subprocess.run(["git", "rev-parse", "--verify", f"{rev}^{{commit}}"], cwd=root, capture_output=True, check=False)
        if exists.returncode != 0:
            raise SystemExit(f"--base {rev} is not a commit in this checkout (fetch full history)")
        return None
    return json.loads(result.stdout)


def validate(root: Path, base: dict | None = None) -> list[str]:
    artifact = json.loads((root / ARTIFACT).read_text(encoding="utf-8"))
    schema = json.loads((root / SCHEMA).read_text(encoding="utf-8"))
    errors = validate_schema(artifact, schema, schema)
    if errors:
        return [f"{ARTIFACT}: {error}" for error in errors]
    literal, problem = reviewed_literal((root / DRIFT_TEST).read_text(encoding="utf-8"))
    if problem:
        errors.append(problem)
    errors.extend(check_model(artifact, literal))
    errors.extend(check_ledger(artifact))
    errors.extend(check_tuning_manifest(artifact))
    errors.extend(check_sources(root, artifact))
    errors.extend(check_not_packaged(root))
    errors.extend(compare_with_base(base, artifact))
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("root", nargs="?", default=Path.cwd(), type=Path)
    parser.add_argument("--base", help="compare with the artifact at this revision (pull requests)")
    args = parser.parse_args()
    root = args.root.resolve()
    base = base_artifact(root, args.base) if args.base else None
    errors = validate(root, base)
    for error in errors:
        print(f"ERROR {error}")
    scope = f" against {args.base}" if args.base else ""
    print(f"Scoring artifact check{scope} complete: {len(errors)} error(s)")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
