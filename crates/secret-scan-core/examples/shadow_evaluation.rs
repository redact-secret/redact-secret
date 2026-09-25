//! Maintainer-local shadow evaluation of the beta.9 evidence scorer
//! (issue #771, `docs/specs/engine.md`, "Maintainer-local shadow
//! evaluation").
//!
//! ```text
//! cargo run --release --locked -p redact-secret --example shadow_evaluation -- \
//!     [--profile full|common] [--artifact <path>] < inputs.jsonl > shadow.jsonl
//! ```
//!
//! Reads JSON Lines from standard input, one `{"id": "...", "text": "..."}`
//! object per line, and writes JSON Lines to standard output: one
//! `shadow-evaluation` header, then for each input one `shadow-comparison`
//! line per finding the product reports (or one `shadow-error` line). The
//! format is `redact-secret/shadow-evaluation/1`.
//!
//! # Why this compiles the core source itself
//!
//! The scorer is crate-internal on purpose: no public Rust, JavaScript,
//! Python or CLI item carries a score or band, and the core declares no
//! Cargo features
//! (`decision-freeze-the-shadow-evidence-score-and-confidence-contract`,
//! sections 8 and 9). A separate crate cannot name a `pub(crate)` item, so
//! this example does not link the library's API for the evaluation. It
//! compiles the library's own source files as modules of this executable,
//! the same files at the same commit, so it runs the product's detectors,
//! overlap resolution and scorer rather than a reimplementation, without
//! making any item public. The module list below mirrors `src/lib.rs`; a
//! module the evaluation needs and this list lacks fails to compile.
//!
//! Like `assessment_adapter`, this file sits outside the published package
//! (`include` is `src/**/*.rs` and `README.md`), and only it performs I/O:
//! the core source it compiles still names no file, stream or environment
//! facility.

#![forbid(unsafe_code)]
#![allow(
    dead_code,
    unused_imports,
    reason = "the mirrored core modules carry the whole public API, most of which this executable does not call"
)]
// In the library these signatures are exported API, which clippy exempts
// from these lints (`avoid-breaking-exported-api`). Compiled into an
// executable they are no longer exported, so the lints would fire on core
// source that is correct as it stands.
#![allow(
    clippy::trivially_copy_pass_by_ref,
    clippy::unnecessary_wraps,
    clippy::unused_self,
    reason = "the core's public signatures are fixed API, not this executable's choice"
)]

#[path = "../src/detectors/mod.rs"]
mod detectors;
#[path = "../src/entropy.rs"]
mod entropy;
#[path = "../src/error.rs"]
mod error;
#[path = "../src/evidence/mod.rs"]
mod evidence;
#[path = "../src/incremental.rs"]
mod incremental;
#[path = "../src/invisible_table.rs"]
mod invisible_table;
#[path = "../src/limits.rs"]
mod limits;
#[path = "../src/normalize.rs"]
mod normalize;
#[path = "../src/pipeline.rs"]
mod pipeline;
#[path = "../src/policy.rs"]
mod policy;
#[path = "../src/redact.rs"]
mod redact;
#[path = "../src/registry.rs"]
mod registry;
#[path = "../src/ruleset.rs"]
mod ruleset;
#[path = "../src/types.rs"]
mod types;

// The crate-root names the core source refers to as `crate::…`, mirrored
// from `src/lib.rs`.
use entropy::shannon_entropy;
use error::{
    DetectorFailure, FormatterFailure, PolicyFailure, SecretScanError, SecretScanErrorCode,
};
use incremental::{
    IncrementalLimits, IncrementalPolicy, IncrementalPolicyContext, IncrementalResult,
    IncrementalSanitizer, SessionState,
};
use limits::{DEFAULT_MAX_FINDINGS, DEFAULT_MAX_INPUT_BYTES, WholeInputLimits};
use pipeline::{
    run_detector_pipeline, scan, scan_and_redact, scan_and_redact_with_limits, scan_with_limits,
};
use policy::DefaultPolicy;
use redact::{
    MAX_PLACEHOLDER_LENGTH, default_placeholder_formatter, redact, redact_with_limits,
    typed_placeholder_formatter,
};
use registry::{DetectorRegistry, Profile, RegisteredDetector};
use ruleset::{RulesetError, RulesetErrorClass, load_ruleset};
use types::{
    Action, ByteRange, Candidate, Confidence, DetectedFinding, Detector, DetectorContext, Finding,
    MAX_IDENTIFIER_LENGTH, Obfuscation, PlaceholderContext, PlaceholderFormatter, Policy,
    PolicyContext, ScanResult, Specificity, is_identifier,
};

/// `src/lib.rs`'s `VERSION`: this example belongs to the same package.
const VERSION: &str = env!("CARGO_PKG_VERSION");
/// `src/lib.rs`'s `RANGE_UNIT`.
const RANGE_UNIT: &str = "utf8-bytes";

use std::io::{BufRead as _, Write as _};
use std::path::PathBuf;
use std::process::ExitCode;

use evidence::aggregate::SHADOW_MODEL;
use evidence::features::FEATURE_SCHEMA_VERSION;
use evidence::shadow::{shadow_evaluation_header, shadow_evaluation_jsonl};

/// The reviewed scoring artifact, relative to this package.
const DEFAULT_ARTIFACT: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../docs/contracts/scoring/shadow-scoring-artifact.json"
);

struct Options {
    profile: Profile,
    artifact: PathBuf,
}

fn parse_options() -> Result<Options, String> {
    let mut options = Options {
        profile: Profile::Full,
        artifact: PathBuf::from(DEFAULT_ARTIFACT),
    };
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--profile" => {
                let name = args.next().ok_or("--profile needs full or common")?;
                options.profile = Profile::from_name(&name)
                    .ok_or_else(|| format!("unknown profile {name:?}; use full or common"))?;
            }
            "--artifact" => {
                options.artifact = PathBuf::from(args.next().ok_or("--artifact needs a path")?);
            }
            other => return Err(format!("unknown argument {other:?}")),
        }
    }
    Ok(options)
}

/// The artifact's `revision` and `modelFingerprint`, after checking that it
/// describes the scorer compiled here.
fn artifact_identity(path: &PathBuf) -> Result<(u64, String), String> {
    let text = std::fs::read_to_string(path)
        .map_err(|error| format!("cannot read {}: {error}", path.display()))?;
    let artifact: serde_json::Value = serde_json::from_str(&text)
        .map_err(|error| format!("{} is not JSON: {error}", path.display()))?;
    let model = artifact["model"]["aggregation"]["id"].as_str();
    let features = artifact["model"]["featureSchema"]["id"].as_str();
    if model != Some(SHADOW_MODEL.id) || features != Some(FEATURE_SCHEMA_VERSION) {
        return Err(format!(
            "{} describes {model:?} over {features:?}, but this build compiles {} over {}",
            path.display(),
            SHADOW_MODEL.id,
            FEATURE_SCHEMA_VERSION
        ));
    }
    let revision = artifact["artifact"]["revision"]
        .as_u64()
        .ok_or("artifact.revision is not an integer")?;
    let fingerprint = artifact["modelFingerprint"]
        .as_str()
        .filter(|value| value.len() == 64 && value.bytes().all(|b| b.is_ascii_hexdigit()))
        .ok_or("modelFingerprint is not a SHA-256")?;
    Ok((revision, fingerprint.to_owned()))
}

/// One input line's `id` and `text`. Errors name the line, never its
/// content.
fn parse_input(number: usize, line: &str) -> Result<(String, String), String> {
    let record: serde_json::Value = serde_json::from_str(line)
        .map_err(|_| format!("input line {number} is not JSON text in valid Unicode"))?;
    let field = |name: &str| {
        record[name]
            .as_str()
            .map(str::to_owned)
            .ok_or_else(|| format!("input line {number} has no string {name:?}"))
    };
    Ok((field("id")?, field("text")?))
}

fn run() -> Result<(), String> {
    let options = parse_options()?;
    let (revision, fingerprint) = artifact_identity(&options.artifact)?;
    let registry = match options.profile {
        Profile::Full => DetectorRegistry::with_built_in([]),
        Profile::Common => DetectorRegistry::with_common_built_in([]),
    }
    .map_err(|error| format!("cannot build the registry: {}", error.code().as_str()))?;

    let stdout = std::io::stdout();
    let mut out = std::io::BufWriter::new(stdout.lock());
    let write_error = |error: std::io::Error| format!("cannot write output: {error}");
    out.write_all(
        shadow_evaluation_header(revision, &fingerprint, options.profile.as_str()).as_bytes(),
    )
    .map_err(write_error)?;

    for (index, line) in std::io::stdin().lock().lines().enumerate() {
        let number = index + 1;
        let line = line.map_err(|error| format!("cannot read input line {number}: {error}"))?;
        if line.trim().is_empty() {
            continue;
        }
        let (id, text) = parse_input(number, &line)?;
        out.write_all(shadow_evaluation_jsonl(&id, &text, &registry).as_bytes())
            .map_err(write_error)?;
    }
    out.flush().map_err(write_error)
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            let _ = writeln!(std::io::stderr(), "shadow_evaluation: {message}");
            ExitCode::from(2)
        }
    }
}
