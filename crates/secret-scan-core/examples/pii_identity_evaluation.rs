//! Maintainer-local identity/sensitivity evaluation of one production PII
//! family (issue #910, `docs/specs/engine.md`,
//! "Maintainer-local PII identity evaluation").
//!
//! ```text
//! cargo run --release --locked -p redact-secret --example pii_identity_evaluation -- \
//!     --family pii:global:email < cases.jsonl > identity.jsonl
//! ```
//!
//! Reads JSON Lines from standard input, one object per line with exactly
//! the keys `id` (string), `family` (string, equal to `--family`), `text`
//! (string) and `candidate` (`{"start": <utf8 byte>, "end": <utf8 byte>}` or
//! `null`). `candidate` is the benchmark's authored candidate range, never
//! product output. Writes JSON Lines to standard output: one header
//! `{"format", "family", "vocabulary", "activationIdentity"}`, then exactly
//! one `{"id", "family", "identity", "sensitivity"}` line per input, in input
//! order. The format is `redact-secret/pii-identity-evaluation/1`.
//!
//! `identity` is `established` or `unmatched`; `sensitivity` is `sensitive`,
//! `non-sensitive` or `not-established`. They describe the alternative the
//! family's join keeps for exactly the candidate range. A null candidate, a
//! range no alternative has, or a range that is not a slice of `text` reports
//! `unmatched` / `not-established`. The core has no invalid identity state,
//! so an invalid lookalike and unrecognized text both read `unmatched`. No
//! line carries a confidence, specificity, obfuscation, score, threshold,
//! feature, other range or any part of the input text.
//!
//! # Why this compiles the core source itself
//!
//! Identity and sensitivity are crate-internal on purpose: a public PII
//! finding is the only public statement the product makes about an
//! occurrence, and no public Rust, JavaScript, Python, Wasm or CLI item
//! carries the join's intermediate states. A separate crate cannot name a
//! `pub(crate)` item, so, like `shadow_evaluation`, this example compiles the
//! library's own source files as modules of this executable, the same files
//! at the same commit. It runs the product's family detectors, context
//! vocabulary and join rather than a reimplementation, without making any
//! item public. The module list below mirrors `src/lib.rs`.
//!
//! Like `shadow_evaluation` and `assessment_adapter`, this file sits outside
//! the published package (`include` is `src/**/*.rs` and `README.md`), and
//! only it performs I/O: the core source it compiles still names no file,
//! stream or environment facility.

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

#[path = "../src/composition.rs"]
mod composition;
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
#[path = "../src/json.rs"]
mod json;
#[path = "../src/limits.rs"]
mod limits;
#[path = "../src/normalize.rs"]
mod normalize;
#[path = "../src/pii.rs"]
mod pii;
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
#[path = "../src/selection.rs"]
mod selection;
#[path = "../src/sha256.rs"]
mod sha256;
#[path = "../src/structured_validators.rs"]
mod structured_validators;
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
use pii::PiiSelection;
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
use std::process::ExitCode;

use pii::{IDENTITY_EVALUATION_FORMAT, IdentityEvaluator};
use serde_json::Value;

/// The input keys, exactly.
const INPUT_KEYS: [&str; 4] = ["candidate", "family", "id", "text"];

fn parse_family() -> Result<IdentityEvaluator, String> {
    let mut family = None;
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--family" => family = Some(args.next().ok_or("--family needs a family id")?),
            other => return Err(format!("unknown argument {other:?}")),
        }
    }
    let family = family.ok_or("--family <id> is required, e.g. --family pii:global:email")?;
    IdentityEvaluator::new(&family).ok_or_else(|| {
        format!("{family:?} is not a production PII family compiled into this build")
    })
}

/// One input line: its `id`, `text` and authored `candidate` range.
struct Case {
    id: String,
    text: String,
    candidate: Option<(usize, usize)>,
}

/// One input line's `id`, `text` and `candidate`. Errors name the line and
/// the key, never the content.
fn parse_input(number: usize, line: &str, family: &str) -> Result<Case, String> {
    let record: Value = serde_json::from_str(line)
        .map_err(|_| format!("input line {number} is not JSON text in valid Unicode"))?;
    let object = record
        .as_object()
        .ok_or_else(|| format!("input line {number} is not a JSON object"))?;
    let mut keys: Vec<&str> = object.keys().map(String::as_str).collect();
    keys.sort_unstable();
    if keys != INPUT_KEYS {
        return Err(format!(
            "input line {number} must have exactly the keys {INPUT_KEYS:?}"
        ));
    }
    let string = |name: &str| {
        object[name]
            .as_str()
            .map(str::to_owned)
            .ok_or_else(|| format!("input line {number} has no string {name:?}"))
    };
    if string("family")? != family {
        return Err(format!(
            "input line {number} names a family other than --family"
        ));
    }
    let candidate = match &object["candidate"] {
        Value::Null => None,
        Value::Object(range) => {
            let mut range_keys: Vec<&str> = range.keys().map(String::as_str).collect();
            range_keys.sort_unstable();
            let offset = |name: &str| {
                range[name]
                    .as_u64()
                    .and_then(|value| usize::try_from(value).ok())
                    .ok_or_else(|| {
                        format!("input line {number} candidate.{name} is not a byte offset")
                    })
            };
            if range_keys != ["end", "start"] {
                return Err(format!(
                    "input line {number} candidate must be null or exactly {{\"start\", \"end\"}}"
                ));
            }
            Some((offset("start")?, offset("end")?))
        }
        _ => {
            return Err(format!(
                "input line {number} candidate must be null or exactly {{\"start\", \"end\"}}"
            ));
        }
    };
    Ok(Case {
        id: string("id")?,
        text: string("text")?,
        candidate,
    })
}

fn json_string(value: &str) -> String {
    Value::String(value.to_owned()).to_string()
}

fn run() -> Result<(), String> {
    let evaluator = parse_family()?;
    let family = evaluator.family();

    let stdout = std::io::stdout();
    let mut out = std::io::BufWriter::new(stdout.lock());
    let write_error = |error: std::io::Error| format!("cannot write output: {error}");
    writeln!(
        out,
        "{{\"format\":{},\"family\":{},\"vocabulary\":{},\"activationIdentity\":{}}}",
        json_string(IDENTITY_EVALUATION_FORMAT),
        json_string(family),
        json_string(IdentityEvaluator::vocabulary()),
        json_string(evaluator.activation_identity()),
    )
    .map_err(write_error)?;

    for (index, line) in std::io::stdin().lock().lines().enumerate() {
        let number = index + 1;
        let line = line.map_err(|_| format!("cannot read input line {number}"))?;
        if line.trim().is_empty() {
            continue;
        }
        let case = parse_input(number, &line, family)?;
        let outcome = evaluator.evaluate(&case.text, case.candidate);
        writeln!(
            out,
            "{{\"id\":{},\"family\":{},\"identity\":\"{}\",\"sensitivity\":\"{}\"}}",
            json_string(&case.id),
            json_string(family),
            outcome.identity,
            outcome.sensitivity,
        )
        .map_err(write_error)?;
    }
    out.flush().map_err(write_error)
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            let _ = writeln!(std::io::stderr(), "pii_identity_evaluation: {message}");
            ExitCode::from(2)
        }
    }
}
