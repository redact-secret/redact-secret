//! Assessment adapter for the Rust library surface.
//!
//! This executable is intentionally outside the library package contents. It
//! drives only the public `redact_secret::` API and emits the shared assessment
//! result contract for the `rust-core` surface.

#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_precision_loss,
    clippy::cast_sign_loss,
    clippy::struct_field_names
)]

use std::collections::{HashMap, HashSet};
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Instant;

use redact_secret::{
    Action, DefaultPolicy, DetectorRegistry, Finding, IncrementalLimits, IncrementalSanitizer,
    RANGE_UNIT, VERSION, default_placeholder_formatter, scan, scan_and_redact,
};
use serde_json::{Value, json};

const RESULT_SCHEMA_VERSION: &str = "3";
const DEFAULT_PROFILE: &str = "scale-logs-small-whole";
const BOUNDARY_LIMIT: &str = "Sampled immediately before and after processing; short-lived peaks between those boundaries may be missed, so maxima are observed samples, not guaranteed true peaks.";
const GENERATOR_ALGORITHM: &str = "assessment-filler-density-v1";
const SYNTHETIC_SECRET_LINE: &str = "token=ghp_ASSESSMENTSYNTHETIC0000000000000000\n";

#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    Accuracy,
    Performance,
    SelfTest,
}

struct Options {
    mode: Mode,
    profile: String,
    runs: usize,
    json_out: Option<PathBuf>,
    markdown_out: Option<PathBuf>,
    mismatches_out: Option<PathBuf>,
    strict: bool,
}

#[derive(Clone)]
struct Fixture {
    id: String,
    input: String,
    expected: Vec<Expectation>,
}

#[derive(Clone)]
struct Expectation {
    detector: String,
    type_name: String,
    start: usize,
    end: usize,
    policy: String,
}

struct ActualFinding {
    detector: String,
    type_name: String,
    start: usize,
    end: usize,
    action: String,
}

struct AccuracyTotals {
    true_positives: u64,
    false_positives: u64,
    false_negatives: u64,
    policy_mismatches: u64,
}

struct Profile {
    id: String,
    purpose: String,
    category: String,
    target_input_bytes: usize,
    target_density_per_kib: u64,
    chunk_profile: String,
    unicode_mix: bool,
    generator_algorithm: String,
}

struct Sample {
    initialization_ms: f64,
    processing_ms: f64,
    throughput_bytes_per_second: f64,
    rss: Option<MemorySample>,
}

#[derive(Clone, Copy)]
struct MemorySample {
    baseline_bytes: u64,
    maximum_observed_bytes: u64,
}

fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let options = parse_arguments(env::args().skip(1))?;
    match options.mode {
        Mode::Accuracy => run_accuracy(&options),
        Mode::Performance => run_performance(&options),
        Mode::SelfTest => run_self_test(),
    }
}

fn parse_arguments(args: impl Iterator<Item = String>) -> Result<Options, String> {
    let mut options = Options {
        mode: Mode::Accuracy,
        profile: DEFAULT_PROFILE.to_owned(),
        runs: 10,
        json_out: None,
        markdown_out: None,
        mismatches_out: None,
        strict: false,
    };
    let mut args = args.peekable();
    while let Some(argument) = args.next() {
        match argument.as_str() {
            "accuracy" => options.mode = Mode::Accuracy,
            "performance" => options.mode = Mode::Performance,
            "self-test" => options.mode = Mode::SelfTest,
            "--profile" => options.profile = required_value(&argument, &mut args)?,
            "--runs" => {
                options.runs = required_value(&argument, &mut args)?
                    .parse()
                    .map_err(|_| "--runs must be an integer from 2 through 100".to_owned())?;
            }
            "--json-out" => {
                options.json_out = Some(PathBuf::from(required_value(&argument, &mut args)?));
            }
            "--markdown-out" => {
                options.markdown_out = Some(PathBuf::from(required_value(&argument, &mut args)?));
            }
            "--mismatches-out" => {
                options.mismatches_out = Some(PathBuf::from(required_value(&argument, &mut args)?));
            }
            "--strict" => options.strict = true,
            _ => return Err(format!("unknown argument: {argument}")),
        }
    }
    if !(2..=100).contains(&options.runs) {
        return Err("--runs must be an integer from 2 through 100".to_owned());
    }
    Ok(options)
}

fn required_value(
    name: &str,
    args: &mut std::iter::Peekable<impl Iterator<Item = String>>,
) -> Result<String, String> {
    args.next()
        .filter(|value| !value.is_empty())
        .ok_or_else(|| format!("{name} requires a value"))
}

fn run_accuracy(options: &Options) -> Result<(), String> {
    if RANGE_UNIT != "utf8-bytes" {
        return Err("rust-core range unit drifted from utf8-bytes".to_owned());
    }
    let corpus = read_json(&repo_root().join("assessment/fixtures/accuracy-corpus.json"))?;
    if string_field(&corpus, "offsetUnit")? != "utf8-byte" {
        return Err("accuracy corpus offsetUnit is not utf8-byte".to_owned());
    }
    let fixtures = fixtures(&corpus)?;
    if usize_field(&corpus, "fixtureCount")? != fixtures.len() {
        return Err("accuracy corpus fixtureCount does not match fixtures".to_owned());
    }
    let registry = DetectorRegistry::with_built_in([]).map_err(error_text)?;
    let mut totals = AccuracyTotals {
        true_positives: 0,
        false_positives: 0,
        false_negatives: 0,
        policy_mismatches: 0,
    };
    let mut mismatches = Vec::new();
    for fixture in &fixtures {
        let findings = scan(&fixture.input, &registry, &DefaultPolicy).map_err(|error| {
            format!(
                "accuracy evaluation failed before completing: {}",
                error.code()
            )
        })?;
        let actual = findings.iter().map(actual_finding).collect::<Vec<_>>();
        score_fixture(fixture, &actual, &mut totals, &mut mismatches);
    }
    let result = json!({
        "schemaVersion": RESULT_SCHEMA_VERSION,
        "surface": "rust-core",
        "profileId": "accuracy-corpus",
        "accuracy": {
            "truePositives": totals.true_positives,
            "falsePositives": totals.false_positives,
            "falseNegatives": totals.false_negatives,
            "policyMismatches": totals.policy_mismatches,
        },
        "provenance": provenance(
            &string_or_number(&corpus["corpusVersion"])?,
            &sha256_file(&repo_root().join("assessment/fixtures/accuracy-corpus.json"))?,
            &invoked_command(),
        ),
    });
    write_json(&result, options.json_out.as_deref())?;
    if let Some(path) = options.markdown_out.as_deref() {
        write_file(path, &markdown_accuracy(&result, &mismatches))?;
    }
    if let Some(path) = options.mismatches_out.as_deref() {
        write_file(path, &format_json(&Value::Array(mismatches.clone()))?)?;
    }
    eprintln!(
        "rust-core accuracy: {} true positive(s), {} false positive(s), {} false negative(s), {} policy mismatch(es) across {} fixture(s)",
        totals.true_positives,
        totals.false_positives,
        totals.false_negatives,
        totals.policy_mismatches,
        fixtures.len()
    );
    if options.strict
        && (totals.false_positives > 0
            || totals.false_negatives > 0
            || totals.policy_mismatches > 0)
    {
        return Err("--strict: at least one mismatch was found".to_owned());
    }
    Ok(())
}

fn run_performance(options: &Options) -> Result<(), String> {
    if cfg!(debug_assertions) {
        return Err("Performance assessment requires a release build (--release).".to_owned());
    }
    let document = read_json(&repo_root().join("assessment/fixtures/workload-profiles.json"))?;
    let profiles = array_field(&document, "profiles")?;
    if usize_field(&document, "profileCount")? != profiles.len() {
        return Err("workload profileCount does not match profiles".to_owned());
    }
    let profile = profiles
        .iter()
        .find(|profile| string_field(profile, "id").is_ok_and(|id| id == options.profile))
        .ok_or_else(|| format!("{}: unknown scale profile", options.profile))
        .and_then(profile_from_value)?;
    if profile.purpose != "scale" {
        return Err(format!("{}: unknown scale profile", profile.id));
    }
    if profile.generator_algorithm != GENERATOR_ALGORITHM {
        return Err(format!("{}: unsupported generator", profile.id));
    }
    let mut samples = Vec::new();
    for _ in 0..options.runs {
        samples.push(measure_one(&profile)?);
    }
    let initialization_samples = samples
        .iter()
        .map(|sample| sample.initialization_ms)
        .collect::<Vec<_>>();
    let processing_samples = samples
        .iter()
        .map(|sample| sample.processing_ms)
        .collect::<Vec<_>>();
    let throughput_samples = samples
        .iter()
        .map(|sample| sample.throughput_bytes_per_second)
        .collect::<Vec<_>>();
    let rss_samples = samples
        .iter()
        .filter_map(|sample| sample.rss)
        .collect::<Vec<_>>();
    let rss = if rss_samples.len() == samples.len() {
        available_memory(rss_samples, BOUNDARY_LIMIT)
    } else {
        unavailable_memory(
            "RSS sampling is not implemented for this operating system.",
            "No samples were available.",
        )
    };
    let processing = distribution(&processing_samples);
    let result = json!({
        "schemaVersion": RESULT_SCHEMA_VERSION,
        "surface": "rust-core",
        "profileId": profile.id,
        "performance": {
            "initialization": distribution(&initialization_samples),
            "processing": processing,
            "throughput": distribution_with_unit(&throughput_samples, "bytes-per-second"),
            "memory": {
                "nodeHeap": unavailable_memory("The Rust library does not run inside a Node.js heap.", "No samples were available."),
                "nodeRss": unavailable_memory("The Rust library does not run inside a Node.js process.", "No samples were available."),
                "nodeExternal": unavailable_memory("The Rust library has no Node external-memory category.", "No samples were available."),
                "browserJsHeap": unavailable_memory("The Rust library does not run inside a browser JavaScript heap.", "No samples were available."),
                "wasmLinearMemory": unavailable_memory("The Rust library surface does not use WebAssembly linear memory.", "No samples were available."),
                "pythonHeap": unavailable_memory("The Rust library does not run inside a Python allocator.", "No samples were available."),
                "processRss": rss,
                "streamingBuffer": unavailable_memory("The public incremental session exposes lifecycle state but intentionally does not expose retained plaintext buffer size.", "No samples were available."),
            },
        },
        "provenance": provenance("1", &sha256_file(&repo_root().join("assessment/fixtures/workload-profiles.json"))?, &invoked_command()),
    });
    write_json(&result, options.json_out.as_deref())?;
    if let Some(path) = options.markdown_out.as_deref() {
        write_file(path, &markdown_performance(&result))?;
    }
    eprintln!(
        "rust-core performance: {} run(s), median {} ms",
        options.runs, result["performance"]["processing"]["median"]
    );
    Ok(())
}

fn run_self_test() -> Result<(), String> {
    if RANGE_UNIT != "utf8-bytes" {
        return Err("unexpected range unit".to_owned());
    }
    let registry = DetectorRegistry::with_built_in([]).map_err(error_text)?;
    let input = "\u{1F511} API_KEY=ghp_SYNTHETICREVOKED00000000000000000000";
    let result = scan_and_redact(
        input,
        &registry,
        &DefaultPolicy,
        &default_placeholder_formatter,
    )
    .map_err(error_text)?;
    let finding = result
        .findings()
        .first()
        .ok_or_else(|| "unicode known-answer scan produced no finding".to_owned())?;
    if finding.range().start() != "\u{1F511} API_KEY=".len() {
        return Err("unicode known-answer range was not a UTF-8 byte range".to_owned());
    }
    let mut session = IncrementalSanitizer::new(
        IncrementalLimits::new(40_000, 32_896, 8_192, 32_768).map_err(error_text)?,
    )
    .map_err(error_text)?;
    let prefix = "\u{1F511} API_KEY=ghp_SYNTHETIC";
    let suffix = "REVOKED00000000000000000000";
    let first = session.append(prefix).map_err(error_text)?;
    if !first.findings().is_empty() {
        return Err("incremental session emitted an incomplete finding".to_owned());
    }
    let second = session.append(suffix).map_err(error_text)?;
    let final_result = session.finalize().map_err(error_text)?;
    let incremental_findings = second.findings().len() + final_result.findings().len();
    if incremental_findings != 1 {
        return Err("incremental known-answer run did not emit one finding".to_owned());
    }
    let mut failed = IncrementalSanitizer::new(
        IncrementalLimits::new(16, IncrementalLimits::minimum_buffered_bytes(8, 8), 8, 8)
            .map_err(error_text)?,
    )
    .map_err(error_text)?;
    if failed
        .append("this input is longer than the declared limit")
        .is_ok()
    {
        return Err("limit failure self-test unexpectedly succeeded".to_owned());
    }
    if failed.finalize().is_ok() {
        return Err("failed session finalized after a limit failure".to_owned());
    }
    eprintln!("rust-core assessment adapter self-test passed");
    Ok(())
}

fn score_fixture(
    fixture: &Fixture,
    actual: &[ActualFinding],
    totals: &mut AccuracyTotals,
    mismatches: &mut Vec<Value>,
) {
    let mut expected_by_key = HashMap::new();
    for expected in &fixture.expected {
        expected_by_key.insert(
            match_key(
                &expected.detector,
                &expected.type_name,
                expected.start,
                expected.end,
            ),
            expected,
        );
    }
    let mut consumed = HashSet::new();
    for finding in actual {
        let key = match_key(
            &finding.detector,
            &finding.type_name,
            finding.start,
            finding.end,
        );
        match expected_by_key.get(&key) {
            Some(expected) if consumed.insert(key) => {
                totals.true_positives += 1;
                if finding.action != expected.policy {
                    totals.policy_mismatches += 1;
                    mismatches.push(json!({
                        "fixtureId": fixture.id,
                        "kind": "policy-mismatch",
                        "detector": expected.detector,
                        "type": expected.type_name,
                        "expectedRange": [expected.start, expected.end],
                        "actualRange": [finding.start, finding.end],
                        "expectedPolicy": expected.policy,
                        "actualPolicy": finding.action,
                    }));
                }
            }
            _ => {
                totals.false_positives += 1;
                mismatches.push(json!({
                    "fixtureId": fixture.id,
                    "kind": "extra",
                    "detector": finding.detector,
                    "type": finding.type_name,
                    "actualRange": [finding.start, finding.end],
                }));
            }
        }
    }
    for (key, expected) in expected_by_key {
        if consumed.contains(&key) {
            continue;
        }
        totals.false_negatives += 1;
        mismatches.push(json!({
            "fixtureId": fixture.id,
            "kind": "missing",
            "detector": expected.detector,
            "type": expected.type_name,
            "expectedRange": [expected.start, expected.end],
            "expectedPolicy": expected.policy,
        }));
    }
}

fn match_key(detector: &str, type_name: &str, start: usize, end: usize) -> String {
    format!("{detector} {type_name} {start} {end}")
}

fn actual_finding(finding: &Finding) -> ActualFinding {
    ActualFinding {
        detector: finding.detector().to_owned(),
        type_name: finding.type_name().to_owned(),
        start: finding.range().start(),
        end: finding.range().end(),
        action: action_name(finding.action()).to_owned(),
    }
}

fn action_name(action: Action) -> &'static str {
    match action {
        Action::Block => "block",
        Action::Redact => "redact",
        Action::Warn => "warn",
        Action::Allow => "allow",
    }
}

fn measure_one(profile: &Profile) -> Result<Sample, String> {
    let input = generate_workload_input(profile);
    let chunks = partition_input(&input, &profile.chunk_profile)?;
    let input_bytes = input.len();
    let initialization_start = Instant::now();
    let registry = DetectorRegistry::with_built_in([]).map_err(error_text)?;
    let initialization_ms = initialization_start.elapsed().as_secs_f64() * 1000.0;
    process_input(&registry, &input, &chunks, &profile.chunk_profile)?;
    let baseline = current_rss_bytes()?;
    let processing_start = Instant::now();
    let sink = process_input(&registry, &input, &chunks, &profile.chunk_profile)?;
    let processing_ms = processing_start.elapsed().as_secs_f64() * 1000.0;
    let after = current_rss_bytes()?;
    if sink == 0 || processing_ms <= 0.0 {
        return Err("processing did not complete".to_owned());
    }
    Ok(Sample {
        initialization_ms,
        processing_ms,
        throughput_bytes_per_second: input_bytes as f64 / (processing_ms / 1000.0),
        rss: baseline
            .zip(after)
            .map(|(baseline_bytes, after_bytes)| MemorySample {
                baseline_bytes,
                maximum_observed_bytes: baseline_bytes.max(after_bytes),
            }),
    })
}

fn process_input(
    registry: &DetectorRegistry,
    input: &str,
    chunks: &[String],
    chunk_profile: &str,
) -> Result<usize, String> {
    if chunk_profile == "whole" {
        let result = scan_and_redact(
            input,
            registry,
            &DefaultPolicy,
            &default_placeholder_formatter,
        )
        .map_err(error_text)?;
        return Ok(result.text().len() + result.findings().len());
    }
    let mut session = IncrementalSanitizer::new(
        IncrementalLimits::new(input.len() + 1, 32_896, 8_192, 32_768).map_err(error_text)?,
    )
    .map_err(error_text)?;
    let mut sink = 0;
    for chunk in chunks {
        let result = session.append(chunk).map_err(error_text)?;
        sink += result.text().len() + result.findings().len();
    }
    let final_result = session.finalize().map_err(error_text)?;
    Ok(sink + final_result.text().len() + final_result.findings().len())
}

fn generate_workload_input(profile: &Profile) -> String {
    let filler = match (profile.category.as_str(), profile.unicode_mix) {
        ("logs", false) => {
            "2026-09-12T00:00:00Z INFO fixture request completed status=200 latency_ms=12\n"
        }
        ("code", false) => {
            "function computeFixtureTotal(values) {\n  return values.reduce((a, b) => a + b, 0);\n}\n"
        }
        ("chat", false) => "Hey, did you get a chance to look at the fixture PR yet? No rush.\n",
        ("negative-text", false) => {
            "The quick brown fox jumps over the lazy dog near the old fixture barn.\n"
        }
        ("logs", true) => "2026-09-12T00:00:00Z ｲﾝﾌｫ 요청 완료 상태=200 café=\u{1F511}\n",
        ("code", true) => "// función de prueba: サンプル \u{1F600}\n",
        ("chat", true) => "¡Hola! ¿Cómo estás? 你好吗？ \u{1F600}\n",
        ("negative-text", true) => "Café naïve résumé \u{1F98A} über den alten Zaun.\n",
        _ => "",
    };
    let filler_bytes = filler.len();
    let secret_bytes = SYNTHETIC_SECRET_LINE.len();
    let lines_per_kib = 1024.0 / filler_bytes as f64;
    let secret_every_n_lines = if profile.target_density_per_kib > 0 {
        (lines_per_kib / profile.target_density_per_kib as f64)
            .round()
            .max(1.0) as usize
    } else {
        usize::MAX
    };
    let mut input = String::new();
    let mut bytes = 0;
    let mut line = 0usize;
    while bytes < profile.target_input_bytes {
        line += 1;
        let use_secret =
            secret_every_n_lines != usize::MAX && line.is_multiple_of(secret_every_n_lines);
        let next = if use_secret {
            SYNTHETIC_SECRET_LINE
        } else {
            filler
        };
        input.push_str(next);
        bytes += if use_secret {
            secret_bytes
        } else {
            filler_bytes
        };
    }
    input
}

fn partition_input(input: &str, chunk_profile: &str) -> Result<Vec<String>, String> {
    if chunk_profile == "whole" {
        return Ok(vec![input.to_owned()]);
    }
    if chunk_profile == "utf16-boundary" {
        return Ok(input.chars().map(|scalar| scalar.to_string()).collect());
    }
    let maximum_bytes = chunk_profile
        .strip_prefix("fixed-")
        .ok_or_else(|| format!("{chunk_profile}: unsupported chunk profile"))?
        .parse::<usize>()
        .map_err(|_| format!("{chunk_profile}: unsupported chunk profile"))?;
    let mut chunks = Vec::new();
    let mut chunk = String::new();
    let mut bytes = 0;
    for scalar in input.chars() {
        let scalar_bytes = scalar.len_utf8();
        if !chunk.is_empty() && bytes + scalar_bytes > maximum_bytes {
            chunks.push(std::mem::take(&mut chunk));
            bytes = 0;
        }
        chunk.push(scalar);
        bytes += scalar_bytes;
    }
    if !chunk.is_empty() {
        chunks.push(chunk);
    }
    Ok(chunks)
}

fn current_rss_bytes() -> Result<Option<u64>, String> {
    #[cfg(target_os = "macos")]
    {
        let output = Command::new("ps")
            .args(["-o", "rss=", "-p", &std::process::id().to_string()])
            .output()
            .map_err(|error| format!("failed to sample RSS: {error}"))?;
        let text = String::from_utf8(output.stdout)
            .map_err(|_| "failed to decode RSS sample".to_owned())?;
        let kib = text
            .trim()
            .parse::<u64>()
            .map_err(|_| "failed to parse RSS sample".to_owned())?;
        Ok(Some(kib * 1024))
    }
    #[cfg(target_os = "linux")]
    {
        let status = fs::read_to_string("/proc/self/status")
            .map_err(|error| format!("failed to sample RSS: {error}"))?;
        let mut fields = status
            .lines()
            .find(|line| line.starts_with("VmRSS:"))
            .ok_or_else(|| "failed to parse RSS sample".to_owned())?
            .split_whitespace();
        let _label = fields.next();
        let kib = fields
            .next()
            .ok_or_else(|| "failed to parse RSS sample".to_owned())?
            .parse::<u64>()
            .map_err(|_| "failed to parse RSS sample".to_owned())?;
        if fields.next() != Some("kB") {
            return Err("failed to parse RSS sample".to_owned());
        }
        Ok(Some(kib * 1024))
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        Ok(None)
    }
}

fn distribution(samples: &[f64]) -> Value {
    distribution_with_unit(samples, "milliseconds")
}

fn distribution_with_unit(samples: &[f64], unit: &str) -> Value {
    let mut sorted = samples.to_vec();
    sorted.sort_by(f64::total_cmp);
    let mean = samples.iter().sum::<f64>() / samples.len() as f64;
    let variance = samples
        .iter()
        .map(|sample| (*sample - mean).powi(2))
        .sum::<f64>()
        / samples.len() as f64;
    let middle = sorted.len() / 2;
    let median = if sorted.len().is_multiple_of(2) {
        sorted[middle - 1].midpoint(sorted[middle])
    } else {
        sorted[middle]
    };
    json!({
        "unit": unit,
        "samples": samples,
        "minimum": sorted[0],
        "median": median,
        "p95": sorted[((0.95 * sorted.len() as f64).ceil() as usize).saturating_sub(1)],
        "maximum": sorted[sorted.len() - 1],
        "mean": mean,
        "standardDeviation": variance.sqrt(),
    })
}

fn available_memory(samples: Vec<MemorySample>, sampling_limit: &str) -> Value {
    json!({
        "unit": "bytes",
        "samples": samples.into_iter().map(|sample| json!({
            "baselineBytes": sample.baseline_bytes,
            "maximumObservedBytes": sample.maximum_observed_bytes,
        })).collect::<Vec<_>>(),
        "samplingLimit": sampling_limit,
    })
}

fn unavailable_memory(reason: &str, sampling_limit: &str) -> Value {
    json!({
        "unit": "bytes",
        "samples": [],
        "unavailableReason": reason,
        "samplingLimit": sampling_limit,
    })
}

fn provenance(corpus_version: &str, corpus_hash: &str, command: &str) -> Value {
    json!({
        "commit": git_commit(),
        "artifactIdentity": format!("redact-secret@{VERSION}"),
        "corpusVersion": corpus_version,
        "corpusHash": corpus_hash,
        "os": host_os(),
        "cpu": env::consts::ARCH,
        "runtime": format!("rustc-{}", rustc_version()),
        "command": command,
        "buildProfile": if cfg!(debug_assertions) { "debug" } else { "release" },
    })
}

fn invoked_command() -> String {
    // Record the actual executable and argv, including argument boundaries.
    serde_json::to_string(&env::args().collect::<Vec<_>>()).unwrap_or_default()
}

fn markdown_accuracy(result: &Value, mismatches: &[Value]) -> String {
    let accuracy = &result["accuracy"];
    let mut lines = vec![
        format!(
            "# Accuracy assessment — {}",
            result["surface"].as_str().unwrap_or("rust-core")
        ),
        String::new(),
        format!(
            "- Profile: `{}`",
            result["profileId"].as_str().unwrap_or("accuracy-corpus")
        ),
        format!(
            "- Schema version: `{}`",
            result["schemaVersion"]
                .as_str()
                .unwrap_or(RESULT_SCHEMA_VERSION)
        ),
        format!(
            "- Artifact: `{}`",
            result["provenance"]["artifactIdentity"]
                .as_str()
                .unwrap_or("redact-secret")
        ),
        format!(
            "- Commit: `{}`",
            result["provenance"]["commit"].as_str().unwrap_or("unknown")
        ),
        format!(
            "- Corpus: `{}` (`{}`)",
            result["provenance"]["corpusVersion"]
                .as_str()
                .unwrap_or("unknown"),
            result["provenance"]["corpusHash"]
                .as_str()
                .unwrap_or("unknown")
        ),
        format!(
            "- Host: {} / {} / {}",
            result["provenance"]["os"].as_str().unwrap_or("unknown"),
            result["provenance"]["cpu"].as_str().unwrap_or("unknown"),
            result["provenance"]["runtime"]
                .as_str()
                .unwrap_or("unknown")
        ),
        format!(
            "- Command: `{}`",
            result["provenance"]["command"]
                .as_str()
                .unwrap_or("unknown")
        ),
        String::new(),
        "## Accuracy metrics".to_owned(),
        String::new(),
        "| Metric | Count |".to_owned(),
        "| --- | --- |".to_owned(),
        format!("| True positives | {} |", accuracy["truePositives"]),
        format!("| False positives | {} |", accuracy["falsePositives"]),
        format!("| False negatives | {} |", accuracy["falseNegatives"]),
        format!("| Policy mismatches | {} |", accuracy["policyMismatches"]),
        String::new(),
        "## Mismatches".to_owned(),
        String::new(),
    ];
    if mismatches.is_empty() {
        lines.push("None — every fixture matched its reviewed expectation.".to_owned());
    } else {
        lines.push("| Fixture | Kind | Detector | Type | Range | Policy |".to_owned());
        lines.push("| --- | --- | --- | --- | --- | --- |".to_owned());
        for mismatch in mismatches {
            lines.push(format!(
                "| {} | {} | {} | {} | {} | {} |",
                mismatch["fixtureId"].as_str().unwrap_or("unknown"),
                mismatch["kind"].as_str().unwrap_or("unknown"),
                mismatch["detector"].as_str().unwrap_or("unknown"),
                mismatch["type"].as_str().unwrap_or("unknown"),
                mismatch_range(mismatch),
                mismatch_policy(mismatch),
            ));
        }
    }
    format!("{}\n", lines.join("\n"))
}

fn markdown_performance(result: &Value) -> String {
    let performance = &result["performance"];
    let mut lines = vec![
        format!("# Performance assessment — {}", result["surface"].as_str().unwrap_or("rust-core")),
        String::new(),
        format!("- Profile: `{}`", result["profileId"].as_str().unwrap_or(DEFAULT_PROFILE)),
        format!("- Schema version: `{}`", result["schemaVersion"].as_str().unwrap_or(RESULT_SCHEMA_VERSION)),
        format!("- Artifact: `{}`", result["provenance"]["artifactIdentity"].as_str().unwrap_or("redact-secret")),
        format!("- Commit: `{}`", result["provenance"]["commit"].as_str().unwrap_or("unknown")),
        format!(
            "- Host: {} / {} / {}",
            result["provenance"]["os"].as_str().unwrap_or("unknown"),
            result["provenance"]["cpu"].as_str().unwrap_or("unknown"),
            result["provenance"]["runtime"].as_str().unwrap_or("unknown")
        ),
        format!("- Command: `{}`", result["provenance"]["command"].as_str().unwrap_or("unknown")),
        String::new(),
        "## Timing and throughput distributions".to_owned(),
        String::new(),
        "| Measurement | Unit | Runs | Min | Median | p95 | Max | Mean | Population std dev |".to_owned(),
        "| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |".to_owned(),
        distribution_row("Initialization", &performance["initialization"]),
        distribution_row("Steady-state processing", &performance["processing"]),
        distribution_row("Throughput", &performance["throughput"]),
        String::new(),
        "Raw samples are preserved in the JSON result under each distribution's `samples` field.".to_owned(),
        String::new(),
        "## Memory observations".to_owned(),
        String::new(),
        "Memory categories are reported separately and must not be summed.".to_owned(),
        String::new(),
        "| Category | Samples | Baseline bytes (min) | Maximum observed bytes (max) | Availability / sampling limit |".to_owned(),
        "| --- | ---: | ---: | ---: | --- |".to_owned(),
    ];
    if let Some(memory) = performance["memory"].as_object() {
        for (name, metric) in memory {
            lines.push(memory_row(name, metric));
        }
    }
    lines.push(String::new());
    lines.push("Observed maxima are sampled observations, not guaranteed true peaks.".to_owned());
    format!("{}\n", lines.join("\n"))
}

fn distribution_row(label: &str, distribution: &Value) -> String {
    let runs = distribution["samples"].as_array().map_or(0, Vec::len);
    format!(
        "| {label} | {} | {runs} | {} | {} | {} | {} | {} | {} |",
        distribution["unit"].as_str().unwrap_or("unknown"),
        distribution["minimum"],
        distribution["median"],
        distribution["p95"],
        distribution["maximum"],
        distribution["mean"],
        distribution["standardDeviation"],
    )
}

fn memory_row(name: &str, metric: &Value) -> String {
    let samples = metric["samples"].as_array().cloned().unwrap_or_default();
    let baselines = samples
        .iter()
        .filter_map(|sample| sample["baselineBytes"].as_u64())
        .collect::<Vec<_>>();
    let maxima = samples
        .iter()
        .filter_map(|sample| sample["maximumObservedBytes"].as_u64())
        .collect::<Vec<_>>();
    let baseline = baselines
        .iter()
        .min()
        .map_or("—".to_owned(), u64::to_string);
    let maximum = maxima.iter().max().map_or("—".to_owned(), u64::to_string);
    let availability = metric["unavailableReason"].as_str().unwrap_or("available");
    let sampling = metric["samplingLimit"].as_str().unwrap_or("unknown");
    format!(
        "| {name} | {} | {baseline} | {maximum} | {availability}; {sampling} |",
        samples.len()
    )
}

fn mismatch_range(mismatch: &Value) -> String {
    if let Some(range) = mismatch["expectedRange"].as_array() {
        return format!("[{}, {})", range[0], range[1]);
    }
    if let Some(range) = mismatch["actualRange"].as_array() {
        return format!("[{}, {})", range[0], range[1]);
    }
    "—".to_owned()
}

fn mismatch_policy(mismatch: &Value) -> String {
    match mismatch["kind"].as_str() {
        Some("policy-mismatch") => format!(
            "expected `{}`, got `{}`",
            mismatch["expectedPolicy"].as_str().unwrap_or("unknown"),
            mismatch["actualPolicy"].as_str().unwrap_or("unknown")
        ),
        Some("missing") => format!(
            "expected `{}`",
            mismatch["expectedPolicy"].as_str().unwrap_or("unknown")
        ),
        _ => "—".to_owned(),
    }
}

fn fixtures(corpus: &Value) -> Result<Vec<Fixture>, String> {
    array_field(corpus, "fixtures")?
        .iter()
        .map(|fixture| {
            let expected = array_field(fixture, "expected")?
                .iter()
                .map(|expected| {
                    Ok(Expectation {
                        detector: string_field(expected, "detector")?.to_owned(),
                        type_name: string_field(expected, "type")?.to_owned(),
                        start: usize_field(expected, "start")?,
                        end: usize_field(expected, "end")?,
                        policy: string_field(expected, "policyOutcome")?.to_owned(),
                    })
                })
                .collect::<Result<Vec<_>, String>>()?;
            Ok(Fixture {
                id: string_field(fixture, "id")?.to_owned(),
                input: string_field(fixture, "input")?.to_owned(),
                expected,
            })
        })
        .collect()
}

fn profile_from_value(value: &Value) -> Result<Profile, String> {
    Ok(Profile {
        id: string_field(value, "id")?.to_owned(),
        purpose: string_field(value, "purpose")?.to_owned(),
        category: string_field(value, "category")?.to_owned(),
        target_input_bytes: usize_field(value, "targetInputBytes")?,
        target_density_per_kib: value["targetDensityPerKiB"]
            .as_u64()
            .ok_or_else(|| "targetDensityPerKiB: expected number".to_owned())?,
        chunk_profile: string_field(value, "chunkProfile")?.to_owned(),
        unicode_mix: value["unicodeMix"]
            .as_bool()
            .ok_or_else(|| "unicodeMix: expected boolean".to_owned())?,
        generator_algorithm: string_field(value, "generatorAlgorithm")?.to_owned(),
    })
}

fn read_json(path: &Path) -> Result<Value, String> {
    serde_json::from_str(
        &fs::read_to_string(path).map_err(|error| format!("{}: {error}", path.display()))?,
    )
    .map_err(|error| format!("{}: {error}", path.display()))
}

fn string_field<'a>(value: &'a Value, key: &str) -> Result<&'a str, String> {
    value[key]
        .as_str()
        .ok_or_else(|| format!("{key}: expected string"))
}

fn usize_field(value: &Value, key: &str) -> Result<usize, String> {
    value[key]
        .as_u64()
        .and_then(|number| usize::try_from(number).ok())
        .ok_or_else(|| format!("{key}: expected safe integer"))
}

fn array_field<'a>(value: &'a Value, key: &str) -> Result<&'a Vec<Value>, String> {
    value[key]
        .as_array()
        .ok_or_else(|| format!("{key}: expected array"))
}

fn string_or_number(value: &Value) -> Result<String, String> {
    if let Some(text) = value.as_str() {
        return Ok(text.to_owned());
    }
    value
        .as_u64()
        .map(|number| number.to_string())
        .ok_or_else(|| "corpusVersion: expected string or safe integer".to_owned())
}

fn write_json(result: &Value, path: Option<&Path>) -> Result<(), String> {
    let text = format_json(result)?;
    if let Some(path) = path {
        write_file(path, &text)
    } else {
        println!("{text}");
        Ok(())
    }
}

fn write_file(path: &Path, text: &str) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|error| format!("{}: {error}", parent.display()))?;
    }
    fs::write(path, text).map_err(|error| format!("{}: {error}", path.display()))
}

fn format_json(value: &Value) -> Result<String, String> {
    serde_json::to_string_pretty(value)
        .map(|text| format!("{text}\n"))
        .map_err(|error| error.to_string())
}

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn sha256_file(path: &Path) -> Result<String, String> {
    let output = Command::new("shasum")
        .args(["-a", "256"])
        .arg(path)
        .output()
        .map_err(|error| format!("failed to hash {}: {error}", path.display()))?;
    if !output.status.success() {
        return Err(format!("failed to hash {}", path.display()));
    }
    let text =
        String::from_utf8(output.stdout).map_err(|_| "hash output was not UTF-8".to_owned())?;
    text.split_whitespace()
        .next()
        .map(str::to_owned)
        .ok_or_else(|| "hash output was empty".to_owned())
}

fn git_commit() -> String {
    command_text("git", &["rev-parse", "HEAD"]).unwrap_or_else(|_| "0".repeat(40))
}

fn rustc_version() -> String {
    command_text("rustc", &["--version"]).map_or_else(
        |_| "unknown".to_owned(),
        |text| text.trim_start_matches("rustc ").to_owned(),
    )
}

fn host_os() -> String {
    format!(
        "{}-{}",
        env::consts::OS,
        command_text("uname", &["-r"]).unwrap_or_else(|_| "unknown".to_owned())
    )
}

fn command_text(program: &str, args: &[&str]) -> Result<String, String> {
    let output = Command::new(program)
        .args(args)
        .current_dir(repo_root())
        .output()
        .map_err(|error| format!("{program}: {error}"))?;
    if !output.status.success() {
        return Err(format!("{program}: command failed"));
    }
    String::from_utf8(output.stdout)
        .map(|text| text.trim().to_owned())
        .map_err(|_| format!("{program}: output was not UTF-8"))
}

fn error_text(error: impl std::fmt::Display) -> String {
    error.to_string()
}
