//! Scan-cost harness with per-detector attribution (issue #981).
//!
//! `cargo bench -p redact-secret --bench scan_cost -- [options] [filter]`
//!
//! A plain `harness = false` binary: no benchmarking dependency, only the
//! public `redact_secret::` API, and `std::time::Instant` here rather than in
//! `src/`, which may not name `std::time`. It is excluded from the published
//! package by the manifest's `include` list.
//!
//! For each workload it times the whole-input `scan_and_redact` and an
//! `IncrementalSanitizer` session fed in fixed-size chunks, then repeats the
//! pipeline's `collect_candidates` loop by hand, timing every registered
//! detector's `detect()` over the whole input and once per line (the #883 /
//! #950 method). Every figure is the median of `--runs` timed repetitions
//! after one untimed warm-up.
//!
//! Attribution runs detectors on the raw input. The pipeline scans a
//! normalized copy (invisible code points removed), and that type is private,
//! so on the `unicode-invisible` workload the per-detector figures describe
//! the raw text, not the exact bytes the pipeline hands each detector. Per-line
//! attribution approximates the incremental unit split, which is private too.
//!
//! Options:
//!   `--runs N`        timed repetitions per figure (default 21)
//!   `--filter S`      run only workloads whose name contains `S` (a bare
//!                     positional argument means the same)
//!   `--json`          print one JSON document on stdout instead of tables
//!   `--no-detectors`  skip per-detector attribution
//!   `--top K`         detector rows per table (default 12; JSON lists all)
//!   `--list`          print the workload names and exit
//!
//! The session constructor (a registry build) is outside the timed
//! incremental closure; `registry-build` times the constructors on their own
//! (#1059). Each path also reports throughput in MB/s (10^6 bytes/s).

#![allow(
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::struct_field_names,
    clippy::too_many_lines,
    clippy::type_complexity
)]

use std::fmt::Write as _;
use std::hint::black_box;
use std::time::Instant;

use redact_secret::{
    DEFAULT_MAX_INPUT_BYTES, DefaultPolicy, DetectorContext, DetectorRegistry, IncrementalLimits,
    IncrementalSanitizer, PiiSelection, default_placeholder_formatter, load_ruleset,
    scan_and_redact,
};
use serde_json::{Value, json};

#[path = "support/workloads.rs"]
mod workloads;

use workloads::{
    CLI_MAX_MULTILINE_BYTES, CLI_MAX_TOKEN_BYTES, RegistryKind, ScanPath, WORKLOADS, Workload,
    partition,
};

/// The pseudo-workload name that selects the registry-construction timings.
const REGISTRY_BUILD: &str = "registry-build";
/// Constructions per timed sample, so one sample is well above timer
/// resolution.
const REGISTRY_BUILDS_PER_SAMPLE: usize = 50;
/// A synthetic eight-detector ruleset: the `ruleset-value-grammar` case of
/// `conformance/fixtures/ruleset-reference.json`.
const SYNTHETIC_RULESET: &str = "ruleset-revision: 1\ndetector: acme-alnum-token\nspecificity: contextual\nprefix: \"ACME_AN_\"\nalphabet: alnum\nrun: at-least 20\nvalidator: none\ndetector: acme-alnum-dash-token\nspecificity: contextual\nprefix: \"ACME_AD_\"\nalphabet: alnum-dash\nrun: at-least 20\nvalidator: none\ndetector: acme-alnum-dash-dot-token\nspecificity: entropy\nprefix: \"ACME_ADD_\"\nalphabet: alnum-dash-dot\nrun: at-least 20\nvalidator: none\ndetector: acme-upper-alnum-token\nspecificity: contextual\nprefix: \"ACME_UA_\"\nalphabet: upper-alnum\nrun: exact 20\nvalidator: none\ndetector: acme-digit-token\nspecificity: entropy\nprefix: \"ACME_DG_\"\nalphabet: digit\nrun: exact 16\nvalidator: none\ndetector: acme-lower-hex-token\nspecificity: contextual\nprefix: \"ACME_LH_\"\nalphabet: lower-hex\nrun: exact 32\nvalidator: none\ndetector: acme-base64-token\nspecificity: entropy\nprefix: \"ACME_B64_\"\nalphabet: base64-body\nrun: at-least 20\nvalidator: none\ndetector: acme-checksum-token\nspecificity: contextual\nprefix: \"ACME_CK_\"\nalphabet: alnum\nrun: at-least 8\nvalidator: trailing-lower-hex\n";

/// The registries a workload can scan with, built once.
struct Registries {
    built_in: DetectorRegistry,
    pii: DetectorRegistry,
    selection: PiiSelection,
}

impl Registries {
    fn get(&self, kind: RegistryKind) -> &DetectorRegistry {
        match kind {
            RegistryKind::BuiltIn => &self.built_in,
            RegistryKind::BuiltInAndPii => &self.pii,
        }
    }
}

struct Options {
    runs: usize,
    filter: Option<String>,
    json: bool,
    detectors: bool,
    top: usize,
    list: bool,
}

#[derive(Clone, Copy)]
struct Stats {
    median_ms: f64,
    min_ms: f64,
    max_ms: f64,
}

impl Stats {
    fn to_json(self) -> Value {
        json!({
            "median_ms": round4(self.median_ms),
            "min_ms": round4(self.min_ms),
            "max_ms": round4(self.max_ms),
        })
    }
}

struct DetectorCost {
    id: String,
    candidates: usize,
    whole: Stats,
    per_line: Option<Stats>,
}

fn main() {
    if let Err(message) = run() {
        eprintln!("scan_cost: {message}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let options = parse_arguments(std::env::args().skip(1))?;
    if options.list {
        for workload in WORKLOADS {
            println!("{:<32} {}", workload.name, workload.description);
        }
        println!(
            "{REGISTRY_BUILD:<32} DetectorRegistry construction: built-in, built-in + PII, built-in + ruleset (#1059)"
        );
        return Ok(());
    }
    let selected: Vec<&Workload> = WORKLOADS
        .iter()
        .filter(|workload| {
            options
                .filter
                .as_deref()
                .is_none_or(|filter| workload.name.contains(filter))
        })
        .collect();
    let registry_build = options
        .filter
        .as_deref()
        .is_none_or(|filter| REGISTRY_BUILD.contains(filter));
    if selected.is_empty() && !registry_build {
        return Err("no workload matches the filter; see --list".to_owned());
    }
    let selection = PiiSelection::parse(&["pii"]).map_err(|error| error.to_string())?;
    let registries = Registries {
        built_in: DetectorRegistry::with_built_in([]).map_err(|error| error.to_string())?,
        pii: DetectorRegistry::with_built_in_and_pii(&selection)
            .map_err(|error| error.to_string())?,
        selection,
    };
    let registry = &registries.built_in;
    let mut results = Vec::new();
    for workload in selected {
        eprintln!("scan_cost: {} ...", workload.name);
        let result = measure_workload(workload, &registries, &options)?;
        if !options.json {
            print!("{}", result.1);
        }
        results.push(result.0);
    }
    let mut registry_json = Value::Null;
    if registry_build {
        eprintln!("scan_cost: {REGISTRY_BUILD} ...");
        let (value, table) = measure_registry_build(&registries.selection, options.runs)?;
        if !options.json {
            print!("{table}");
        }
        registry_json = value;
    }
    if options.json {
        let document = json!({
            "harness": "scan_cost",
            "issue": 981,
            "runs": options.runs,
            "statistic": "median of runs after one untimed warm-up",
            "target": format!("{}-{}", std::env::consts::ARCH, std::env::consts::OS),
            "detector_count": registry.len(),
            "workloads": results,
            "registry_build": registry_json,
        });
        let text = serde_json::to_string_pretty(&document).map_err(|error| error.to_string())?;
        println!("{text}");
    }
    Ok(())
}

fn parse_arguments(args: impl Iterator<Item = String>) -> Result<Options, String> {
    let mut options = Options {
        runs: 21,
        filter: None,
        json: false,
        detectors: true,
        top: 12,
        list: false,
    };
    let mut args = args.peekable();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            // `cargo bench` passes `--bench` to every bench target.
            "--bench" => {}
            "--json" => options.json = true,
            "--no-detectors" => options.detectors = false,
            "--list" => options.list = true,
            "--runs" => options.runs = number(args.next(), "--runs")?,
            "--top" => options.top = number(args.next(), "--top")?,
            "--filter" => {
                options.filter = Some(args.next().ok_or("--filter needs a value")?);
            }
            other if other.starts_with('-') => return Err(format!("unknown option {other}")),
            other => options.filter = Some(other.to_owned()),
        }
    }
    if options.runs == 0 {
        return Err("--runs must be at least 1".to_owned());
    }
    Ok(options)
}

fn number(value: Option<String>, flag: &str) -> Result<usize, String> {
    value
        .and_then(|value| value.parse().ok())
        .ok_or_else(|| format!("{flag} needs a non-negative integer"))
}

fn measure_workload(
    workload: &Workload,
    registries: &Registries,
    options: &Options,
) -> Result<(Value, String), String> {
    let registry = registries.get(workload.registry);
    let input = (workload.generate)();
    let lines: Vec<&str> = input.split_inclusive('\n').collect();
    let findings = scan_whole(&input, registry)?.1;
    let mut table = String::new();
    let _ = writeln!(
        table,
        "\n## {} — {} bytes, {} lines, {} findings, {} runs\n{}",
        workload.name,
        input.len(),
        lines.len(),
        findings,
        options.runs,
        workload.description
    );

    let mut paths = serde_json::Map::new();
    for &path in workload.paths {
        let stats = match path {
            ScanPath::Whole => time(options.runs, || scan_whole(&input, registry).map(|r| r.0))?,
            ScanPath::Incremental(chunk) => {
                let chunks = partition(&input, chunk);
                time_with_setup(
                    options.runs,
                    || new_session(&input, workload.registry, registries),
                    |session| scan_incremental(session, &chunks),
                )?
            }
        };
        let mb_per_s = mb_per_s(input.len(), stats.median_ms);
        let _ = writeln!(
            table,
            "  {:<28} median {:>10.3} ms  (min {:.3}, max {:.3})  {:>9.2} MB/s",
            path.label(),
            stats.median_ms,
            stats.min_ms,
            stats.max_ms,
            mb_per_s
        );
        let mut value = stats.to_json();
        value["mb_per_s"] = json!(round4(mb_per_s));
        paths.insert(path.label(), value);
    }

    let mut detectors_json = Value::Null;
    let mut sums = Value::Null;
    if options.detectors {
        let costs = attribute(&input, &lines, registry, options.runs)?;
        let whole_sum: f64 = costs.iter().map(|cost| cost.whole.median_ms).sum();
        let line_sum: Option<f64> = costs
            .iter()
            .map(|cost| cost.per_line.map(|stats| stats.median_ms))
            .sum();
        let _ = writeln!(
            table,
            "  sum of detector medians: whole {whole_sum:.3} ms, per line {}",
            line_sum.map_or_else(|| "n/a (one line)".to_owned(), |sum| format!("{sum:.3} ms"))
        );
        let _ = writeln!(
            table,
            "  {:<44} {:>11} {:>12} {:>10}",
            "detector (top by whole)", "whole ms", "per-line ms", "candidates"
        );
        for cost in costs.iter().take(options.top) {
            let _ = writeln!(
                table,
                "  {:<44} {:>11.4} {:>12} {:>10}",
                cost.id,
                cost.whole.median_ms,
                cost.per_line.map_or_else(
                    || "n/a".to_owned(),
                    |stats| format!("{:.4}", stats.median_ms)
                ),
                cost.candidates
            );
        }
        sums = json!({
            "whole_ms": round4(whole_sum),
            "per_line_ms": line_sum.map(round4),
        });
        detectors_json = Value::Array(
            costs
                .iter()
                .map(|cost| {
                    json!({
                        "id": cost.id,
                        "candidates_whole": cost.candidates,
                        "whole": cost.whole.to_json(),
                        "per_line": cost.per_line.map(Stats::to_json),
                    })
                })
                .collect(),
        );
    }

    let value = json!({
        "name": workload.name,
        "description": workload.description,
        "bytes": input.len(),
        "lines": lines.len(),
        "registry": match workload.registry {
            RegistryKind::BuiltIn => "built-in",
            RegistryKind::BuiltInAndPii => "built-in+pii",
        },
        "findings_whole": findings,
        "paths": paths,
        "detector_sum_of_medians": sums,
        "detectors": detectors_json,
    });
    Ok((value, table))
}

/// Per-detector cost, sorted by whole-input median, most expensive first.
fn attribute(
    input: &str,
    lines: &[&str],
    registry: &DetectorRegistry,
    runs: usize,
) -> Result<Vec<DetectorCost>, String> {
    let whole_context = DetectorContext::new(input.len());
    let mut costs = Vec::with_capacity(registry.len());
    for registered in registry.detectors() {
        let detector = registered.detector();
        let detect = |text: &str, context: &DetectorContext| {
            detector
                .detect(text, context)
                .map(|candidates| black_box(candidates).len())
                .map_err(|_| format!("{}: detector failure", registered.id()))
        };
        let candidates = detect(input, &whole_context)?;
        let whole = time(runs, || detect(input, &whole_context))?;
        let per_line = if lines.len() > 1 {
            Some(time(runs, || {
                let mut sink = 0;
                for line in lines {
                    sink += detect(line, &DetectorContext::new(line.len()))?;
                }
                Ok(sink)
            })?)
        } else {
            None
        };
        costs.push(DetectorCost {
            id: registered.id().to_owned(),
            candidates,
            whole,
            per_line,
        });
    }
    costs.sort_by(|a, b| b.whole.median_ms.total_cmp(&a.whole.median_ms));
    Ok(costs)
}

/// Returns (a sink value, the finding count).
fn scan_whole(input: &str, registry: &DetectorRegistry) -> Result<(usize, usize), String> {
    let result = scan_and_redact(
        input,
        registry,
        &DefaultPolicy,
        &default_placeholder_formatter,
    )
    .map_err(|error| error.to_string())?;
    let result = black_box(result);
    Ok((
        result.text().len() + result.findings().len(),
        result.findings().len(),
    ))
}

/// A fresh session for one incremental run, built outside the timed part.
fn new_session(
    input: &str,
    kind: RegistryKind,
    registries: &Registries,
) -> Result<IncrementalSanitizer, String> {
    let limits = IncrementalLimits::new(
        DEFAULT_MAX_INPUT_BYTES.max(input.len()),
        IncrementalLimits::minimum_buffered_bytes(CLI_MAX_TOKEN_BYTES, CLI_MAX_MULTILINE_BYTES),
        CLI_MAX_TOKEN_BYTES,
        CLI_MAX_MULTILINE_BYTES,
    )
    .map_err(|error| error.to_string())?;
    match kind {
        RegistryKind::BuiltIn => IncrementalSanitizer::new(limits),
        RegistryKind::BuiltInAndPii => {
            IncrementalSanitizer::with_built_in_and_pii(limits, &registries.selection)
        }
    }
    .map_err(|error| error.to_string())
}

fn scan_incremental(mut session: IncrementalSanitizer, chunks: &[&str]) -> Result<usize, String> {
    let mut sink = 0;
    for chunk in chunks {
        let result = black_box(session.append(chunk).map_err(|error| error.to_string())?);
        sink += result.text().len() + result.findings().len();
    }
    let result = black_box(session.finalize().map_err(|error| error.to_string())?);
    Ok(sink + result.text().len() + result.findings().len())
}

/// Per-construction cost of each registry constructor a host calls (#1059).
fn measure_registry_build(
    selection: &PiiSelection,
    runs: usize,
) -> Result<(Value, String), String> {
    let ruleset = SYNTHETIC_RULESET.as_bytes();
    let constructors: [(&str, &dyn Fn() -> Result<usize, String>); 3] = [
        ("with_built_in([])", &|| {
            DetectorRegistry::with_built_in([])
                .map(|registry| black_box(registry).len())
                .map_err(|error| error.to_string())
        }),
        ("with_built_in_and_pii([\"pii\"])", &|| {
            DetectorRegistry::with_built_in_and_pii(selection)
                .map(|registry| black_box(registry).len())
                .map_err(|error| error.to_string())
        }),
        ("load_ruleset(8 rules) + with_built_in", &|| {
            let detectors = load_ruleset(ruleset).map_err(|error| error.to_string())?;
            DetectorRegistry::with_built_in(detectors)
                .map(|registry| black_box(registry).len())
                .map_err(|error| error.to_string())
        }),
    ];
    let mut table = String::new();
    let _ = writeln!(
        table,
        "\n## {REGISTRY_BUILD} — {REGISTRY_BUILDS_PER_SAMPLE} constructions per sample, {runs} runs"
    );
    let mut rows = Vec::new();
    for (name, build) in constructors {
        let stats = time(runs, || {
            let mut sink = 0;
            for _ in 0..REGISTRY_BUILDS_PER_SAMPLE {
                sink += build()?;
            }
            Ok(sink)
        })?;
        let per = |ms: f64| ms * 1000.0 / REGISTRY_BUILDS_PER_SAMPLE as f64;
        let _ = writeln!(
            table,
            "  {:<40} median {:>9.2} µs  (min {:.2}, max {:.2}) per construction",
            name,
            per(stats.median_ms),
            per(stats.min_ms),
            per(stats.max_ms)
        );
        rows.push(json!({
            "constructor": name,
            "median_us": round4(per(stats.median_ms)),
            "min_us": round4(per(stats.min_ms)),
            "max_us": round4(per(stats.max_ms)),
        }));
    }
    Ok((Value::Array(rows), table))
}

fn time(
    runs: usize,
    mut operation: impl FnMut() -> Result<usize, String>,
) -> Result<Stats, String> {
    black_box(operation()?);
    let mut samples = Vec::with_capacity(runs);
    for _ in 0..runs {
        let start = Instant::now();
        black_box(operation()?);
        samples.push(start.elapsed().as_secs_f64() * 1000.0);
    }
    samples.sort_by(f64::total_cmp);
    Ok(Stats {
        median_ms: samples[samples.len() / 2],
        min_ms: samples[0],
        max_ms: samples[samples.len() - 1],
    })
}

/// Like [`time`], but `setup` runs before each repetition, outside the
/// timed part.
fn time_with_setup<S>(
    runs: usize,
    mut setup: impl FnMut() -> Result<S, String>,
    mut operation: impl FnMut(S) -> Result<usize, String>,
) -> Result<Stats, String> {
    black_box(operation(setup()?)?);
    let mut samples = Vec::with_capacity(runs);
    for _ in 0..runs {
        let state = setup()?;
        let start = Instant::now();
        black_box(operation(state)?);
        samples.push(start.elapsed().as_secs_f64() * 1000.0);
    }
    samples.sort_by(f64::total_cmp);
    Ok(Stats {
        median_ms: samples[samples.len() / 2],
        min_ms: samples[0],
        max_ms: samples[samples.len() - 1],
    })
}

/// Throughput in 10^6 bytes per second.
fn mb_per_s(bytes: usize, median_ms: f64) -> f64 {
    bytes as f64 / 1_000_000.0 / (median_ms / 1000.0)
}

fn round4(value: f64) -> f64 {
    (value * 10_000.0).round() / 10_000.0
}
