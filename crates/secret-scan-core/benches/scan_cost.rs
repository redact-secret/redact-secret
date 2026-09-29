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

#![allow(
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::struct_field_names
)]

use std::fmt::Write as _;
use std::hint::black_box;
use std::time::Instant;

use redact_secret::{
    DEFAULT_MAX_INPUT_BYTES, DefaultPolicy, DetectorContext, DetectorRegistry, IncrementalLimits,
    IncrementalSanitizer, default_placeholder_formatter, scan_and_redact,
};
use serde_json::{Value, json};

/// The CLI's streaming read size (`secret-scan-cli/src/limits.rs`).
const CLI_CHUNK_BYTES: usize = 64 * 1024;
/// The CLI's construct limits, so the incremental path runs as the CLI does.
const CLI_MAX_TOKEN_BYTES: usize = 1024 * 1024;
const CLI_MAX_MULTILINE_BYTES: usize = 1024 * 1024;

/// `assessment-filler-density-v1` (`examples/assessment_adapter.rs`).
const SYNTHETIC_SECRET_LINE: &str = "token=ghp_ASSESSMENTSYNTHETIC0000000000000000\n";
const LOGS_FILLER: &str =
    "2026-09-12T00:00:00Z INFO fixture request completed status=200 latency_ms=12\n";
const MIXED_FILLERS: [&str; 8] = [
    LOGS_FILLER,
    "function computeFixtureTotal(values) {\n  return values.reduce((a, b) => a + b, 0);\n}\n",
    "Hey, did you get a chance to look at the fixture PR yet? No rush.\n",
    "The quick brown fox jumps over the lazy dog near the old fixture barn.\n",
    "2026-09-12T00:00:00Z ｲﾝﾌｫ 요청 완료 상태=200 café=\u{1F511}\n",
    "// función de prueba: サンプル \u{1F600}\n",
    "¡Hola! ¿Cómo estás? 你好吗？ \u{1F600}\n",
    "Café naïve résumé \u{1F98A} über den alten Zaun.\n",
];

#[derive(Clone, Copy)]
enum ScanPath {
    Whole,
    Incremental(usize),
}

impl ScanPath {
    fn label(self) -> String {
        match self {
            Self::Whole => "whole".to_owned(),
            Self::Incremental(chunk) => format!("incremental-fixed{chunk}"),
        }
    }
}

struct Workload {
    name: &'static str,
    description: &'static str,
    generate: fn() -> String,
    paths: &'static [ScanPath],
}

const WHOLE_AND_CLI: &[ScanPath] = &[ScanPath::Whole, ScanPath::Incremental(CLI_CHUNK_BYTES)];

const WORKLOADS: &[Workload] = &[
    Workload {
        name: "scale-logs-64k",
        description: "assessment-filler-density-v1 logs, 64 KiB, 4 placeholder secrets/KiB (benchmarks small-whole row)",
        generate: || filler_density(LOGS_FILLER, 64 * 1024),
        paths: WHOLE_AND_CLI,
    },
    Workload {
        name: "scale-logs-256k",
        description: "assessment-filler-density-v1 logs, 256 KiB, 4 placeholder secrets/KiB (benchmarks medium-fixed4096 row)",
        generate: || filler_density(LOGS_FILLER, 256 * 1024),
        paths: &[
            ScanPath::Whole,
            ScanPath::Incremental(4096),
            ScanPath::Incremental(CLI_CHUNK_BYTES),
        ],
    },
    Workload {
        name: "mixed-10m",
        description: "10 MiB cycling the eight assessment fillers (ASCII and Unicode), 1 detected secret/KiB",
        generate: mixed_text,
        paths: WHOLE_AND_CLI,
    },
    Workload {
        name: "minified-json-64k",
        description: "one-line minified JSON, 64 KiB, no newline (#989)",
        generate: || minified_json(64 * 1024),
        paths: WHOLE_AND_CLI,
    },
    Workload {
        name: "minified-json-256k",
        description: "one-line minified JSON, 256 KiB, no newline (#989)",
        generate: || minified_json(256 * 1024),
        paths: WHOLE_AND_CLI,
    },
    Workload {
        name: "provider-tables-64k",
        description: "multi-line Heroku / Twilio / Confluent layouts between log lines, 64 KiB",
        generate: provider_tables,
        paths: WHOLE_AND_CLI,
    },
    Workload {
        name: "unicode-invisible-64k",
        description: "non-ASCII text with invisible code points, some inside tokens, 64 KiB",
        generate: unicode_invisible,
        paths: WHOLE_AND_CLI,
    },
    Workload {
        name: "open-assignment-whitespace-10k",
        description: "API_KEY= then 10,000 lines of eight spaces (#986)",
        generate: open_assignment_whitespace,
        paths: WHOLE_AND_CLI,
    },
];

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
    if selected.is_empty() {
        return Err("no workload matches the filter; see --list".to_owned());
    }
    let registry = DetectorRegistry::with_built_in([]).map_err(|error| error.to_string())?;
    let mut results = Vec::new();
    for workload in selected {
        eprintln!("scan_cost: {} ...", workload.name);
        let result = measure_workload(workload, &registry, &options)?;
        if !options.json {
            print!("{}", result.1);
        }
        results.push(result.0);
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
    registry: &DetectorRegistry,
    options: &Options,
) -> Result<(Value, String), String> {
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
                time(options.runs, || scan_incremental(&input, &chunks))?
            }
        };
        let _ = writeln!(
            table,
            "  {:<28} median {:>10.3} ms  (min {:.3}, max {:.3})",
            path.label(),
            stats.median_ms,
            stats.min_ms,
            stats.max_ms
        );
        paths.insert(path.label(), stats.to_json());
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

fn scan_incremental(input: &str, chunks: &[&str]) -> Result<usize, String> {
    let limits = IncrementalLimits::new(
        DEFAULT_MAX_INPUT_BYTES.max(input.len()),
        IncrementalLimits::minimum_buffered_bytes(CLI_MAX_TOKEN_BYTES, CLI_MAX_MULTILINE_BYTES),
        CLI_MAX_TOKEN_BYTES,
        CLI_MAX_MULTILINE_BYTES,
    )
    .map_err(|error| error.to_string())?;
    let mut session = IncrementalSanitizer::new(limits).map_err(|error| error.to_string())?;
    let mut sink = 0;
    for chunk in chunks {
        let result = black_box(session.append(chunk).map_err(|error| error.to_string())?);
        sink += result.text().len() + result.findings().len();
    }
    let result = black_box(session.finalize().map_err(|error| error.to_string())?);
    Ok(sink + result.text().len() + result.findings().len())
}

/// Splits on character boundaries into chunks of at most `maximum` bytes,
/// the `fixed-N` chunk profile of the assessment adapter.
fn partition(input: &str, maximum: usize) -> Vec<&str> {
    let mut chunks = Vec::new();
    let mut rest = input;
    while !rest.is_empty() {
        let mut end = maximum.min(rest.len());
        while !rest.is_char_boundary(end) {
            end -= 1;
        }
        if end == 0 {
            end = rest.chars().next().map_or(rest.len(), char::len_utf8);
        }
        let (chunk, tail) = rest.split_at(end);
        chunks.push(chunk);
        rest = tail;
    }
    chunks
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

fn round4(value: f64) -> f64 {
    (value * 10_000.0).round() / 10_000.0
}

// ------------------------------------------------------------ generators
//
// Every value below is synthetic. None is a real or revoked credential.

/// `assessment-filler-density-v1` at 4 secrets per KiB, as the benchmarks
/// `scale-logs` profiles use it.
fn filler_density(filler: &str, target: usize) -> String {
    let every = ((1024.0 / filler.len() as f64) / 4.0).round().max(1.0) as usize;
    let mut input = String::with_capacity(target + 128);
    let mut line = 0usize;
    while input.len() < target {
        line += 1;
        input.push_str(if line.is_multiple_of(every) {
            SYNTHETIC_SECRET_LINE
        } else {
            filler
        });
    }
    input
}

/// Alphanumerics without look-alikes, for synthetic token bodies.
const TOKEN_ALPHABET: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789";

/// Lines the built-in detectors report (`github_token`, `contextual_secret`,
/// `bearer_token`). The assessment secret line reports nothing: its body is
/// a placeholder, so the `scale-logs` workloads have no findings.
fn detected_lines() -> [String; 3] {
    [
        format!("token=ghp_{}\n", synthetic(TOKEN_ALPHABET, 36, 3)),
        format!("password = \"{}\"\n", synthetic(TOKEN_ALPHABET, 24, 7)),
        format!(
            "Authorization: Bearer {}\n",
            synthetic(TOKEN_ALPHABET, 40, 2)
        ),
    ]
}

fn mixed_text() -> String {
    let target = 10 * 1024 * 1024;
    let secrets = detected_lines();
    let mut input = String::with_capacity(target + 128);
    let mut line = 0usize;
    let mut secret = 0usize;
    let mut next_secret = 1024;
    while input.len() < target {
        if input.len() >= next_secret {
            input.push_str(&secrets[secret % secrets.len()]);
            secret += 1;
            next_secret += 1024;
        }
        input.push_str(MIXED_FILLERS[line % MIXED_FILLERS.len()]);
        line += 1;
    }
    input
}

fn minified_json(target: usize) -> String {
    let mut input = String::with_capacity(target + 256);
    input.push_str("{\"items\":[");
    let mut index = 0usize;
    while input.len() + 2 < target {
        if index > 0 {
            input.push(',');
        }
        let _ = write!(
            input,
            "{{\"id\":{index},\"status\":200,\"name\":\"fixture-{index}\",\"enabled\":true,\"latency_ms\":12,\"region\":\"us-east-1\""
        );
        if index % 16 == 15 {
            let _ = write!(input, ",\"api_key\":\"SYNTHETICfixture{index:016}\"");
        }
        input.push('}');
        index += 1;
    }
    input.push_str("]}");
    input
}

/// Deterministic synthetic text over `alphabet` (the tests' `synthetic`).
fn synthetic(alphabet: &[u8], len: usize, seed: usize) -> String {
    (0..len)
        .map(|index| char::from(alphabet[(index * 7 + seed) % alphabet.len()]))
        .collect()
}

fn provider_tables() -> String {
    const LOWER_HEX: &[u8] = b"0123456789abcdef";
    let hex = synthetic(LOWER_HEX, 32, 5);
    let uuid = format!(
        "{}-{}-{}-{}-{}",
        &hex[..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..]
    );
    let key_id = synthetic(b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789", 16, 1);
    let confluent = synthetic(
        b"ABCDEFGHJKLMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789+/",
        64,
        5,
    );
    let mut block = String::new();
    let _ = write!(
        block,
        "$ heroku authorizations:info $AUTH_ID\nClient:      <none>\nDescription: ci deploy\nScope:       global\nToken:       {uuid}\nUpdated at:  2026-09-02T10:14:31Z\n"
    );
    block.push_str(LOGS_FILLER);
    let _ = write!(
        block,
        "schema.registry.url=https://psrc-7q2x1.us-east-2.aws.confluent.cloud\nbasic.auth.credentials.source=USER_INFO\nbasic.auth.user.info={key_id}:{confluent}\n"
    );
    block.push_str(LOGS_FILLER);
    block.push_str("$ twilio profiles:list --properties authToken\nID     Auth Token\n");
    for row in 0..12 {
        let token = synthetic(LOWER_HEX, 32, 13 + row);
        let _ = writeln!(block, "prof{row:<3} {token}");
    }
    block.push_str(LOGS_FILLER);
    let target = 64 * 1024;
    let mut input = String::with_capacity(target + block.len());
    while input.len() < target {
        input.push_str(&block);
    }
    input
}

fn unicode_invisible() -> String {
    let lines = [
        "2026-09-12T00:00:00Z ｲﾝﾌｫ 요청\u{200B} 완료 상태=200 café\u{00AD}naïve\n".to_owned(),
        "사용자\u{2060} 세션 갱신 \u{FEFF}résumé über\u{200D}den Zaun 你好\n".to_owned(),
        // An invisible code point inside a token: detected after normalization.
        format!("token=ghp_\u{200B}{}\n", synthetic(TOKEN_ALPHABET, 36, 3)),
        "¡Hola! ¿Cómo\u{200C} estás? サンプル \u{1F600} status=ok\n".to_owned(),
    ];
    let target = 64 * 1024;
    let mut input = String::with_capacity(target + 128);
    let mut line = 0usize;
    while input.len() < target {
        input.push_str(&lines[line % lines.len()]);
        line += 1;
    }
    input
}

fn open_assignment_whitespace() -> String {
    let mut input = String::from("API_KEY=\n");
    for _ in 0..10_000 {
        input.push_str("        \n");
    }
    input
}
