//! End-to-end tests over the real `redact-secret` binary.
//!
//! These exercise the parts a unit test cannot: process arguments as the
//! operating system delivers them, real files, real standard streams, and the
//! exit codes a pre-commit hook or CI job actually branches on.
//!
//! Every fixture is synthetic. `SYNTHETIC_TOKEN` has the shape the built-in
//! GitHub detector recognizes and authenticates nothing; no test in this file
//! reads, writes, or transmits a real credential.
//!
//! `clippy.toml` relaxes `unwrap` and `expect` for test code, but only inside
//! a function marked `#[test]`. This file is test code end to end, including
//! the helpers that set up a run, so the same relaxation is declared here.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};

/// A synthetic, revoked-shaped GitHub token.
const SYNTHETIC_TOKEN: &str = "ghp_SYNTHETICREVOKED00000000000000000000";
/// A synthetic, revoked-shaped AWS access key id.
const SYNTHETIC_AWS_KEY: &str = "AKIAIOSFODNN7SYNTHET";

/// The binary under test, as cargo built it for this test target.
fn binary() -> &'static str {
    env!("CARGO_BIN_EXE_redact-secret")
}

/// A scratch directory unique to this process, removed when the guard drops.
struct Scratch {
    root: PathBuf,
}

impl Scratch {
    fn new() -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let root = std::env::temp_dir().join(format!(
            "redact-secret-cli-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&root).unwrap();
        Self { root }
    }

    fn write(&self, name: &str, contents: &str) -> PathBuf {
        self.write_bytes(name, contents.as_bytes())
    }

    fn write_bytes(&self, name: &str, contents: &[u8]) -> PathBuf {
        let path = self.root.join(name);
        fs::write(&path, contents).unwrap();
        path
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

/// One completed run of the binary.
struct Run {
    code: i32,
    stdout: String,
    stderr: String,
}

impl Run {
    fn from(output: &Output) -> Self {
        Self {
            code: output.status.code().unwrap_or(-1),
            stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        }
    }

    /// Asserts that neither stream reproduced a matched value.
    fn leaks_nothing(&self) -> &Self {
        for secret in [SYNTHETIC_TOKEN, SYNTHETIC_AWS_KEY] {
            assert!(
                !self.stdout.contains(secret),
                "stdout reproduced a matched value: {}",
                self.stdout
            );
            assert!(
                !self.stderr.contains(secret),
                "stderr reproduced a matched value: {}",
                self.stderr
            );
        }
        self
    }
}

/// Runs the binary, feeding `stdin` from its own thread.
///
/// The write has to be concurrent with the read: an input large enough to
/// force several reads also produces an output large enough to fill the
/// operating system's pipe buffer, and a single-threaded writer would
/// deadlock against a child that is blocked writing its result.
fn run(args: &[&Path], stdin: &[u8]) -> Run {
    let mut child = Command::new(binary())
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    let mut sink = child.stdin.take().unwrap();
    let payload = stdin.to_vec();
    let writer = std::thread::spawn(move || {
        // A run that fails early closes its input; that is not a test failure.
        let _ = sink.write_all(&payload);
        drop(sink);
    });

    let output = child.wait_with_output().unwrap();
    writer.join().unwrap();
    Run::from(&output)
}

fn run_args(args: &[&str], stdin: &[u8]) -> Run {
    let args: Vec<&Path> = args.iter().map(Path::new).collect();
    run(&args, stdin)
}

// --- check mode: sources -----------------------------------------------

#[test]
fn check_reads_standard_input_when_no_path_is_given() {
    let run = run_args(&[], format!("API_KEY={SYNTHETIC_TOKEN}\n").as_bytes());
    assert_eq!(run.code, 1);
    assert!(run.stdout.starts_with("<stdin>:"));
    assert!(run.stdout.contains("github_token"));
    run.leaks_nothing();
}

#[test]
fn check_reads_one_file() {
    let scratch = Scratch::new();
    let path = scratch.write("one.env", &format!("API_KEY={SYNTHETIC_TOKEN}\n"));
    let run = run(&[&path], b"");

    assert_eq!(run.code, 1);
    assert_eq!(run.stdout.lines().count(), 1);
    assert!(run.stdout.contains("one.env:8-48 github_token"));
    run.leaks_nothing();
}

#[test]
fn check_reads_several_files_in_order() {
    let scratch = Scratch::new();
    let first = scratch.write("first.env", &format!("API_KEY={SYNTHETIC_TOKEN}\n"));
    let clean = scratch.write("clean.txt", "nothing to see\n");
    let third = scratch.write("third.env", &format!("AWS={SYNTHETIC_AWS_KEY}\n"));
    let run = run(&[&first, &clean, &third], b"");

    assert_eq!(run.code, 1);
    let lines: Vec<&str> = run.stdout.lines().collect();
    assert_eq!(lines.len(), 2);
    assert!(lines[0].contains("first.env"));
    assert!(lines[0].contains("github_token"));
    assert!(lines[1].contains("third.env"));
    assert!(lines[1].contains("aws_access_key_id"));
    assert!(run.stderr.contains("2 finding(s) in 3 source(s)"));
    run.leaks_nothing();
}

#[test]
fn a_file_path_that_looks_like_an_option_is_reachable_after_a_double_dash() {
    let scratch = Scratch::new();
    let path = scratch.write("--json", &format!("API_KEY={SYNTHETIC_TOKEN}\n"));
    let run = run(&[Path::new("--"), &path], b"");

    assert_eq!(run.code, 1);
    assert!(run.stdout.contains("github_token"));
    run.leaks_nothing();
}

// --- check mode: exit codes --------------------------------------------

#[test]
fn a_clean_check_exits_zero_with_an_empty_report() {
    let run = run_args(&[], b"nothing interesting here\n");
    assert_eq!(run.code, 0);
    assert_eq!(run.stdout, "");
    assert!(run.stderr.contains("0 finding(s) in 1 source(s)"));
}

#[test]
fn a_finding_exits_one() {
    let run = run_args(&[], format!("API_KEY={SYNTHETIC_TOKEN}\n").as_bytes());
    assert_eq!(run.code, 1);
}

#[test]
fn a_usage_failure_exits_two_and_prints_the_usage_block() {
    let run = run_args(&["--nope"], b"");
    assert_eq!(run.code, 2);
    assert_eq!(run.stdout, "");
    assert!(run.stderr.contains("USAGE: unrecognized option"));
    assert!(run.stderr.contains("usage: redact-secret"));
    assert!(!run.stderr.contains("--nope"));
}

#[test]
fn a_missing_file_exits_two_without_naming_an_operating_system_message() {
    let scratch = Scratch::new();
    let missing = scratch.root.join("absent.env");
    let run = run(&[&missing], b"");

    assert_eq!(run.code, 2);
    assert!(run.stderr.contains("READ_FAILED"));
    assert!(run.stderr.contains("Reading the input failed."));
}

#[test]
fn a_failure_outranks_a_finding() {
    let scratch = Scratch::new();
    let found = scratch.write("found.env", &format!("API_KEY={SYNTHETIC_TOKEN}\n"));
    let missing = scratch.root.join("absent.env");
    let run = run(&[&found, &missing], b"");

    assert_eq!(run.code, 2, "a partially scanned run is not a clean one");
    assert!(
        run.stdout.contains("github_token"),
        "what was scanned is still reported"
    );
    assert!(run.stderr.contains("READ_FAILED"));
    run.leaks_nothing();
}

// --- check mode: safe reporting ----------------------------------------

#[test]
fn the_json_report_is_one_object_and_carries_no_matched_text() {
    let scratch = Scratch::new();
    let path = scratch.write("keys.env", &format!("API_KEY={SYNTHETIC_TOKEN}\n"));
    let run = run(&[Path::new("--json"), &path], b"");

    assert_eq!(run.code, 1);
    assert!(run.stdout.starts_with("{\n"));
    assert!(run.stdout.trim_end().ends_with('}'));
    assert_eq!(run.stdout.matches("\"findingCount\"").count(), 1);
    assert!(run.stdout.contains("\"rangeUnit\": \"utf8-bytes\""));
    assert!(run.stdout.contains("\"findingCount\": 1"));
    assert!(run.stdout.contains("\"type\": \"github_token\""));
    assert!(run.stdout.contains("\"detector\": \"github-token\""));
    assert!(run.stdout.contains("\"confidence\": \"high\""));
    assert!(run.stdout.contains("\"action\": \"redact\""));
    assert!(run.stdout.contains("\"start\": 8"));
    assert!(run.stdout.contains("\"end\": 48"));
    assert!(run.stdout.contains("\"failures\": []"));
    run.leaks_nothing();
}

#[test]
fn the_json_report_of_a_clean_run_is_still_a_complete_object() {
    let run = run_args(&["--json"], b"nothing interesting here\n");

    assert_eq!(run.code, 0);
    assert!(run.stdout.contains("\"findingCount\": 0"));
    assert!(run.stdout.contains("\"source\": \"<stdin>\""));
    assert!(run.stdout.contains("\"findings\": []"));
    assert!(run.stdout.contains("\"failures\": []"));
    assert_eq!(
        run.stdout.matches('{').count(),
        run.stdout.matches('}').count()
    );
    assert_eq!(
        run.stdout.matches('[').count(),
        run.stdout.matches(']').count()
    );
}

/// `id` is the only opaque handle the report exposes, and the core numbers
/// each scan from `finding-1`. A multi-file check runs one scan per file, so
/// the report has to renumber or a consumer keyed on `id` collides.
#[test]
fn finding_ids_are_unique_across_sources() {
    let scratch = Scratch::new();
    let first = scratch.write("first.env", &format!("API_KEY={SYNTHETIC_TOKEN}\n"));
    let second = scratch.write("second.env", &format!("AWS={SYNTHETIC_AWS_KEY}\n"));
    let third = scratch.write("third.env", &format!("API_KEY={SYNTHETIC_TOKEN}\n"));
    let run = run(&[&first, &second, &third], b"");

    assert_eq!(run.code, 1);
    let ids: Vec<&str> = run
        .stdout
        .lines()
        .filter_map(|line| line.rsplit_once("id=").map(|(_, id)| id))
        .collect();
    assert_eq!(ids, ["finding-1", "finding-2", "finding-3"]);
}

#[test]
fn a_single_source_keeps_the_numbering_the_core_produced() {
    let contents = format!("API_KEY={SYNTHETIC_TOKEN}\nAWS={SYNTHETIC_AWS_KEY}\n");
    let run = run_args(&[], contents.as_bytes());

    let ids: Vec<&str> = run
        .stdout
        .lines()
        .filter_map(|line| line.rsplit_once("id=").map(|(_, id)| id))
        .collect();
    assert_eq!(ids, ["finding-1", "finding-2"]);
}

#[test]
fn the_json_report_records_a_failed_source_alongside_a_scanned_one() {
    let scratch = Scratch::new();
    let found = scratch.write("found.env", &format!("API_KEY={SYNTHETIC_TOKEN}\n"));
    let malformed = scratch.write_bytes("malformed.bin", &[0xff, 0xfe, 0x00]);
    let run = run(&[Path::new("--json"), &found, &malformed], b"");

    assert_eq!(run.code, 2);
    assert!(run.stdout.contains("\"code\": \"NOT_UTF8\""));
    assert!(
        run.stdout
            .contains("\"message\": \"Input is not valid UTF-8.\"")
    );
    assert!(run.stdout.contains("malformed.bin"));
    run.leaks_nothing();
}

#[test]
fn a_check_report_never_reproduces_a_private_key_block() {
    let block = concat!(
        "-----BEGIN RSA PRIVATE KEY-----\n",
        "U1lOVEhFVElDUkVWT0tFRFRFU1RLRVlOT1RSRUFMMDAwMDAwMDAwMDAwMDAwMDA=\n",
        "-----END RSA PRIVATE KEY-----\n",
    );
    let run = run_args(&[], block.as_bytes());

    assert_eq!(run.code, 1);
    assert!(run.stdout.contains("private_key"));
    assert!(run.stdout.contains("action=block"));
    assert!(!run.stdout.contains("BEGIN RSA PRIVATE KEY"));
    assert!(!run.stdout.contains("U1lOVEhFVElD"));
    assert!(!run.stderr.contains("U1lOVEhFVElD"));
}

// --- decoding ----------------------------------------------------------

#[test]
fn malformed_standard_input_fails_closed_with_an_input_free_diagnostic() {
    let run = run_args(&[], &[0x41, 0xff, 0xfe, 0x0a]);
    assert_eq!(run.code, 2);
    assert!(run.stderr.contains("NOT_UTF8"));
    assert!(run.stderr.contains("Input is not valid UTF-8."));
    assert_eq!(
        run.stderr.lines().count(),
        2,
        "one summary and one diagnostic"
    );
}

#[test]
fn a_malformed_file_fails_closed_and_is_not_scanned_in_part() {
    let scratch = Scratch::new();
    let mut bytes = format!("API_KEY={SYNTHETIC_TOKEN}\n").into_bytes();
    bytes.extend_from_slice(&[0xff, 0xfe]);
    let path = scratch.write_bytes("mixed.bin", &bytes);
    let run = run(&[&path], b"");

    assert_eq!(run.code, 2);
    assert_eq!(
        run.stdout, "",
        "a source that failed to decode reports nothing"
    );
    assert!(run.stderr.contains("NOT_UTF8"));
    run.leaks_nothing();
}

#[test]
fn malformed_input_fails_closed_in_redact_mode_too() {
    let run = run_args(&["--redact"], &[0x41, 0x0a, 0xff, 0xfe]);
    assert_eq!(run.code, 2);
    assert!(run.stderr.contains("NOT_UTF8"));
}

#[test]
fn a_character_split_across_reads_is_not_mistaken_for_malformed_input() {
    // Lines of astral characters, past several 64 KiB reads, so a read
    // boundary certainly lands inside a four-byte sequence.
    let line = format!("{}\n", "\u{1f511}".repeat(64));
    let input = line.repeat(2 * 1024);
    let run = run_args(&["--redact"], input.as_bytes());

    assert_eq!(run.code, 0);
    assert_eq!(run.stdout, input);
}

// --- redact mode -------------------------------------------------------

#[test]
fn redact_sanitizes_standard_input() {
    let run = run_args(
        &["--redact"],
        format!("API_KEY={SYNTHETIC_TOKEN}\ntail\n").as_bytes(),
    );
    assert_eq!(run.code, 0);
    assert_eq!(run.stdout, "API_KEY=<SECRET_1>\ntail\n");
    run.leaks_nothing();
}

#[test]
fn redact_sanitizes_exactly_one_file_and_leaves_it_untouched() {
    let scratch = Scratch::new();
    let contents = format!("API_KEY={SYNTHETIC_TOKEN}\ntail\n");
    let path = scratch.write("one.env", &contents);
    let before = fs::metadata(&path).unwrap().len();

    let run = run(&[Path::new("--redact"), &path], b"");

    assert_eq!(run.code, 0);
    assert_eq!(run.stdout, "API_KEY=<SECRET_1>\ntail\n");
    assert_eq!(
        fs::read_to_string(&path).unwrap(),
        contents,
        "redaction must never modify its input in place"
    );
    assert_eq!(fs::metadata(&path).unwrap().len(), before);
    run.leaks_nothing();
}

/// Redaction reports success when it wrote the whole sanitized stream.
/// Finding something is what it is for, so a finding — including one the
/// policy blocks — is not a failure there. Check mode is the mode that fails
/// a hook on a finding.
#[test]
fn redact_exits_zero_even_for_a_finding_the_policy_blocks() {
    let block = concat!(
        "-----BEGIN RSA PRIVATE KEY-----\n",
        "U1lOVEhFVElDUkVWT0tFRFRFU1RLRVlOT1RSRUFMMDAwMDAwMDAwMDAwMDAwMDA=\n",
        "-----END RSA PRIVATE KEY-----\n",
    );
    let checked = run_args(&[], block.as_bytes());
    let redacted = run_args(&["--redact"], block.as_bytes());

    assert_eq!(checked.code, 1, "check fails a hook on the blocked finding");
    assert!(checked.stdout.contains("action=block"));

    assert_eq!(
        redacted.code, 0,
        "redaction wrote the whole sanitized stream"
    );
    assert!(redacted.stdout.contains("<SECRET_1>"));
    assert!(!redacted.stdout.contains("U1lOVEhFVElD"));
}

#[test]
fn redact_refuses_more_than_one_file() {
    let scratch = Scratch::new();
    let first = scratch.write("a.env", "clean\n");
    let second = scratch.write("b.env", "clean\n");
    let run = run(&[Path::new("--redact"), &first, &second], b"");

    assert_eq!(run.code, 2);
    assert_eq!(run.stdout, "");
    assert!(run.stderr.contains("exactly one path"));
}

#[test]
fn redact_refuses_the_check_report_option() {
    let run = run_args(&["--redact", "--json"], b"");
    assert_eq!(run.code, 2);
    assert!(run.stderr.contains("--json is a check option"));
}

#[test]
fn redacted_output_matches_between_the_streamed_and_whole_file_paths() {
    let scratch = Scratch::new();
    let contents =
        format!("line one\nAPI_KEY={SYNTHETIC_TOKEN}\nAWS={SYNTHETIC_AWS_KEY}\nlast line\n");
    let path = scratch.write("both.env", &contents);

    let streamed = run_args(&["--redact"], contents.as_bytes());
    let whole = run(&[Path::new("--redact"), &path], b"");

    assert_eq!(streamed.code, 0);
    assert_eq!(whole.code, 0);
    assert_eq!(streamed.stdout, whole.stdout);
    assert_eq!(
        streamed.stdout,
        "line one\nAPI_KEY=<SECRET_1>\nAWS=<SECRET_2>\nlast line\n"
    );
    streamed.leaks_nothing();
}

#[test]
fn check_and_redact_agree_on_the_same_input() {
    let contents = format!("API_KEY={SYNTHETIC_TOKEN}\nAWS={SYNTHETIC_AWS_KEY}\n");
    let checked = run_args(&[], contents.as_bytes());
    let redacted = run_args(&["--redact"], contents.as_bytes());

    assert_eq!(checked.code, 1);
    assert_eq!(checked.stdout.lines().count(), 2);
    assert_eq!(redacted.stdout.matches("<SECRET_").count(), 2);
}

// --- limits ------------------------------------------------------------

/// The `max token` limit the binary prints in its own help, so a test builds
/// input against the limit in force rather than against a copied number.
fn declared_max_token_bytes() -> usize {
    let help = run_args(&["--help"], b"").stdout;
    let line = help
        .lines()
        .find(|line| line.trim_start().starts_with("max token "))
        .expect("help must declare the token limit");
    line.split_whitespace()
        .nth(2)
        .and_then(|bytes| bytes.parse().ok())
        .expect("the token limit must be a byte count")
}

#[test]
fn an_open_construct_past_the_token_limit_fails_the_run() {
    // One unterminated assignment longer than the declared token limit.
    let mut input = b"API_KEY=".to_vec();
    input.resize(declared_max_token_bytes() + 1, b'a');
    input.push(b'\n');
    let run = run_args(&[], &input);

    assert_eq!(run.code, 2);
    assert!(run.stderr.contains("TOKEN_LIMIT_EXCEEDED"));
}

/// The construct limits bound a streamed run but not a run over a path, so a
/// limit tuned to credential length would make the two paths disagree about
/// ordinary input: a minified bundle, a lockfile entry, or a base64 blob would
/// scan by path and fail on standard input.
#[test]
fn an_ordinary_long_line_behaves_the_same_streamed_or_by_path() {
    let scratch = Scratch::new();
    let contents = format!(
        "var bundle = \"{}\";\nAPI_KEY={SYNTHETIC_TOKEN}\n",
        "a".repeat(64 * 1024)
    );
    let path = scratch.write("bundle.js", &contents);

    let streamed = run_args(&["--json"], contents.as_bytes());
    let by_path = run(&[Path::new("--json"), &path], b"");

    assert_eq!(streamed.code, 1, "a long line must not fail a streamed run");
    assert_eq!(by_path.code, 1);
    // Compare the structured findings, not rendered source labels: text
    // reports escape Windows backslashes and other non-printing characters.
    let streamed_report: serde_json::Value = serde_json::from_str(&streamed.stdout).unwrap();
    let path_report: serde_json::Value = serde_json::from_str(&by_path.stdout).unwrap();
    assert_eq!(streamed_report["findingCount"], 1);
    assert_eq!(path_report["findingCount"], 1);
    assert_eq!(
        streamed_report["sources"][0]["findings"], path_report["sources"][0]["findings"],
        "the two paths must report the same finding at the same offsets",
    );

    let streamed_redaction = run_args(&["--redact"], contents.as_bytes());
    let path_redaction = run(&[Path::new("--redact"), &path], b"");
    assert_eq!(streamed_redaction.code, 0);
    assert_eq!(path_redaction.code, 0);
    assert_eq!(streamed_redaction.stdout, path_redaction.stdout);
    streamed_redaction.leaks_nothing();
}

// --- version and help --------------------------------------------------

#[test]
fn version_reports_the_product_version_alone() {
    let run = run_args(&["--version"], b"");
    assert_eq!(run.code, 0);
    assert_eq!(run.stdout.lines().count(), 1);
    assert!(run.stdout.starts_with("redact-secret "));
    assert_eq!(run_args(&["-V"], b"").stdout, run.stdout);
}

#[test]
fn version_and_help_reject_extra_arguments() {
    for args in [
        vec!["--version", "a.txt"],
        vec!["a.txt", "--help"],
        vec!["--help", "--json"],
    ] {
        let run = run_args(&args, b"");
        assert_eq!(run.code, 2, "{args:?} should be rejected");
        assert!(run.stderr.contains("take no other arguments"));
    }
}

#[test]
fn help_documents_the_modes_the_exit_codes_and_the_reporting_shape() {
    let run = run_args(&["--help"], b"");
    assert_eq!(run.code, 0);
    for expected in [
        "check mode",
        "redact mode",
        "--json",
        "--redact",
        "exit codes",
        "limits",
        "utf8-bytes",
        "never modified in place",
        "\"findingCount\"",
        "\"failures\"",
        "unique across the whole report",
        "check the exit code before using the output",
        "redact: never returned",
        "streamed path only",
    ] {
        assert!(run.stdout.contains(expected), "help omits {expected}");
    }
    assert_eq!(run_args(&["-h"], b"").stdout, run.stdout);
}

// --- canonical corpus: redact mode --------------------------------------

/// The canonical synchronous corpus, loaded the same way
/// `crates/secret-scan-core/tests/support/mod.rs` loads it: `include_str!`,
/// so a fixture change forces a rebuild of this test.
const SYNCHRONOUS_CORPUS: &str =
    include_str!("../../../conformance/fixtures/synchronous-corpus.json");

/// One `canonical`-tier corpus fixture. That tier declares exactly one
/// high-confidence expectation per fixture, and `DefaultPolicy`
/// (`crates/secret-scan-core/src/policy.rs`) always redacts or blocks a
/// high-confidence finding — both actions replace the range with
/// `<SECRET_1>`. The corpus-expected redacted text is therefore computable
/// from `expected[0].start`/`end` alone, without calling the redaction code
/// under test.
struct CanonicalRedactFixture {
    id: String,
    input: String,
    start: usize,
    end: usize,
}

/// Every `canonical`-tier fixture in `synchronous-corpus.json`. Neither this
/// helper nor its caller embeds a fixture input or a matched value; every
/// value here is read out of the corpus file at run time.
fn canonical_redact_fixtures() -> Vec<CanonicalRedactFixture> {
    let document: serde_json::Value =
        serde_json::from_str(SYNCHRONOUS_CORPUS).expect("synchronous-corpus.json is valid JSON");
    document["fixtures"]
        .as_array()
        .expect("synchronous-corpus.json has a fixtures array")
        .iter()
        .filter(|fixture| fixture["tier"].as_str() == Some("canonical"))
        .map(|fixture| {
            let id = fixture["id"]
                .as_str()
                .expect("canonical fixture has an id")
                .to_owned();
            let expected = fixture["expected"]
                .as_array()
                .filter(|expected| expected.len() == 1)
                .expect("canonical fixture must declare exactly one expectation");
            let expectation = &expected[0];
            CanonicalRedactFixture {
                input: fixture["input"]
                    .as_str()
                    .expect("canonical fixture has an input")
                    .to_owned(),
                start: usize::try_from(
                    expectation["start"]
                        .as_u64()
                        .expect("canonical fixture expectation has a start"),
                )
                .expect("start fits in usize"),
                end: usize::try_from(
                    expectation["end"]
                        .as_u64()
                        .expect("canonical fixture expectation has an end"),
                )
                .expect("end fits in usize"),
                id,
            }
        })
        .collect()
}

/// Runs the real `redact-secret --redact` binary over every canonical-tier
/// corpus fixture and asserts its stdout equals the corpus-expected redacted
/// text, exercising argument parsing, standard I/O, and the redaction
/// pipeline together the way a pre-commit hook actually invokes them.
#[test]
fn redact_matches_the_canonical_corpus_redacted_text() {
    let fixtures = canonical_redact_fixtures();
    assert!(!fixtures.is_empty(), "canonical tier must not be empty");

    for fixture in fixtures {
        let expected = format!(
            "{}<SECRET_1>{}",
            &fixture.input[..fixture.start],
            &fixture.input[fixture.end..],
        );
        let run = run_args(&["--redact"], fixture.input.as_bytes());
        assert_eq!(run.code, 0, "{}", fixture.id);
        assert_eq!(run.stdout, expected, "{}", fixture.id);
    }
}

// --- canonical corpus: whole-input vs incremental parity ---------------

/// The canonical incremental partition-equivalence corpus, loaded the same
/// way `crates/secret-scan-core/tests/support/mod.rs` loads it: `include_str!`,
/// so a fixture change forces a rebuild of this test.
const INCREMENTAL_CORPUS: &str =
    include_str!("../../../conformance/fixtures/incremental-corpus.json");

/// Every fixture's `id` and `input`, read out of the corpus file at run time.
fn incremental_corpus_fixtures() -> Vec<(String, String)> {
    let document: serde_json::Value =
        serde_json::from_str(INCREMENTAL_CORPUS).expect("incremental-corpus.json is valid JSON");
    document["fixtures"]
        .as_array()
        .expect("incremental-corpus.json has a fixtures array")
        .iter()
        .map(|fixture| {
            (
                fixture["id"]
                    .as_str()
                    .expect("fixture has an id")
                    .to_owned(),
                fixture["input"]
                    .as_str()
                    .expect("fixture has an input")
                    .to_owned(),
            )
        })
        .collect()
}

/// A `--json` check report's findings, with the `source` field dropped: a
/// file-path run and a stdin run necessarily name different sources, but
/// every other field must agree.
fn findings_ignoring_source(stdout: &str) -> serde_json::Value {
    let mut report: serde_json::Value =
        serde_json::from_str(stdout).expect("--json output is valid JSON");
    for source in report["sources"]
        .as_array_mut()
        .expect("report has a sources array")
    {
        source
            .as_object_mut()
            .expect("source entry is an object")
            .remove("source");
    }
    report
}

/// issue #265: a path read whole and the same bytes streamed through stdin
/// must report identical findings for every fixture in the canonical
/// incremental corpus, not just the two mismatches the evaluator found.
#[test]
fn cli_file_path_and_stdin_reports_match_the_incremental_corpus() {
    let scratch = Scratch::new();
    let fixtures = incremental_corpus_fixtures();
    assert!(!fixtures.is_empty(), "incremental corpus must not be empty");

    for (id, input) in fixtures {
        let path = scratch.write(&format!("{id}.txt"), &input);
        let file = run(&[Path::new("--json"), &path], b"");
        let stdin = run_args(&["--json"], input.as_bytes());

        assert_eq!(file.code, stdin.code, "{id}: exit code");
        assert_eq!(
            findings_ignoring_source(&file.stdout),
            findings_ignoring_source(&stdin.stdout),
            "{id}: findings diverged between file path and stdin",
        );
    }
}

// --- broken pipe -------------------------------------------------------

/// A downstream reader that exits early must not hang the binary, must not
/// let it report success, and must not leave a matched value anywhere.
///
/// The pipeline is driven by `sh` so the binary's own exit status is
/// observable: a shell pipeline reports the last command's status, so the
/// status is echoed to stderr from inside the pipeline instead. The input is
/// far larger than any pipe buffer, so `head` has certainly exited before the
/// binary's last write.
#[cfg(unix)]
#[test]
fn a_closed_downstream_pipe_fails_the_run_instead_of_hanging() {
    let scratch = Scratch::new();
    let mut contents = format!("API_KEY={SYNTHETIC_TOKEN}\n");
    while contents.len() < 4 * 1024 * 1024 {
        contents.push_str("padding line that holds nothing interesting\n");
    }
    let path = scratch.write("large.env", &contents);

    let script = format!(
        "{{ '{}' --redact '{}'; echo \"status=$?\" >&2; }} | head -c 1 >/dev/null",
        binary(),
        path.display(),
    );
    let output = Command::new("sh").arg("-c").arg(&script).output().unwrap();
    let run = Run::from(&output);

    assert!(
        run.stderr.contains("status=2"),
        "expected the binary to report a write failure, got: {}",
        run.stderr
    );
    assert!(run.stderr.contains("WRITE_FAILED"));
    run.leaks_nothing();
}
