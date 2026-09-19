//! Shared support for the canonical-corpus integration tests.
//!
//! Loads the language-neutral fixtures under `conformance/fixtures/` (the
//! single behavioral contract required by
//! `decision-govern-cross-language-conformance`) and provides the partition
//! generators the incremental proofs enumerate. Partitioning is generated
//! deterministically here, not stored as fixture data.
//!
//! Every fixture value is synthetic; nothing in this module reproduces a
//! matched value outside the fixture input it came from.

#![allow(dead_code, clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use redact_secret::{
    Confidence, DefaultPolicy, DetectorRegistry, Finding, IncrementalLimits, IncrementalSanitizer,
    default_placeholder_formatter, redact, scan,
};
use serde_json::Value;

// ---------------------------------------------------------------------------
// canonical corpus loading
// ---------------------------------------------------------------------------

/// The canonical incremental corpus, embedded at compile time so a fixture
/// change forces a rebuild of these tests.
const INCREMENTAL_CORPUS: &str =
    include_str!("../../../../conformance/fixtures/incremental-corpus.json");

/// The canonical synchronous corpus, which carries the adversarial tier and
/// its declared resource caps.
const SYNCHRONOUS_CORPUS: &str =
    include_str!("../../../../conformance/fixtures/synchronous-corpus.json");

/// The canonical Unicode range-conversion corpus: UTF-8 byte spans every
/// binding's native range conversion must preserve.
const UNICODE_CONVERSION_CORPUS: &str =
    include_str!("../../../../conformance/fixtures/unicode-conversion-corpus.json");

/// One canonical expectation: safe classification metadata and a UTF-8 byte
/// range. The schema has no field for a matched value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CanonicalExpectation {
    pub detector: String,
    pub type_name: String,
    pub confidence: Confidence,
    pub specificity: String,
    pub start: usize,
    pub end: usize,
    /// The wire name of the declared [`Obfuscation`](redact_secret::Obfuscation),
    /// or `None` when the fixture leaves it unspecified (every fixture
    /// predating this optional field).
    pub obfuscation: Option<String>,
}

/// The declared input, finding-count, and runtime caps an adversarial
/// fixture must stay within.
#[derive(Clone, Copy, Debug)]
#[allow(clippy::struct_field_names)]
pub struct CanonicalResource {
    pub max_input_bytes: usize,
    pub max_findings: usize,
    pub max_runtime_ms: u128,
}

/// A canonical incremental fixture: an input and the whole-input reference
/// every partition of that input must reproduce.
#[derive(Clone, Debug)]
pub struct CanonicalIncrementalFixture {
    pub id: String,
    pub input: String,
    pub text: String,
    pub expected: Vec<CanonicalExpectation>,
}

/// A canonical Unicode range-conversion fixture: an input and the single
/// UTF-8 byte span every binding's native range conversion must preserve.
#[derive(Clone, Debug)]
pub struct CanonicalRangeFixture {
    pub id: String,
    pub input: String,
    pub start: usize,
    pub end: usize,
}

/// A canonical synchronous fixture, with the resource caps the adversarial
/// tier declares.
#[derive(Clone, Debug)]
pub struct CanonicalFixture {
    pub id: String,
    pub tier: String,
    pub kind: String,
    pub support: String,
    pub input: String,
    /// `None` for a `not-yet-evaluated` fixture, which declares no
    /// expectation yet.
    pub expected: Option<Vec<CanonicalExpectation>>,
    pub resource: Option<CanonicalResource>,
}

impl CanonicalFixture {
    /// The expectations a supported fixture declares. Panics for a
    /// `not-yet-evaluated` fixture, which has none by design and must be
    /// filtered out before this is called.
    pub fn declared_expectations(&self) -> &[CanonicalExpectation] {
        self.expected.as_deref().unwrap_or_else(|| {
            panic!(
                "canonical fixture {} is {} and declares no expectations",
                self.id, self.support,
            )
        })
    }
}

fn field<'a>(object: &'a Value, key: &str, fixture: &str) -> &'a Value {
    object
        .get(key)
        .unwrap_or_else(|| panic!("canonical fixture {fixture} is missing {key}"))
}

fn text_field(object: &Value, key: &str, fixture: &str) -> String {
    field(object, key, fixture)
        .as_str()
        .unwrap_or_else(|| panic!("canonical fixture {fixture} has a non-string {key}"))
        .to_owned()
}

fn offset_field(object: &Value, key: &str, fixture: &str) -> usize {
    usize::try_from(
        field(object, key, fixture)
            .as_u64()
            .unwrap_or_else(|| panic!("canonical fixture {fixture} has a non-offset {key}")),
    )
    .unwrap()
}

/// Canonical `expected` is an array, or `null` for a `not-yet-evaluated`
/// fixture that deliberately declares no expectation yet.
fn parse_expectations(object: &Value, fixture: &str) -> Option<Vec<CanonicalExpectation>> {
    let expected = field(object, "expected", fixture);
    if expected.is_null() {
        return None;
    }
    Some(
        expected
            .as_array()
            .unwrap_or_else(|| panic!("canonical fixture {fixture} has a non-array expected"))
            .iter()
            .map(|expected| {
                let confidence_name = text_field(expected, "confidence", fixture);
                CanonicalExpectation {
                    detector: text_field(expected, "detector", fixture),
                    type_name: text_field(expected, "type", fixture),
                    confidence: Confidence::from_name(&confidence_name).unwrap_or_else(|| {
                        panic!("canonical fixture {fixture} has an unknown confidence")
                    }),
                    specificity: text_field(expected, "specificity", fixture),
                    start: offset_field(expected, "start", fixture),
                    end: offset_field(expected, "end", fixture),
                    obfuscation: expected
                        .get("obfuscation")
                        .map(|value| {
                            value.as_str().unwrap_or_else(|| {
                                panic!("canonical fixture {fixture} has a non-string obfuscation")
                            })
                        })
                        .map(str::to_owned),
                }
            })
            .collect(),
    )
}

fn parse_corpus(source: &str, name: &str) -> Vec<Value> {
    let document: Value = serde_json::from_str(source)
        .unwrap_or_else(|error| panic!("{name} is not valid JSON: {error}"));
    assert_eq!(
        document.get("offsetUnit").and_then(Value::as_str),
        Some("utf8-byte"),
        "{name} must declare canonical UTF-8 byte offsets",
    );
    let fixtures = document
        .get("fixtures")
        .and_then(Value::as_array)
        .unwrap_or_else(|| panic!("{name} has no fixtures array"))
        .clone();
    assert_eq!(
        document.get("fixtureCount").and_then(Value::as_u64),
        Some(fixtures.len() as u64),
        "{name} declares an inaccurate fixtureCount",
    );
    fixtures
}

/// Every fixture in `conformance/fixtures/incremental-corpus.json`.
pub fn incremental_corpus() -> Vec<CanonicalIncrementalFixture> {
    parse_corpus(INCREMENTAL_CORPUS, "incremental-corpus.json")
        .iter()
        .map(|fixture| {
            let id = text_field(fixture, "id", "<unidentified>");
            CanonicalIncrementalFixture {
                input: text_field(fixture, "input", &id),
                text: text_field(fixture, "text", &id),
                expected: parse_expectations(fixture, &id).unwrap_or_else(|| {
                    panic!("incremental fixture {id} must declare expectations")
                }),
                id,
            }
        })
        .collect()
}

/// Every fixture in `conformance/fixtures/synchronous-corpus.json`.
pub fn synchronous_corpus() -> Vec<CanonicalFixture> {
    parse_corpus(SYNCHRONOUS_CORPUS, "synchronous-corpus.json")
        .iter()
        .map(|fixture| {
            let id = text_field(fixture, "id", "<unidentified>");
            let resource = fixture.get("resource").map(|resource| CanonicalResource {
                max_input_bytes: offset_field(resource, "maxInputBytes", &id),
                max_findings: offset_field(resource, "maxFindings", &id),
                max_runtime_ms: u128::from(
                    field(resource, "maxRuntimeMs", &id)
                        .as_u64()
                        .unwrap_or_else(|| panic!("canonical fixture {id} has no maxRuntimeMs")),
                ),
            });
            CanonicalFixture {
                tier: text_field(fixture, "tier", &id),
                kind: text_field(fixture, "kind", &id),
                support: text_field(fixture, "support", &id),
                input: text_field(fixture, "input", &id),
                expected: parse_expectations(fixture, &id),
                resource,
                id,
            }
        })
        .collect()
}

/// Every fixture in `conformance/fixtures/unicode-conversion-corpus.json`.
pub fn unicode_conversion_corpus() -> Vec<CanonicalRangeFixture> {
    parse_corpus(UNICODE_CONVERSION_CORPUS, "unicode-conversion-corpus.json")
        .iter()
        .map(|fixture| {
            let id = text_field(fixture, "id", "<unidentified>");
            let input = text_field(fixture, "input", &id);
            let expectations = parse_expectations(fixture, &id).unwrap_or_else(|| {
                panic!("unicode-conversion fixture {id} must declare an expectation")
            });
            assert_eq!(
                expectations.len(),
                1,
                "unicode-conversion fixture {id} must declare exactly one expectation",
            );
            CanonicalRangeFixture {
                start: expectations[0].start,
                end: expectations[0].end,
                input,
                id,
            }
        })
        .collect()
}

// ---------------------------------------------------------------------------
// whole-input reference
// ---------------------------------------------------------------------------

/// The whole-input reference: the synchronous pipeline over `input` with the
/// built-in registry, the default policy, and the default placeholder
/// formatter — exactly what an incremental session must reproduce.
pub fn whole_input(input: &str) -> (String, Vec<Finding>) {
    let registry = DetectorRegistry::with_built_in([]).unwrap();
    let findings = scan(input, &registry, &DefaultPolicy).unwrap();
    let text = redact(input, &findings, &default_placeholder_formatter).unwrap();
    (text, findings)
}

// ---------------------------------------------------------------------------
// incremental session drivers
// ---------------------------------------------------------------------------

/// What one incremental session produced, split into the text and findings
/// released by `append` calls and those released by the single `finalize`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SessionRun {
    pub appended_text: String,
    pub appended_findings: Vec<Finding>,
    pub finalized_text: String,
    pub finalized_findings: Vec<Finding>,
    /// How many results carried a non-empty text, in call order.
    pub emitting_calls: usize,
}

impl SessionRun {
    /// The concatenated safe output of the whole session.
    pub fn text(&self) -> String {
        format!("{}{}", self.appended_text, self.finalized_text)
    }

    /// Every finding the session released, in call order.
    pub fn findings(&self) -> Vec<Finding> {
        let mut findings = self.appended_findings.clone();
        findings.extend(self.finalized_findings.iter().cloned());
        findings
    }
}

/// Limits generous enough that no corpus fixture reaches one, so a partition
/// difference can never be masked by a limit failure.
pub fn generous_limits() -> IncrementalLimits {
    IncrementalLimits::new(1_000_000, 16_512, 8_192, 16_384).unwrap()
}

/// Runs `chunks` through a fresh session: one `append` per chunk, then one
/// `finalize`.
pub fn run_session(chunks: &[&str], limits: IncrementalLimits) -> SessionRun {
    let mut sanitizer = IncrementalSanitizer::new(limits).unwrap();
    let mut run = SessionRun {
        appended_text: String::new(),
        appended_findings: Vec::new(),
        finalized_text: String::new(),
        finalized_findings: Vec::new(),
        emitting_calls: 0,
    };
    for chunk in chunks {
        let result = sanitizer.append(chunk).unwrap();
        if !result.text().is_empty() {
            run.emitting_calls += 1;
        }
        let (text, findings) = result.into_parts();
        run.appended_text.push_str(&text);
        run.appended_findings.extend(findings);
    }
    let result = sanitizer.finalize().unwrap();
    if !result.text().is_empty() {
        run.emitting_calls += 1;
    }
    let (text, findings) = result.into_parts();
    run.finalized_text = text;
    run.finalized_findings = findings;
    run
}

/// Runs `chunks` with [`generous_limits`].
pub fn run(chunks: &[&str]) -> SessionRun {
    run_session(chunks, generous_limits())
}

// ---------------------------------------------------------------------------
// UTF-8 byte-chunk driver
// ---------------------------------------------------------------------------

/// The streaming UTF-8 decoder a byte-oriented host must place in front of
/// the core, which accepts `&str` and therefore never sees a partial code
/// point. It retains at most three bytes of an incomplete sequence between
/// chunks, exactly as the Node and Web stream adapters do.
#[derive(Debug, Default)]
pub struct Utf8ChunkDecoder {
    pending: Vec<u8>,
}

impl Utf8ChunkDecoder {
    pub fn new() -> Self {
        Self::default()
    }

    /// Decodes as much of `bytes` as completes a code point, retaining the
    /// rest. Panics only if the byte stream is not valid UTF-8, which a
    /// partition of a `&str` never is.
    pub fn decode(&mut self, bytes: &[u8]) -> String {
        self.pending.extend_from_slice(bytes);
        let decoded = match std::str::from_utf8(&self.pending) {
            Ok(text) => text.to_owned(),
            Err(error) => {
                assert!(
                    error.error_len().is_none(),
                    "a partition of valid UTF-8 produced invalid UTF-8",
                );
                let valid_up_to = error.valid_up_to();
                // SAFETY-FREE: `valid_up_to` is by definition a valid prefix.
                std::str::from_utf8(&self.pending[..valid_up_to])
                    .unwrap()
                    .to_owned()
            }
        };
        self.pending.drain(..decoded.len());
        decoded
    }

    /// Asserts the stream ended on a complete code point.
    pub fn finish(&self) {
        assert!(
            self.pending.is_empty(),
            "the byte stream ended inside a code point",
        );
    }
}

/// Decodes `chunks` of bytes into the `&str` pieces a host would hand the
/// core, one per byte chunk (empty pieces included, so a chunk that carries
/// only a partial code point still produces an `append` call).
pub fn decode_byte_chunks(chunks: &[&[u8]]) -> Vec<String> {
    let mut decoder = Utf8ChunkDecoder::new();
    let pieces: Vec<String> = chunks.iter().map(|chunk| decoder.decode(chunk)).collect();
    decoder.finish();
    pieces
}

// ---------------------------------------------------------------------------
// partition generators
// ---------------------------------------------------------------------------

/// Every two-chunk partition at a host-native `&str` boundary — that is, at
/// every UTF-8 byte index that is also a char boundary, the only positions
/// Rust's native string type can be divided at.
pub fn char_boundary_partitions(input: &str) -> Vec<[&str; 2]> {
    (0..=input.len())
        .filter(|index| input.is_char_boundary(*index))
        .map(|index| [&input[..index], &input[index..]])
        .collect()
}

/// Every two-chunk partition at *every* UTF-8 byte index, including indices
/// inside a multi-byte code point, decoded through [`Utf8ChunkDecoder`].
pub fn utf8_byte_partitions(input: &str) -> Vec<Vec<String>> {
    let bytes = input.as_bytes();
    (0..=bytes.len())
        .map(|index| decode_byte_chunks(&[&bytes[..index], &bytes[index..]]))
        .collect()
}

/// The maximally fragmented host-native partition: one chunk per character.
pub fn single_char_partition(input: &str) -> Vec<&str> {
    let mut chunks = Vec::new();
    let mut cursor = 0;
    for character in input.chars() {
        let end = cursor + character.len_utf8();
        chunks.push(&input[cursor..end]);
        cursor = end;
    }
    chunks
}

/// The maximally fragmented byte partition: one chunk per UTF-8 byte,
/// decoded through [`Utf8ChunkDecoder`].
pub fn single_byte_partition(input: &str) -> Vec<String> {
    let chunks: Vec<&[u8]> = input.as_bytes().chunks(1).collect();
    decode_byte_chunks(&chunks)
}

/// Borrows every piece of an owned partition so it can be handed to
/// [`run_session`].
pub fn as_chunks(pieces: &[String]) -> Vec<&str> {
    pieces.iter().map(String::as_str).collect()
}
