//! The `scan_cost` workloads (issue #981, extended by #1053–#1060).
//!
//! Used by the `scan_cost` bench. It names neither crate: only data and
//! generators.
//!
//! Every value below is synthetic. None is a real or revoked credential.

#![allow(
    dead_code,
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::must_use_candidate
)]

use std::fmt::Write as _;

/// The CLI's streaming read size (`secret-scan-cli/src/limits.rs`).
pub(crate) const CLI_CHUNK_BYTES: usize = 64 * 1024;
/// The CLI's construct limits, so the incremental path runs as the CLI does.
pub(crate) const CLI_MAX_TOKEN_BYTES: usize = 1024 * 1024;
pub(crate) const CLI_MAX_MULTILINE_BYTES: usize = 1024 * 1024;

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
pub(crate) enum ScanPath {
    Whole,
    Incremental(usize),
}

impl ScanPath {
    pub fn label(self) -> String {
        match self {
            Self::Whole => "whole".to_owned(),
            Self::Incremental(chunk) => format!("incremental-fixed{chunk}"),
        }
    }
}

/// Which registry a workload scans with.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum RegistryKind {
    /// `DetectorRegistry::with_built_in([])`.
    BuiltIn,
    /// `DetectorRegistry::with_built_in_and_pii` with the selection `["pii"]`.
    BuiltInAndPii,
}

pub(crate) struct Workload {
    pub name: &'static str,
    pub description: &'static str,
    pub generate: fn() -> String,
    pub paths: &'static [ScanPath],
    pub registry: RegistryKind,
}

const WHOLE_AND_CLI: &[ScanPath] = &[ScanPath::Whole, ScanPath::Incremental(CLI_CHUNK_BYTES)];

const KIB64: usize = 64 * 1024;
const KIB256: usize = 256 * 1024;

pub(crate) const WORKLOADS: &[Workload] = &[
    Workload {
        name: "scale-logs-64k",
        description: "assessment-filler-density-v1 logs, 64 KiB, 4 placeholder secrets/KiB (benchmarks small-whole row)",
        generate: || filler_density(LOGS_FILLER, KIB64),
        paths: WHOLE_AND_CLI,
        registry: RegistryKind::BuiltIn,
    },
    Workload {
        name: "scale-logs-256k",
        description: "assessment-filler-density-v1 logs, 256 KiB, 4 placeholder secrets/KiB (benchmarks medium-fixed4096 row)",
        generate: || filler_density(LOGS_FILLER, KIB256),
        paths: &[
            ScanPath::Whole,
            ScanPath::Incremental(4096),
            ScanPath::Incremental(CLI_CHUNK_BYTES),
        ],
        registry: RegistryKind::BuiltIn,
    },
    Workload {
        name: "mixed-10m",
        description: "10 MiB cycling the eight assessment fillers (ASCII and Unicode), 1 detected secret/KiB",
        generate: mixed_text,
        paths: WHOLE_AND_CLI,
        registry: RegistryKind::BuiltIn,
    },
    Workload {
        name: "minified-json-64k",
        description: "one-line minified JSON, 64 KiB, no newline (#989)",
        generate: || minified_json(KIB64),
        paths: WHOLE_AND_CLI,
        registry: RegistryKind::BuiltIn,
    },
    Workload {
        name: "minified-json-256k",
        description: "one-line minified JSON, 256 KiB, no newline (#989)",
        generate: || minified_json(KIB256),
        paths: WHOLE_AND_CLI,
        registry: RegistryKind::BuiltIn,
    },
    Workload {
        name: "provider-tables-64k",
        description: "multi-line Heroku / Twilio / Confluent layouts between log lines, 64 KiB",
        generate: provider_tables,
        paths: WHOLE_AND_CLI,
        registry: RegistryKind::BuiltIn,
    },
    Workload {
        name: "unicode-invisible-64k",
        description: "non-ASCII text with invisible code points, some inside tokens, 64 KiB",
        generate: unicode_invisible,
        paths: WHOLE_AND_CLI,
        registry: RegistryKind::BuiltIn,
    },
    Workload {
        name: "open-assignment-whitespace-10k",
        description: "API_KEY= then 10,000 lines of eight spaces (#986)",
        generate: open_assignment_whitespace,
        paths: WHOLE_AND_CLI,
        registry: RegistryKind::BuiltIn,
    },
    Workload {
        name: "value-one-line-64k",
        description: "` value=x` repeated on one line, 64 KiB (#1054)",
        generate: || one_line(" value=x", KIB64),
        paths: WHOLE_AND_CLI,
        registry: RegistryKind::BuiltIn,
    },
    Workload {
        name: "value-one-line-256k",
        description: "` value=x` repeated on one line, 256 KiB (#1054)",
        generate: || one_line(" value=x", KIB256),
        paths: WHOLE_AND_CLI,
        registry: RegistryKind::BuiltIn,
    },
    Workload {
        name: "query-rescan-64k",
        description: "`?a=` repeated on one line, 64 KiB (#1055)",
        generate: || one_line("?a=", KIB64),
        paths: WHOLE_AND_CLI,
        registry: RegistryKind::BuiltIn,
    },
    Workload {
        name: "query-rescan-256k",
        description: "`?a=` repeated on one line, 256 KiB (#1055)",
        generate: || one_line("?a=", KIB256),
        paths: WHOLE_AND_CLI,
        registry: RegistryKind::BuiltIn,
    },
    Workload {
        name: "brace-rescan-64k",
        description: "`{a=x` repeated on one line, 64 KiB (#1055)",
        generate: || one_line("{a=x", KIB64),
        paths: WHOLE_AND_CLI,
        registry: RegistryKind::BuiltIn,
    },
    Workload {
        name: "brace-rescan-256k",
        description: "`{a=x` repeated on one line, 256 KiB (#1055)",
        generate: || one_line("{a=x", KIB256),
        paths: WHOLE_AND_CLI,
        registry: RegistryKind::BuiltIn,
    },
    Workload {
        name: "paren-rescan-64k",
        description: "`(a=` repeated on one line, 64 KiB (#1055)",
        generate: || one_line("(a=", KIB64),
        paths: WHOLE_AND_CLI,
        registry: RegistryKind::BuiltIn,
    },
    Workload {
        name: "paren-rescan-256k",
        description: "`(a=` repeated on one line, 256 KiB (#1055)",
        generate: || one_line("(a=", KIB256),
        paths: WHOLE_AND_CLI,
        registry: RegistryKind::BuiltIn,
    },
    Workload {
        name: "source-with-prefixes-64k",
        description: "code-like lines, one line of bare synthetic provider prefixes on top, 64 KiB (#1056, #1057)",
        generate: || source_with_prefixes(KIB64),
        paths: WHOLE_AND_CLI,
        registry: RegistryKind::BuiltIn,
    },
    Workload {
        name: "source-with-prefixes-256k",
        description: "code-like lines, one line of bare synthetic provider prefixes on top, 256 KiB (#1056, #1057)",
        generate: || source_with_prefixes(KIB256),
        paths: WHOLE_AND_CLI,
        registry: RegistryKind::BuiltIn,
    },
    Workload {
        name: "pii-long-line-64k",
        description: "one-line JSON with a labelled email and IPv4 at the end, PII registry, 64 KiB (#1058)",
        generate: || pii_long_line(KIB64),
        paths: WHOLE_AND_CLI,
        registry: RegistryKind::BuiltInAndPii,
    },
    Workload {
        name: "pii-long-line-256k",
        description: "one-line JSON with a labelled email and IPv4 at the end, PII registry, 256 KiB (#1058)",
        generate: || pii_long_line(KIB256),
        paths: WHOLE_AND_CLI,
        registry: RegistryKind::BuiltInAndPii,
    },
];

/// Splits on character boundaries into chunks of at most `maximum` bytes,
/// the `fixed-N` chunk profile of the assessment adapter.
pub(crate) fn partition(input: &str, maximum: usize) -> Vec<&str> {
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

// ------------------------------------------------------------ generators

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

/// 10 MiB of the eight mixed fillers with one detected line per KiB: the
/// `mixed-10m` workload, also the input shape of the binding benchmarks.
pub(crate) fn mixed_text() -> String {
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

/// `unit` repeated on one line, no newline, to at least `target` bytes.
fn one_line(unit: &str, target: usize) -> String {
    unit.repeat(target.div_ceil(unit.len()))
}

/// Bare provider prefixes, with no token body, so none of them is a
/// finding: each one only makes its detectors do their first-hit work.
const BARE_PREFIXES: &str = "tr_pat_ tr_dev_ xoxb- xoxp- xapp- ghp_ gho_ github_pat_ glpat- sk_live_ rk_live_ ntn_ secret_ sk-proj- sk-ant- AKIA ASIA SG. sntrys_ hf_ npm_ pypi- dop_v1_ shpat_ lin_api_ pk_live_ xai- gsk_ sq0atp- EAAB .atlasv1. AIza ya29. dapi phx_ ATATT\n";

/// Code-like lines (Rust, TypeScript, YAML, prose comments) under one line
/// of bare provider prefixes.
fn source_with_prefixes(target: usize) -> String {
    const SOURCE: [&str; 8] = [
        "pub fn compute_fixture_total(values: &[u64]) -> u64 {\n",
        "    values.iter().copied().fold(0, |total, value| total + value)\n",
        "}\n",
        "// Returns the configured region, or the default one when unset.\n",
        "export const fixtureRegion = (config) => config.region ?? \"us-east-1\";\n",
        "  retries: 3\n  timeout_ms: 1500\n",
        "#[derive(Debug, Clone)] struct FixtureRow { id: usize, name: String }\n",
        "    let label = format!(\"fixture-{}\", row.id);\n",
    ];
    let mut input = String::with_capacity(target + 256);
    input.push_str(BARE_PREFIXES);
    let mut line = 0usize;
    while input.len() < target {
        input.push_str(SOURCE[line % SOURCE.len()]);
        line += 1;
    }
    input
}

/// One line of minified JSON records with a labelled email and a labelled
/// private IPv4 address at its end, in the synthetic shapes of the
/// `pii-email-v1` and `pii-network-address-v1` fixtures.
fn pii_long_line(target: usize) -> String {
    const TAIL: &str =
        ",{\"email\": \"fixture876-q7m9@x4z8v2n6.synthetic\", \"client_ip\": \"192.168.1.7\"}]}";
    let mut input = String::with_capacity(target + TAIL.len());
    input.push_str("{\"items\":[");
    let mut index = 0usize;
    while input.len() + TAIL.len() < target {
        if index > 0 {
            input.push(',');
        }
        let _ = write!(
            input,
            "{{\"id\":{index},\"status\":\"ok\",\"note\":\"fixture row {index} completed\"}}"
        );
        index += 1;
    }
    input.push_str(TAIL);
    input
}
