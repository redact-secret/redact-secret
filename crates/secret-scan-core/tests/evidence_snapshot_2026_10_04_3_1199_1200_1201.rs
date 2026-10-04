//! Product dispositions for the credential-evidence `snapshot-2026.10.04.3`
//! failures queued by redact-secret#1199 (`SendGrid`), #1200 (generic-token)
//! and #1201 (connection-string), driven through the public default pipeline.
//!
//! The replay scanned `@redact-secret/core@0.1.0-beta.12`; beta.13 and the
//! commit these tests ship in return the same findings on every failing case,
//! so none of the failures is a beta.13 regression. Every input here is
//! independently re-authored and synthetic; the evidence case ids are pinned
//! by name only. Three groups:
//!
//! * #1201 `generic-connection-grammar-authored--amqp-uri-all-sub-delimiters`
//!   is an in-contract defect, fixed in `connection_string.rs`: a `'` is a
//!   valid unencoded userinfo sub-delimiter that the authority scan treated
//!   as a terminator.
//! * #1199/#1200 fragmented and encoded carriers are outside the raw-input
//!   contract (`decision-define-fragmented-credentials-as-outside-the-raw-input-contract`
//!   and `decision-defer-encoded-input-decoding`). These tests pin that
//!   contract: the split or encoded form claims no `SendGrid` key, and the same
//!   key unsplit in the same carrier is still redacted exactly.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod support;

use redact_secret::{Action, Finding};
use support::{as_chunks, run, utf8_byte_partitions, whole_input};

/// `len` bytes cycled from `alphabet` with a stride, so the value is not a
/// run of one character and carries no provider marker of its own.
fn synthetic(alphabet: &[u8], len: usize, seed: usize) -> String {
    (0..len)
        .map(|i| char::from(alphabet[(i * 7 + seed) % alphabet.len()]))
        .collect()
}

const URL_SAFE: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789_-";

/// Whole-input findings, and the same result under every two-chunk byte
/// partition and a line-per-chunk partition.
fn findings_with_parity(input: &str) -> Vec<Finding> {
    let (expected_text, expected) = whole_input(input);
    for pieces in utf8_byte_partitions(input) {
        let session = run(&as_chunks(&pieces));
        assert_eq!(session.text(), expected_text, "{input:?}: {pieces:?}");
        assert_eq!(session.findings(), expected, "{input:?}: {pieces:?}");
    }
    let lines: Vec<&str> = input.split_inclusive('\n').collect();
    let session = run(&lines);
    assert_eq!(session.text(), expected_text, "{input:?}: per line");
    assert_eq!(session.findings(), expected, "{input:?}: per line");
    expected
}

fn span(input: &str, finding: &Finding) -> String {
    input[finding.range().start()..finding.range().end()].to_owned()
}

// ------------------------------------------------------------------ #1201

/// Every RFC 3986 sub-delimiter, `'` included, in one userinfo password.
const ALL_SUB_DELIMITERS: &str = "!$&'()*+,;=";

#[test]
fn issue_1201_amqp_uri_all_sub_delimiters_redacts_the_whole_password() {
    // Evidence case:
    // generic-connection-grammar-authored--amqp-uri-all-sub-delimiters
    let password = format!("Qv4{ALL_SUB_DELIMITERS}Nz7");
    let input = format!("amqp://worker:{password}@mq.example.net:5672/jobs\n");
    let findings = findings_with_parity(&input);
    assert_eq!(findings.len(), 1, "{findings:?}");
    assert_eq!(span(&input, &findings[0]), password);
    assert_eq!(findings[0].range().start(), "amqp://worker:".len());
    assert_eq!(findings[0].type_name(), "connection_string_password");
    assert_eq!(findings[0].action(), Action::Redact);
    let (sanitized, _) = whole_input(&input);
    assert!(!sanitized.contains(&password), "{sanitized:?}");
    assert!(
        sanitized.contains("@mq.example.net:5672/jobs"),
        "{sanitized:?}"
    );
}

#[test]
fn issue_1201_a_single_quote_anywhere_in_an_unquoted_userinfo_password() {
    for scheme in [
        "amqp", "amqps", "postgres", "mysql", "mongodb", "redis", "https",
    ] {
        for password in [
            "Kd5'Rw8Xq2Lm",
            "'Kd5Rw8Xq2Lm",
            "Kd5Rw8Xq2Lm'",
            "K'd'5'R'w'8'X'q'2",
        ] {
            let input = format!("{scheme}://worker:{password}@db.example.net:5432/jobs\n");
            let findings = findings_with_parity(&input);
            assert_eq!(findings.len(), 1, "{input:?}: {findings:?}");
            assert_eq!(span(&input, &findings[0]), password, "{input:?}");
        }
    }
}

#[test]
fn issue_1201_a_quote_opened_url_still_closes_at_its_quote() {
    // Complete-URL detection inside single quotes is unchanged.
    let input = "DATABASE_URL='amqp://worker:Kd5Rw8Xq2Lm@mq.example.net:5672/jobs'\n";
    let findings = findings_with_parity(input);
    assert_eq!(findings.len(), 1, "{findings:?}");
    assert_eq!(span(input, &findings[0]), "Kd5Rw8Xq2Lm");

    // A quoted URL list is not one authority: the first URL has no `@`, and
    // the `'` that closes it must not let the next item's `@` supply one.
    for input in [
        "urls = ['mysql://u:Pass1234word','a@b.example.com']\n",
        "urls = ['https://example.com:8080','a@b.example.com']\n",
    ] {
        let findings = findings_with_parity(input);
        assert!(findings.is_empty(), "{input:?}: {findings:?}");
    }
}

#[test]
fn issue_1201_the_host_never_contains_a_quote() {
    // After the `@` a `'` is a terminator again, so a trailing quote closes
    // the URL instead of invalidating its host.
    let input = "see amqp://worker:Kd5Rw8Xq2Lm@mq.example.net:5672'\n";
    let findings = findings_with_parity(input);
    assert_eq!(findings.len(), 1, "{findings:?}");
    assert_eq!(span(input, &findings[0]), "Kd5Rw8Xq2Lm");
}

#[test]
fn issue_1201_exclusions_survive_a_quote_inside_userinfo() {
    // Placeholder, reference and empty-password twins stay unclaimed whether
    // or not the password carries a quote.
    for input in [
        "amqp://worker:${AMQP_PASSWORD}@mq.example.net:5672/jobs\n",
        "amqp://worker:changeme@mq.example.net:5672/jobs\n",
        "amqp://worker@mq.example.net:5672/jobs\n",
        "amqp://worker:@mq.example.net:5672/jobs\n",
        "amqp://worker:Kd5'Rw8@@mq.example.net:5672/jobs\n",
    ] {
        let findings = findings_with_parity(input);
        assert!(findings.is_empty(), "{input:?}: {findings:?}");
    }
}

// ------------------------------------------------------------------ #1199

/// One mechanism that splits a `SendGrid` key: the carrier text before and after
/// the key, the separator the mechanism inserts between fragments, and where
/// the key is cut.
struct Split {
    case: &'static str,
    prefix: &'static str,
    separator: &'static str,
    suffix: &'static str,
    cuts: &'static [usize],
}

const CASE_PREFIX: &str = "line-break-and-fragment-authored--";

/// The sixteen `SendGrid` fragment cases that failed in `snapshot-2026.10.04.3`.
/// Their runtime meanings differ (a shell continuation joins, a backslash
/// inside single quotes does not, a literal line feed or a markdown soft
/// break inserts a separator); none is part of the raw-input contract.
const SPLITS: &[Split] = &[
    Split {
        case: "key-split-by-literal-crlf",
        prefix: "Pasted from the ticket: ",
        separator: "\r\n",
        suffix: "\r\n",
        cuts: &[40],
    },
    Split {
        case: "key-split-by-literal-line-feed",
        prefix: "Pasted from the ticket: ",
        separator: "\n",
        suffix: "\n",
        cuts: &[40],
    },
    Split {
        case: "key-wrapped-in-markdown-code-span",
        prefix: "Use `",
        separator: "\n",
        suffix: "` as the key.\n",
        cuts: &[40],
    },
    Split {
        case: "key-wrapped-in-markdown-paragraph",
        prefix: "Set the variable to the key ",
        separator: "\n",
        suffix: " before deploying.\n",
        cuts: &[40],
    },
    Split {
        case: "key-split-by-unquoted-shell-continuation",
        prefix: "SENDGRID_API_KEY=",
        separator: "\\\n",
        suffix: "\n",
        cuts: &[40],
    },
    Split {
        case: "key-split-after-prefix-by-shell-continuation",
        prefix: "SENDGRID_API_KEY=",
        separator: "\\\n",
        suffix: "\n",
        cuts: &[3],
    },
    Split {
        case: "key-split-before-last-character-by-shell-continuation",
        prefix: "SENDGRID_API_KEY=",
        separator: "\\\n",
        suffix: "\n",
        cuts: &[68],
    },
    Split {
        case: "key-split-by-backslash-crlf-continuation",
        prefix: "SENDGRID_API_KEY=",
        separator: "\\\r\n",
        suffix: "\r\n",
        cuts: &[40],
    },
    Split {
        case: "key-split-by-double-quoted-shell-continuation",
        prefix: "SENDGRID_API_KEY=\"",
        separator: "\\\n",
        suffix: "\"\n",
        cuts: &[26],
    },
    Split {
        case: "key-split-by-backslash-newline-in-single-quotes",
        prefix: "SENDGRID_API_KEY='",
        separator: "\\\n",
        suffix: "'\n",
        cuts: &[35],
    },
    Split {
        case: "key-split-by-javascript-literal-continuation",
        prefix: "const apiKey = '",
        separator: "\\\n",
        suffix: "';\n",
        cuts: &[30],
    },
    Split {
        case: "key-split-by-python-literal-continuation",
        prefix: "SENDGRID_API_KEY = \"",
        separator: "\\\n",
        suffix: "\"\n",
        cuts: &[35],
    },
    Split {
        case: "key-split-across-javascript-added-literals",
        prefix: "const apiKey = \"",
        separator: "\" + \"",
        suffix: "\";\n",
        cuts: &[30],
    },
    Split {
        case: "key-split-in-three-javascript-added-literals",
        prefix: "const apiKey = \"",
        separator: "\" + \"",
        suffix: "\";\n",
        cuts: &[3, 26],
    },
    Split {
        case: "key-split-across-python-adjacent-literals",
        prefix: "SENDGRID_API_KEY = (\n    \"",
        separator: "\"\n    \"",
        suffix: "\"\n)\n",
        cuts: &[35],
    },
    Split {
        case: "key-with-literal-backslash-n-in-log-line",
        prefix: "request failed key=",
        separator: "\\n",
        suffix: "\n",
        cuts: &[40],
    },
];

fn sendgrid_key() -> String {
    format!(
        "SG.{}.{}",
        synthetic(URL_SAFE, 22, 3),
        synthetic(URL_SAFE, 43, 8)
    )
}

fn split_input(split: &Split, key: &str) -> String {
    let mut out = String::from(split.prefix);
    let mut from = 0;
    for &cut in split.cuts {
        out.push_str(&key[from..cut]);
        out.push_str(split.separator);
        from = cut;
    }
    out.push_str(&key[from..]);
    out.push_str(split.suffix);
    out
}

fn sendgrid_findings(findings: &[Finding]) -> Vec<&Finding> {
    findings
        .iter()
        .filter(|finding| finding.type_name() == "sendgrid_api_key")
        .collect()
}

#[test]
fn issue_1199_fragmented_keys_are_outside_the_raw_input_contract() {
    let key = sendgrid_key();
    assert_eq!(key.len(), 69);
    assert_eq!(SPLITS.len(), 16);
    for split in SPLITS {
        let id = format!("{CASE_PREFIX}{}", split.case);

        // The complete key in the same carrier is redacted exactly.
        let mut joined = String::from(split.prefix);
        joined.push_str(&key);
        joined.push_str(split.suffix);
        let findings = findings_with_parity(&joined);
        let sendgrid = sendgrid_findings(&findings);
        assert_eq!(sendgrid.len(), 1, "{id}: {joined:?}: {findings:?}");
        assert_eq!(span(&joined, sendgrid[0]), key, "{id}");
        assert_eq!(sendgrid[0].action(), Action::Redact, "{id}");

        // The fragmented key claims no `SendGrid` finding: the core does not
        // reconstruct a key across lines, literals or continuations.
        let fragmented = split_input(split, &key);
        let findings = findings_with_parity(&fragmented);
        assert!(
            sendgrid_findings(&findings).is_empty(),
            "{id}: {fragmented:?}: {findings:?}"
        );
    }
}

#[test]
fn issue_1199_a_backslash_in_single_quotes_is_not_a_shell_continuation() {
    // `'...\<LF>...'` keeps the backslash and the newline as value bytes, so
    // the quoted value is not the `SendGrid` key and must not be read as one.
    let key = sendgrid_key();
    let input = format!("SENDGRID_API_KEY='{}\\\n{}'\n", &key[..35], &key[35..]);
    let findings = findings_with_parity(&input);
    assert!(sendgrid_findings(&findings).is_empty(), "{findings:?}");
}

// ------------------------------------------------------------ #1199, #1200

const BASE64_STD: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const BASE64_URL: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

fn base64(bytes: &[u8], alphabet: &[u8; 64], padded: bool) -> String {
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        let sextets = [(n >> 18) & 63, (n >> 12) & 63, (n >> 6) & 63, n & 63];
        for (index, sextet) in sextets.iter().enumerate() {
            if index <= chunk.len() {
                out.push(char::from(alphabet[*sextet as usize]));
            } else if padded {
                out.push('=');
            }
        }
    }
    out
}

fn hex(bytes: &[u8], upper: bool, mixed: bool) -> String {
    bytes
        .iter()
        .enumerate()
        .map(|(index, byte)| {
            if upper || (mixed && index % 2 == 1) {
                format!("{byte:02X}")
            } else {
                format!("{byte:02x}")
            }
        })
        .collect()
}

/// Applies one codec named like the evidence ids (`base64-standard-padded`,
/// `base64-url-safe-unpadded`, `hex-lower`, `hex-upper`, `hex-mixed`).
fn encode(codec: &str, bytes: &[u8]) -> String {
    match codec {
        "base64-standard-padded" => base64(bytes, BASE64_STD, true),
        "base64-standard-unpadded" => base64(bytes, BASE64_STD, false),
        "base64-url-safe-padded" => base64(bytes, BASE64_URL, true),
        "base64-url-safe-unpadded" => base64(bytes, BASE64_URL, false),
        "hex-lower" => hex(bytes, false, false),
        "hex-upper" => hex(bytes, true, false),
        "hex-mixed" => hex(bytes, false, true),
        other => panic!("unknown codec {other}"),
    }
}

/// The encoding layers of an evidence id's `<outer>-of-<inner>...` suffix,
/// applied innermost first.
fn encode_layers(layers: &str, plain: &str) -> String {
    let codecs: Vec<&str> = if layers == "base64-standard-padded-three-layers" {
        vec!["base64-standard-padded"; 3]
    } else {
        layers.split("-of-").collect()
    };
    let mut value = plain.to_owned();
    for codec in codecs.iter().rev() {
        value = encode(codec, value.as_bytes());
    }
    value
}

fn carrier(kind: &str, value: &str) -> String {
    match kind {
        "env" => format!("ENCODED_VALUE={value}\n"),
        "json" => format!("{{\"event\":\"config-sync\",\"payload\":\"{value}\"}}\n"),
        "url" => format!("https://example.invalid/callback?payload={value}\n"),
        other => panic!("unknown carrier {other}"),
    }
}

const ENCODED_PREFIX: &str = "base64-hex-representation-projections--";

/// The thirteen `SendGrid` and thirty-six generic `snapshot-2026.10.04.3`
/// encoded-carrier cases that failed, as `<layers>-in-<carrier>`.
const ENCODED_SENDGRID: &[&str] = &[
    "base64-standard-padded-in-env",
    "base64-standard-padded-in-json",
    "base64-standard-padded-in-url",
    "base64-standard-padded-three-layers-in-env",
    "base64-url-safe-unpadded-of-base64-standard-padded-in-env",
    "base64-url-safe-unpadded-of-hex-upper-of-base64-standard-padded-in-json",
    "hex-lower-in-env",
    "hex-lower-in-url",
    "hex-lower-of-base64-standard-padded-in-env",
    "hex-lower-of-hex-lower-in-env",
    "hex-mixed-in-env",
    "hex-upper-in-env",
    "hex-upper-in-json",
];

/// The generic literal cases add the unpadded, url-safe-padded and
/// url-safe-unpadded plain base64 forms.
const ENCODED_GENERIC: &[&str] = &[
    "base64-standard-padded-in-env",
    "base64-standard-padded-in-json",
    "base64-standard-padded-in-url",
    "base64-standard-padded-three-layers-in-env",
    "base64-standard-unpadded-in-env",
    "base64-url-safe-padded-in-env",
    "base64-url-safe-unpadded-in-env",
    "base64-url-safe-unpadded-in-json",
    "base64-url-safe-unpadded-in-url",
    "base64-url-safe-unpadded-of-base64-standard-padded-in-env",
    "base64-url-safe-unpadded-of-hex-upper-of-base64-standard-padded-in-json",
    "hex-lower-in-env",
    "hex-lower-in-url",
    "hex-lower-of-base64-standard-padded-in-env",
    "hex-lower-of-hex-lower-in-env",
    "hex-mixed-in-env",
    "hex-upper-in-env",
    "hex-upper-in-json",
];

fn split_layers_and_carrier(suffix: &str) -> (&str, &str) {
    let at = suffix.rfind("-in-").expect("carrier");
    (&suffix[..at], &suffix[at + 4..])
}

#[test]
fn issue_1199_encoded_sendgrid_keys_are_not_decoded() {
    let key = sendgrid_key();
    assert_eq!(ENCODED_SENDGRID.len(), 13);
    for suffix in ENCODED_SENDGRID {
        let id = format!("{ENCODED_PREFIX}sendgrid-key-{suffix}");
        let (layers, kind) = split_layers_and_carrier(suffix);

        // The plaintext key in the same carrier is redacted exactly.
        let plain = carrier(kind, &key);
        let findings = findings_with_parity(&plain);
        let sendgrid = sendgrid_findings(&findings);
        assert_eq!(sendgrid.len(), 1, "{id}: {plain:?}: {findings:?}");
        assert_eq!(span(&plain, sendgrid[0]), key, "{id}");

        // The encoded form has no raw detection: decoding is deferred
        // (`decision-defer-encoded-input-decoding`), and an encoded run under
        // a non-credential name or a neutral query parameter is not a
        // contextual assignment.
        let encoded = carrier(kind, &encode_layers(layers, &key));
        let findings = findings_with_parity(&encoded);
        assert!(findings.is_empty(), "{id}: {encoded:?}: {findings:?}");
    }
}

#[test]
fn issue_1200_encoded_generic_literals_are_not_decoded() {
    let literal = "SYNTHETIC~NEVER-ISSUED?EXAMPLE.BASE64.HEX";
    assert_eq!(ENCODED_GENERIC.len(), 18); // 18 alphabet-edge + 16 padding-edge cases
    for suffix in ENCODED_GENERIC {
        for edge in ["alphabet-edge", "padding-edge"] {
            // The padding-edge base has no plain unpadded or url-safe padded form.
            if edge == "padding-edge"
                && matches!(
                    *suffix,
                    "base64-standard-unpadded-in-env" | "base64-url-safe-padded-in-env"
                )
            {
                continue;
            }
            let id = format!("{ENCODED_PREFIX}generic-literal-{edge}-{suffix}");
            let (layers, kind) = split_layers_and_carrier(suffix);
            let encoded = carrier(kind, &encode_layers(layers, literal));
            let findings = findings_with_parity(&encoded);
            assert!(findings.is_empty(), "{id}: {encoded:?}: {findings:?}");
        }
    }

    // Positive preservation: the same literal under a credential name is
    // still a contextual secret, so the generic contract is unchanged.
    for input in [
        format!("api_key = \"{literal}\"\n"),
        format!("SECRET_TOKEN={literal}\n"),
    ] {
        let findings = findings_with_parity(&input);
        assert_eq!(findings.len(), 1, "{input:?}: {findings:?}");
        assert_eq!(span(&input, &findings[0]), literal);
        assert_eq!(findings[0].type_name(), "contextual_secret");
    }
}

#[test]
fn issue_1200_unsettled_assignment_bases_stay_unclaimed() {
    // `policy-ambiguous-assignment-bases-authored--*` and their generated
    // projections carry no expectation (evidence class `unresolved`; the
    // scored status is review-required, not failed): the bare sample words
    // are non-secret by the generic-token value exclusions.
    for input in [
        "access_token=SAMPLE\n",
        "API_KEY=EXAMPLE_API_KEY\n",
        "password=EXAMPLE\n",
        "secret: SAMPLE\n",
    ] {
        let findings = findings_with_parity(input);
        assert!(findings.is_empty(), "{input:?}: {findings:?}");
    }
}
