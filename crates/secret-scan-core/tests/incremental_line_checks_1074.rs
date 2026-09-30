//! Chunk-split equivalence over generated line-oriented text (issue #1074).
//!
//! The per-closed-line retention hints (lookback window, private-key
//! tracker, Heroku command judgment, unit release fast path) must not change
//! what the incremental session releases: for random partitions of generated
//! text the concatenated output and every finding equal the whole-input
//! result. Every value is synthetic. The generator's vocabulary deliberately
//! omits one provider's word (a known, separately tracked defect).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod support;

use support::{run, whole_input};

/// Generated cases per run. Raised to 20000 for a one-off soak, then restored.
const CASES: usize = 300;

const PARTS: &[&str] = &[
    "heroku",
    "auth:token",
    "authorizations:info",
    "$ heroku auth:token",
    "$ heroku authorizations:create",
    "Client:  synthetic",
    "Token:   00000000-0000-0000-0000-000000000000",
    "00000000-0000-0000-0000-000000000000",
    "HEROKU_API_KEY=",
    "twilio",
    "Account SID  Auth Token",
    "-----BEGIN PRIVATE KEY-----",
    "-----END PRIVATE KEY-----",
    "-----BEGIN RSA PRIVATE KEY-----",
    "-----END RSA PRIVATE KEY-----",
    "-----BEGIN ",
    "-----",
    "--",
    "U1lOVEhFVElDX1JFVk9LRURfRklYVFVSRQ==",
    "AWS_SECRET_ACCESS_KEY=",
    "AKIASYNTHETIC0TEST00",
    "SYNTHETICxREVOKEDxTESTx0000000000000000000",
    "password=SYNTH_REVOKED_42",
    "api_key",
    "Authorization: Bearer",
    "ghp_SYNTHETICxREVOKEDxTESTx0000000000000",
    "deepgram",
    "- ",
    "=",
    ":",
    " ",
    "  ",
    "\t",
    "\n",
    "\n",
    "\r\n",
    "\r",
    "\u{e9}",
    "\u{200b}",
    "\u{1f511}",
    "value",
];

struct Rng(u64);

impl Rng {
    fn next(&mut self, bound: usize) -> usize {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        usize::try_from(self.0 % u64::try_from(bound).unwrap()).unwrap()
    }
}

fn generate(rng: &mut Rng) -> String {
    let mut text = String::new();
    for _ in 0..rng.next(40) {
        text.push_str(PARTS[rng.next(PARTS.len())]);
        if rng.next(4) == 0 {
            text.push(' ');
        }
    }
    text
}

fn partition<'a>(text: &'a str, rng: &mut Rng) -> Vec<&'a str> {
    let mut chunks = Vec::new();
    let mut rest = text;
    let widest = [1, 3, 17, 80][rng.next(4)];
    while !rest.is_empty() {
        let mut cut = (1 + rng.next(widest)).min(rest.len());
        while !rest.is_char_boundary(cut) {
            cut += 1;
        }
        let (piece, tail) = rest.split_at(cut);
        chunks.push(piece);
        rest = tail;
    }
    chunks
}

#[test]
fn any_partition_of_generated_line_text_equals_the_whole_input_result() {
    let mut rng = Rng(0x1074_D00D_5EED_0001);
    for case in 0..CASES {
        let text = generate(&mut rng);
        let (expected_text, expected_findings) = whole_input(&text);
        for _ in 0..2 {
            let chunks = partition(&text, &mut rng);
            let session = run(&chunks);
            assert_eq!(session.text(), expected_text, "case {case}: text");
            assert_eq!(
                session.findings(),
                expected_findings,
                "case {case}: findings"
            );
        }
    }
}
