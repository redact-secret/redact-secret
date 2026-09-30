//! Contextual assignment, structural `Basic`/`Token`/`Key` authorization, and a
//! bare vendor-prefixed high-entropy policy layer.
//!
//! Combines explicit credential names or authorization syntax with bounded
//! entropy. A plain `token` name and entropy-only text intentionally produce
//! no candidates. Values above 4 KiB are left to more specific detectors.

use super::pattern::{self, PrefixShape};
use super::text::{
    OPENCODE_REFERENCE_OPENERS, ascii_run_len, char_at, ends_with_ci,
    is_command_substitution_reference, is_env_var_identifier, is_fully_delimited,
    is_glued_instructional_placeholder, is_glued_my_placeholder, is_horizontal_js_whitespace,
    is_instructional_token_placeholder, is_js_whitespace, is_lead_word_phrase_placeholder,
    is_line_start, is_opencode_reference, is_repeated_character_filler,
    is_ruby_interpolation_reference, is_template_reference, is_windows_env_reference,
    matches_placeholder_vocabulary, prev_char, rskip_while_chars, skip_while_chars,
    starts_with_bare_dollar_reference, starts_with_ci, starts_with_digest_label,
};
use crate::error::DetectorFailure;
use crate::types::{ByteRange, Candidate, Confidence, Detector, DetectorContext, Specificity};

const HIGH_SIGNAL_NAMES: &[&str] = &[
    "api_key",
    "apikey",
    "secret",
    "secret_key",
    "access_token",
    "refresh_token",
    "session_token",
    "aws_secret_access_key",
    // The unprefixed AWS API member (`"SecretAccessKey"` in STS, IAM and
    // CloudFormation JSON, `secretAccessKey` in the SDKs), issue #1026.
    "secret_access_key",
    "aws_session_token",
    "password",
    "passwd",
    "private_key",
    "client_secret",
    "webhook_secret",
    // An `auth_token` assignment names a credential (Twilio calls its
    // account secret the "Auth Token"); ambiguous until issue #941.
    "auth_token",
    // RFC 7636 PKCE verifier: the secret half of the code challenge
    // (issue #816).
    "code_verifier",
];

/// High-signal names matched only as the whole normalized name, never as the
/// suffix of a prefixed name: `pass` alone is an ordinary identifier segment
/// (`render_pass`, `first_pass`, `second_pass`), but `db_pass` is the
/// conventional database password variable (`DB_PASS`, `dbPass`). A
/// further-prefixed `app_db_pass` is not matched (issue #823).
///
/// Issue #919 adds three provider credential variables whose only
/// distinguishing segment is a bare `_key` suffix, which is deliberately not
/// a name token (`sort_key`, `cache_key`, `primary_key`, `partition_key` and
/// `idempotency_key` hold non-secrets): `fal_key` (fal's documented and only
/// credential variable, `FAL_KEY`), and Convex's `convex_deploy_key` and
/// `convex_self_hosted_admin_key`. Only these whole names match; `fal_key_id`
/// (the public id half), `convex_key` and `my_fal_key` do not.
const EXACT_HIGH_SIGNAL_NAMES: &[&str] = &[
    "db_pass",
    "fal_key",
    "convex_deploy_key",
    "convex_self_hosted_admin_key",
];

const AMBIGUOUS_NAMES: &[&str] = &["auth", "credential", "credentials", "signing_key"];

/// Names that are credential-bearing only as a URL query, fragment or form
/// parameter (`?code=`, `&code=`), and then only in the ambiguous bucket:
/// the OAuth 2.0 authorization code (RFC 6749 section 4.1.2). Anywhere else
/// `code` is a status, error or country code (issue #816).
const QUERY_ONLY_AMBIGUOUS_NAMES: &[&str] = &["code"];

/// `<prefix>_token` names that hold a request-scoped or public value rather
/// than a credential. Every other prefixed `_token` name is high-signal
/// (issue #702).
const NON_CREDENTIAL_TOKEN_NAMES: &[&str] = &[
    "csrf_token",
    "xsrf_token",
    "page_token",
    "next_page_token",
    "prev_page_token",
    "pagination_token",
    "continuation_token",
    "cancel_token",
    "cancellation_token",
    "sync_token",
    "resume_token",
    "device_token",
    "push_token",
];

/// Names whose value names a Kubernetes Secret *object* rather than holding
/// a secret: the Helm-chart `existingSecret` convention (`auth.existingSecret:
/// postgres-credentials`) and its `existingSecretName` spelling. Matched as
/// the whole name or behind a prefix (`redis_auth_existing_secret`), so the
/// `<prefix>_secret` rule no longer reads them as credentials (issue #911).
/// `secretName` was never a credential name (it ends in `name`).
const OBJECT_REFERENCE_SECRET_NAMES: &[&str] = &["existing_secret", "existing_secret_name"];

/// Name segments that name a provider with its own built-in detector
/// (`MAILCHIMP_API_KEY`, `GITHUB_TOKEN`, `DD_API_KEY`).
///
/// Issue #702 made such a prefix disqualify every name, so the provider
/// detector's contract alone decided and a value it declined got no finding.
/// Since issue #948 a provider-prefixed *high-signal* name is claimed like a
/// generic one ([`has_prefixed_credential_name`]): the provider detector
/// still takes an on-grammar value through overlap resolution (provider
/// specificity over contextual), and `generic-token` reports the value its
/// grammar declines (format drift, a sibling key type, a truncated paste).
/// A provider-prefixed *ambiguous* name (`GITHUB_CREDENTIALS`) still does
/// not qualify.
pub(super) const DEDICATED_PROVIDER_SEGMENTS: &[&str] = &[
    "anthropic",
    "atlassian",
    "jira",
    "confluence",
    "cloudflare",
    "cf",
    "confluent",
    "databricks",
    "datadog",
    "dd",
    "digitalocean",
    "discord",
    "docker",
    "dockerhub",
    "fireworks",
    "github",
    "gh",
    "gitlab",
    "grafana",
    "groq",
    "heroku",
    "huggingface",
    "hf",
    "langfuse",
    "langsmith",
    "langchain",
    "linear",
    "mailchimp",
    "mailgun",
    "neon",
    "netlify",
    "newrelic",
    "notion",
    "npm",
    "okta",
    "openai",
    "openrouter",
    "perplexity",
    "pplx",
    "pinecone",
    "postman",
    "pulumi",
    "pypi",
    "replicate",
    "sendgrid",
    "sentry",
    "shopify",
    "slack",
    "stripe",
    "supabase",
    "telegram",
    "terraform",
    "travis",
    "travisci",
    "twilio",
    "vault",
    "vercel",
    "xai",
];

/// Multi-segment spellings of [`DEDICATED_PROVIDER_SEGMENTS`] entries.
const DEDICATED_PROVIDER_PHRASES: &[&str] = &["new_relic", "digital_ocean", "hugging_face"];

/// First name segments that say the value is not the secret itself
/// (`redacted_api_key`, `hashed_token`, `publishable_key`).
const NON_SECRET_NAME_LEADS: &[&str] = &[
    "redacted",
    "masked",
    "hashed",
    "hash",
    "obfuscated",
    "truncated",
    "sanitized",
    "publishable",
];

/// `true` when a prefixed name's first segment says the value is not the
/// secret itself (`redacted_api_key`, `hashed_token`, `publishable_key`).
fn prefix_says_not_secret(normalized: &str) -> bool {
    normalized
        .split('_')
        .next()
        .is_some_and(|lead| NON_SECRET_NAME_LEADS.contains(&lead))
}

/// Non-secret leads whose name alone never excludes a value: the name says
/// what the field should hold, not what it holds (issue #1018). Only
/// `publishable` is left out, since a publishable key is public by the
/// provider's own documentation.
const VALUE_CHECKED_NAME_LEADS: &[&str] = &[
    "redacted",
    "masked",
    "hashed",
    "hash",
    "obfuscated",
    "truncated",
    "sanitized",
];

/// Leads that say the value is a digest rather than a mask.
const HASH_NAME_LEADS: &[&str] = &["hashed", "hash"];

/// Hex lengths of the common digests (MD5, SHA-1, SHA-224, SHA-256,
/// SHA-384, SHA-512).
const HEX_DIGEST_LENGTHS: &[usize] = &[32, 40, 56, 64, 96, 128];

/// Shortest run of one `x`/`X` that reads as a mask under a masking lead.
const MIN_X_MASK_RUN: usize = 4;

/// `true` when `value` itself shows it was masked or hashed, under a name
/// led by `lead` ([`VALUE_CHECKED_NAME_LEADS`]): any `*`, `•` or `…`, a
/// `...` gap, a run of four or more `x`/`X`, a `redacted`/`masked` word, a
/// digest label (`sha256:`), and under a hash lead a hex digest of a common
/// length or a `$`-delimited crypt string (`$2b$12$...`).
fn value_shows_masking_or_hashing(lead: &str, value: &str) -> bool {
    let bytes = value.as_bytes();
    let lower = value.to_ascii_lowercase();
    let x_run = bytes
        .chunk_by(|left, right| left == right)
        .any(|run| matches!(run[0], b'x' | b'X') && run.len() >= MIN_X_MASK_RUN);
    let shows_mask = value.contains(['*', '\u{2022}', '\u{2026}'])
        || value.contains("...")
        || x_run
        || lower.contains("redacted")
        || lower.contains("masked")
        || starts_with_digest_label(value);
    if shows_mask {
        return true;
    }
    HASH_NAME_LEADS.contains(&lead)
        && ((HEX_DIGEST_LENGTHS.contains(&value.len()) && bytes.iter().all(u8::is_ascii_hexdigit))
            || (value.starts_with('$') && value[1..].contains('$')))
}

/// The name a value-checked lead stands in front of (`masked_api_key` reads
/// `api_key`), when the lead is one of [`VALUE_CHECKED_NAME_LEADS`] and a
/// name follows it. Issue #1018 narrowed
/// `decision-redact-provider-named-credential-assignments` section 2: a
/// `masked_`/`redacted_`/`hashed_`-led name excludes a value only when the
/// value itself shows masking or hashing
/// ([`value_shows_masking_or_hashing`]); a complete, unmasked value under it
/// is judged under the name the lead stands in front of.
fn value_checked_lead_rest(normalized: &str) -> Option<(&str, &str)> {
    let (lead, rest) = normalized.split_once('_')?;
    (VALUE_CHECKED_NAME_LEADS.contains(&lead) && !rest.is_empty()).then_some((lead, rest))
}

/// `true` when `normalized` is led by a value-checked lead
/// ([`value_checked_lead_rest`]) and `value` does not show masking or
/// hashing, so the value is judged as a credential. Shared with the
/// keyword-gated detectors (issue #1018).
pub(super) fn is_unmasked_under_masking_lead(normalized: &str, value: &str) -> bool {
    value_checked_lead_rest(normalized)
        .is_some_and(|(lead, _)| !value_shows_masking_or_hashing(lead, value))
}

/// `true` when `normalized` opens with a lead that says the value is not
/// the secret and `value` bears that out: `publishable_` always, a
/// value-checked lead ([`VALUE_CHECKED_NAME_LEADS`]) only when the value
/// shows masking or hashing (issue #1018).
pub(super) fn masking_lead_hides_value(normalized: &str, value: &str) -> bool {
    normalized.split('_').next() == Some("publishable")
        || value_checked_lead_rest(normalized)
            .is_some_and(|(lead, _)| value_shows_masking_or_hashing(lead, value))
}

/// `true` when a name carries a provider with a dedicated detector
/// ([`DEDICATED_PROVIDER_SEGMENTS`], [`DEDICATED_PROVIDER_PHRASES`]).
fn names_dedicated_provider(normalized: &str) -> bool {
    normalized
        .split('_')
        .any(|segment| DEDICATED_PROVIDER_SEGMENTS.contains(&segment))
        || DEDICATED_PROVIDER_PHRASES
            .iter()
            .any(|phrase| normalized.contains(phrase))
}

/// `true` when `normalized` is `<prefix>_<name>` for one of `names`, with a
/// non-empty prefix. The prefix is not checked.
fn ends_with_prefixed_name(normalized: &str, names: &[&str]) -> bool {
    names.iter().any(|name| {
        normalized.len() > name.len() + 1
            && normalized.ends_with(name)
            && normalized.as_bytes()[normalized.len() - name.len() - 1] == b'_'
    })
}

/// `true` when `normalized` is `<prefix>_<name>` for one of `names` and the
/// prefix neither names a provider with a dedicated detector nor says the
/// value is redacted, hashed or public: `app_credentials`. The ambiguous
/// bucket's prefix rule.
fn has_prefixed_name(normalized: &str, names: &[&str]) -> bool {
    ends_with_prefixed_name(normalized, names)
        && !prefix_says_not_secret(normalized)
        && !names_dedicated_provider(normalized)
}

/// `true` when `normalized` is `<prefix>_<name>` for one of `names` and the
/// prefix does not say the value is redacted, hashed or public:
/// `myapp_api_key`, `db_password`, `jwt_secret`, and since issue #948
/// `openai_api_key` and `stripe_secret_key`. The high-signal bucket's prefix
/// rule; see [`DEDICATED_PROVIDER_SEGMENTS`] for why a provider prefix
/// qualifies here.
fn has_prefixed_credential_name(normalized: &str, names: &[&str]) -> bool {
    ends_with_prefixed_name(normalized, names) && !prefix_says_not_secret(normalized)
}

/// `true` for a high-signal name: one of [`HIGH_SIGNAL_NAMES`] or
/// [`EXACT_HIGH_SIGNAL_NAMES`], the same
/// name behind a generic prefix (`MYAPP_API_KEY`, `DB_PASSWORD`,
/// `JWT_SECRET`), or a prefixed `_token` name outside
/// [`NON_CREDENTIAL_TOKEN_NAMES`] (`CI_DEPLOY_TOKEN`). A prefix that says
/// the value is not the secret does not qualify; a provider prefix does
/// since issue #948 (`OPENAI_API_KEY`, `GITHUB_TOKEN`); see
/// [`has_prefixed_credential_name`].
///
/// Issue #702: before this, only the bare names matched, so a secret under a
/// prefixed variable for a service with no dedicated detector got no finding
/// at all. The false-positive cost is a prefixed name holding a non-secret,
/// high-entropy value of at least eight bytes; placeholder, reference and
/// masked-value exclusions still apply unchanged.
pub(crate) fn is_high_signal_name(normalized: &str) -> bool {
    if is_object_reference_secret_name(normalized) {
        return false;
    }
    HIGH_SIGNAL_NAMES.contains(&normalized)
        || EXACT_HIGH_SIGNAL_NAMES.contains(&normalized)
        || has_prefixed_credential_name(normalized, HIGH_SIGNAL_NAMES)
        || (!AMBIGUOUS_NAMES.contains(&normalized)
            && has_prefixed_credential_name(normalized, &["token"])
            && !NON_CREDENTIAL_TOKEN_NAMES.contains(&normalized)
            && !ends_with_prefixed_name(normalized, NON_CREDENTIAL_TOKEN_NAMES))
}

/// `true` for an [`OBJECT_REFERENCE_SECRET_NAMES`] name, bare or prefixed.
fn is_object_reference_secret_name(normalized: &str) -> bool {
    OBJECT_REFERENCE_SECRET_NAMES.iter().any(|name| {
        normalized == *name
            || normalized
                .strip_suffix(name)
                .is_some_and(|prefix| prefix.ends_with('_'))
    })
}

/// `true` for an ambiguous name: one of [`AMBIGUOUS_NAMES`] or the same name
/// behind a generic prefix (`APP_CREDENTIALS`, not `GITHUB_CREDENTIALS`),
/// when it is not already [`is_high_signal_name`].
fn is_ambiguous_name(normalized: &str) -> bool {
    !is_high_signal_name(normalized) && is_ambiguous_vocabulary_name(normalized)
}

/// The vocabulary half of [`is_ambiguous_name`], for a caller that already
/// knows the name is not high-signal.
fn is_ambiguous_vocabulary_name(normalized: &str) -> bool {
    AMBIGUOUS_NAMES.contains(&normalized) || has_prefixed_name(normalized, AMBIGUOUS_NAMES)
}

const MIN_CONTEXT_VALUE_LENGTH: usize = 8;
const MIN_HIGH_ENTROPY_LENGTH: usize = 16;
const HIGH_ENTROPY_THRESHOLD: f64 = 3.0;
const AMBIGUOUS_ENTROPY_THRESHOLD: f64 = 3.5;
const MAX_CONTEXT_VALUE_LENGTH: usize = 4_096;
const MIN_AUTHORIZATION_VALUE_LENGTH: usize = 12;

// --- name normalization -----------------------------------------------

/// Mirrors `name.replace(/([a-z0-9])([A-Z])/g, "$1_$2").toLowerCase().replace(/[.-]/g, "_")`.
///
/// Capture names are `[A-Za-z][A-Za-z0-9_.-]*`, so this operates on ASCII
/// bytes only. Also the comparison key the declarative ruleset's names
/// section normalizes a caller-supplied `name:` value to before checking it
/// against [`HIGH_SIGNAL_NAMES`]/[`AMBIGUOUS_NAMES`]
/// (`crate::ruleset`, issue #484): the same function, applied to the same
/// kind of input, so a ruleset author's `CorpPassphrase` and a scanned input's
/// `CorpPassphrase=` assignment normalize to the identical key.
pub(crate) fn normalize_name(name: &str) -> String {
    let mut out = String::with_capacity(name.len() + 4);
    normalize_name_into(name, &mut out);
    out
}

/// [`normalize_name`] written into `out`, replacing its contents, so a loop
/// can reuse one buffer instead of allocating per name (issue #984).
fn normalize_name_into(name: &str, out: &mut String) {
    out.clear();
    let bytes = name.as_bytes();
    for (index, &byte) in bytes.iter().enumerate() {
        if index > 0 {
            let previous = bytes[index - 1];
            let previous_is_lower_or_digit =
                previous.is_ascii_lowercase() || previous.is_ascii_digit();
            if previous_is_lower_or_digit && byte.is_ascii_uppercase() {
                out.push('_');
            }
        }
        out.push(match byte {
            b'.' | b'-' => '_',
            other => other.to_ascii_lowercase() as char,
        });
    }
}

fn is_open_assignment_boundary_char(ch: char) -> bool {
    // `?`, `&` and `#` open a URL query, fragment or form parameter
    // (issue #816).
    // `(` opens a single-line call whose keyword argument is the assignment
    // (`Client(api_key="...")`, issue #866).
    is_js_whitespace(ch) || matches!(ch, '{' | '(' | ',' | ';' | '?' | '&' | '#')
}

/// `true` when `normalized` (already passed through [`normalize_name`]) is
/// already one of the built-in [`HIGH_SIGNAL_NAMES`]/[`AMBIGUOUS_NAMES`]
/// entries. The declarative ruleset's names section uses this to make a
/// caller-supplied name that normalizes to an existing built-in name a
/// no-op rather than a duplicate entry or an error (issue #484, point 2:
/// a caller cannot remove, override, or re-bucket a built-in name).
#[must_use]
pub(crate) fn is_reserved_name(normalized: &str) -> bool {
    is_high_signal_name(normalized) || is_ambiguous_name(normalized)
}

/// The fixed, reserved id of the internal detector the declarative
/// ruleset's names section registers when a ruleset adds ambiguous-bucket
/// names (issue #484). Never a caller's choice: `crate::ruleset`'s
/// `detector:` block parser rejects this id the same way it rejects every
/// other built-in id, so a ruleset cannot collide with it.
pub(crate) const RULESET_NAMES_DETECTOR_ID: &str = "generic-token-ruleset-names";

/// Internal retention hint for the built-in incremental scanner: `true` when
/// the tail of `input` still looks like an in-progress contextual assignment
/// whose name is high-signal or ambiguous, so a caller should keep holding
/// the line open in case a bounded-entropy value follows. Mirrors
/// `hasOpenContextualAssignment` in `src/detectors/generic-token.ts`
/// (`decision-govern-cross-language-conformance`).
///
/// Unlike `ASSIGNMENT_PREFIX_PATTERN`'s multiline `^`, the boundary
/// alternation here has no `m` flag in the TypeScript oracle: `^` anchors to
/// the absolute start of `input`, which is exactly byte offset `0` of the
/// slice this function receives.
///
/// The name forms it accepts are a superset of those
/// [`parse_name_and_operator`] can join to an operator on a later line
/// (issue #990): holding a line the grammar would not join only delays its
/// output, while closing one it would join loses the value in a stream.
pub(crate) fn has_open_contextual_assignment(input: &str) -> bool {
    let mut end = rskip_while_chars(input, input.len(), is_js_whitespace);

    if let Some(ch) = prev_char(input, end)
        && (ch == '=' || ch == ':')
    {
        end -= ch.len_utf8();
        // `:=` (issue #815).
        if ch == '=' && prev_char(input, end) == Some(':') {
            end -= 1;
        }
        end = rskip_while_chars(input, end, is_js_whitespace);
    }

    if let Some(ch @ ('"' | '\'')) = prev_char(input, end) {
        end -= ch.len_utf8();
        // An escaped closing quote (`\"access_token\":`, issue #815).
        if prev_char(input, end) == Some('\\') {
            end -= 1;
        }
    }

    let name_end = end;
    let mut name_start = end;
    while let Some(ch) = prev_char(input, name_start) {
        if ch.is_ascii_alphanumeric() || matches!(ch, '_' | '.' | '-') {
            name_start -= ch.len_utf8();
        } else {
            break;
        }
    }
    if name_start == name_end {
        return false;
    }
    let Some(first) = char_at(input, name_start) else {
        return false;
    };
    if !first.is_ascii_alphabetic() {
        return false;
    }

    // Every character the assignment grammar accepts directly before a name
    // ([`is_prefix_boundary_char`], plus the line start and a call's `(`)
    // holds the line open, so no name it can join to an operator on a later
    // line is closed away from it (issue #990). A quote or backtick is a
    // boundary on its own: `x"password"`, `{\"password\"` and
    // `` `password `` are names to the grammar, whatever precedes the quote.
    let boundary_ok = prev_char(input, name_start)
        .is_none_or(|ch| is_open_assignment_boundary_char(ch) || matches!(ch, '"' | '\'' | '`'));
    if !boundary_ok {
        return false;
    }

    let name = &input[name_start..name_end];
    let normalized = normalize_name(name);
    is_high_signal_name(&normalized)
        || is_ambiguous_name(&normalized)
        || is_open_jwk_secret_member(input, name_start, name_end)
        // Issue #1018: `masked_api_key` reads `api_key` when its value turns
        // out to be unmasked, so the name holds the line open like `api_key`.
        || value_checked_lead_rest(&normalized)
            .is_some_and(|(_, rest)| is_high_signal_name(rest) || is_ambiguous_name(rest))
}

/// `true` when the name at `name_start..name_end` is a quoted JWK secret
/// member on a line that carries `"kty"` ([`is_jwk_secret_member`]), so the
/// grammar reads it as `private_key` once its operator arrives (issue #990).
/// Only the name's own line is read: from the line break before the name
/// to the next one after it, which in a retained unit is the unit's tail.
fn is_open_jwk_secret_member(input: &str, name_start: usize, name_end: usize) -> bool {
    if !(JWK_SECRET_MEMBERS.contains(&&input[name_start..name_end])
        && input[..name_start].ends_with('"')
        && input[name_end..].starts_with('"'))
    {
        return false;
    }
    let (line_start, line_end) = super::text::line_around(input, name_start, name_end);
    input[line_start..line_end].contains("\"kty\"")
}

// --- non-secret reference exclusions -----------------------------------

const PLACEHOLDER_WORDS: &[&str] = &[
    "example",
    "sample",
    "placeholder",
    "redacted",
    "changeme",
    "password",
    "secret",
    "replaceme",
];

/// The subset of [`PLACEHOLDER_WORDS`] distinctive enough to tolerate an
/// appended digit (`changeme2`) without also swallowing common real (if
/// weak) credentials like `password1` or `secret01` — see
/// `matches_placeholder_vocabulary`'s doc comment.
const DIGIT_SUFFIX_PLACEHOLDER_WORDS: &[&str] = &[
    "example",
    "sample",
    "placeholder",
    "redacted",
    "changeme",
    "replaceme",
];

fn is_generic_placeholder_word(value: &str) -> bool {
    matches_placeholder_vocabulary(value, PLACEHOLDER_WORDS, DIGIT_SUFFIX_PLACEHOLDER_WORDS)
        || is_placeholder_led_phrase(value)
}

/// Words a placeholder phrase may carry after its lead word, besides the
/// credential words (`text::PLACEHOLDER_CREDENTIAL_WORDS`): the negation and
/// filler of `placeholder-not-a-key` and `placeholder-value` (issue #1041).
const PLACEHOLDER_PHRASE_WORDS: &[&str] = &["not", "a", "an", "real", "value", "only"];

/// `true` for a placeholder phrase led by a distinctive placeholder word
/// (issue #1041): `placeholder-not-a-key`, `placeholder-value`,
/// `example_api_token`. The value splits on `-`, `_` and `.` into two or
/// more words of ASCII letters only; the first is a
/// [`DIGIT_SUFFIX_PLACEHOLDER_WORDS`] entry (never `secret` or `password`,
/// which lead real weak passwords), and every later word is a
/// `text::PLACEHOLDER_CREDENTIAL_WORDS` or [`PLACEHOLDER_PHRASE_WORDS`] entry,
/// all case-insensitively.
///
/// A single placeholder word was already silent; a hyphenated phrase that
/// starts with one was redacted at full confidence. FN cost: a real secret
/// spelled exactly as such a phrase, which no provider issues. A digit, any
/// other byte, or one unlisted word (`placeholder-9f2c`, `sample-hunter`)
/// keeps the value reported.
fn is_placeholder_led_phrase(value: &str) -> bool {
    let is_listed =
        |word: &str, words: &[&str]| words.iter().any(|listed| word.eq_ignore_ascii_case(listed));
    let mut words = value.split(['-', '_', '.']);
    let Some(lead) = words.next() else {
        return false;
    };
    if !is_listed(lead, DIGIT_SUFFIX_PLACEHOLDER_WORDS) {
        return false;
    }
    let mut count = 0usize;
    for word in words {
        if word.is_empty()
            || !word.bytes().all(|byte| byte.is_ascii_alphabetic())
            || !(is_listed(word, PLACEHOLDER_PHRASE_WORDS)
                || super::text::is_placeholder_credential_word(word))
        {
            return false;
        }
        count += 1;
    }
    count > 0
}

fn is_boolean_null_or_digits(lower: &str) -> bool {
    matches!(lower, "true" | "false" | "null" | "undefined")
        || (!lower.is_empty() && lower.bytes().all(|byte| byte.is_ascii_digit()))
}

fn starts_with_env_reference(value: &str) -> bool {
    if value.starts_with("${") {
        return true;
    }
    if starts_with_bare_dollar_reference(value) {
        return true;
    }
    starts_with_ci(value, 0, "process.env.") || starts_with_ci(value, 0, "import.meta.env.")
}

/// `true` for a value starting with `<` followed by at least one non-`>`
/// byte and then a `>` (`^<[^>]+>`).
fn starts_with_angle_bracket_reference(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.first() != Some(&b'<') {
        return false;
    }
    matches!(bytes[1..].iter().position(|&byte| byte == b'>'), Some(index) if index > 0)
}

fn starts_with_path_like(value: &str) -> bool {
    starts_with_angle_bracket_reference(value)
        || value.starts_with('/')
        || value.starts_with("./")
        || value.starts_with("../")
}

fn ends_with_key_or_pem(value: &str) -> bool {
    ends_with_ci(value, ".key") || ends_with_ci(value, ".pem")
}

// --- interpolation / command-substitution reference exclusions
// (issue #279) -----------------------------------------------------------
//
// Each of these is, like `is_template_reference`, a syntax that is only a
// bare reference when it delimits the *whole* value -- a value that merely
// starts with the opener, or that carries the pair embedded inside a larger
// string, stays detected. `docs/specs/contextual-detection.md`
// records the supported syntaxes and the accompanying span-scanning fix
// (`delimited_reference_value`) that lets the whole-value check see past a
// closing `)`/`]`/backtick that a plain unquoted-value boundary scan would
// otherwise cut short before. `is_template_reference`, `is_fully_delimited`,
// `is_command_substitution_reference`, `is_ruby_interpolation_reference`,
// and `is_opencode_reference` live in `super::text`, shared with
// `connection_string` (issue #469).

/// `true` for an Azure Pipelines runtime-expression reference
/// (`$[variables.x]`).
fn is_runtime_expression_reference(value: &str) -> bool {
    is_fully_delimited(value, "$[", "]")
}

/// `true` for a value fully wrapped in a matching pair of backticks
/// (`` `${process.env.X}` ``, `` `date +%s` ``): shell command substitution
/// or a JS template literal, not a secret.
fn is_backtick_reference(value: &str) -> bool {
    is_fully_delimited(value, "`", "`")
}

fn is_interpolation_reference(value: &str) -> bool {
    is_command_substitution_reference(value)
        || is_runtime_expression_reference(value)
        || is_ruby_interpolation_reference(value)
        || is_opencode_reference(value)
        || is_backtick_reference(value)
}

// --- secret-manager reference exclusions (issue #280) -------------------
//
// Each of these names *where* a secret lives at runtime -- a pointer `op
// run`, LiteLLM, `vals`, the bank-vaults injector, or a cloud secret
// manager's own client resolves -- rather than containing one. Per-scheme
// grammars are used instead of a bare scheme-prefix allowlist: a prefix
// check alone would exclude any value an attacker or careless author
// prefixed with it, so each function below requires the whole value to
// satisfy that scheme's actual reference shape. A scheme-like prefix on a
// value that does not otherwise satisfy its grammar stays detected.
// `docs/specs/contextual-detection.md` records
// the supported schemes and grammars.

/// `true` for a byte allowed inside a generic path/identifier segment:
/// ASCII letters, digits, `-`, `_`, or `.`. None of the grammars below
/// allow whitespace or other structural punctuation inside a segment.
fn is_segment_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.')
}

fn is_segment(value: &str) -> bool {
    !value.is_empty() && value.bytes().all(is_segment_byte)
}

/// `true` for a byte allowed inside a reference path that may itself
/// contain `/` (a vals or bank-vaults secret path), as opposed to a single
/// path segment.
fn is_path_byte(byte: u8) -> bool {
    is_segment_byte(byte) || byte == b'/'
}

fn is_path(value: &str) -> bool {
    !value.is_empty() && value.bytes().all(is_path_byte)
}

// --- cmd-style Windows env reference and SQL bind parameter exclusions
// (issue #292) ------------------------------------------------------------
//
// Issue #279 (`decision-exclude-interpolation-command-substitution-references`)
// deferred these two syntaxes so each got its own explicit fixture coverage.
// Both share `is_env_var_identifier`'s identifier shape rather than
// `is_template_reference`'s "anything between the delimiters" rule: `%` and
// `:` are common enough punctuation (a percentage-bounded range, a URL port,
// a prose colon) that a bare delimiter-pair check would exclude values that
// merely start and end with one, so the *content* must itself look like an
// identifier. `is_env_var_identifier` and `is_windows_env_reference` live in
// `super::text`, shared with `connection_string` (issue #469).

/// `true` for a SQL named bind parameter (`:new_password_hash`): the whole
/// value is `:` followed by an identifier, a placeholder the query engine
/// substitutes at execution time rather than a secret.
fn is_sql_bind_parameter(value: &str) -> bool {
    value.strip_prefix(':').is_some_and(is_env_var_identifier)
}

/// `true` for a 1Password secret reference (`op://<vault>/<item>/<field>`):
/// exactly three non-empty, path-safe segments after the `op://` scheme,
/// the vault/item/field selector `op run` and the 1Password SDKs resolve at
/// runtime. More or fewer segments, or a segment carrying whitespace or
/// other unsafe punctuation, stays detected.
fn is_onepassword_reference(value: &str) -> bool {
    let Some(rest) = value.strip_prefix("op://") else {
        return false;
    };
    let mut segments = rest.split('/');
    let (Some(vault), Some(item), Some(field), None) = (
        segments.next(),
        segments.next(),
        segments.next(),
        segments.next(),
    ) else {
        return false;
    };
    is_segment(vault) && is_segment(item) && is_segment(field)
}

/// `true` for a `LiteLLM` `os.environ/<VAR_NAME>` reference: the proxy config
/// resolves this to the named environment variable at load time, so the
/// value names where a secret lives rather than containing one.
fn is_litellm_env_reference(value: &str) -> bool {
    value
        .strip_prefix("os.environ/")
        .is_some_and(is_env_var_identifier)
}

fn is_gcp_project_id(value: &str) -> bool {
    if !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit()) {
        return true;
    }
    matches!(value.as_bytes().first(), Some(first) if first.is_ascii_lowercase())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

fn is_gcp_secret_version(value: &str) -> bool {
    value == "latest" || (!value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit()))
}

/// `true` for a GCP Secret Manager resource name
/// (`projects/<id>/secrets/<name>(/versions/<v>)?`): the resource-name shape
/// the Secret Manager client libraries accept in place of a resolved secret
/// value.
fn is_gcp_secret_manager_reference(value: &str) -> bool {
    let segments: Vec<&str> = value.split('/').collect();
    let (project, name) = match segments.as_slice() {
        ["projects", project, "secrets", name] => (project, name),
        ["projects", project, "secrets", name, "versions", version]
            if is_gcp_secret_version(version) =>
        {
            (project, name)
        }
        _ => return false,
    };
    is_gcp_project_id(project) && is_segment(name)
}

/// `true` for a vals structured reference (`ref+<backend>://<path>#<key>`,
/// e.g. `ref+vault://secret/data/db#/password`): the `ref+` scheme prefix
/// vals (`github.com/helmfile/vals`) uses to resolve a value from Vault,
/// cloud secret managers, and other backends at render time.
fn is_vals_reference(value: &str) -> bool {
    let Some(rest) = value.strip_prefix("ref+") else {
        return false;
    };
    let Some((scheme, after_scheme)) = rest.split_once("://") else {
        return false;
    };
    if scheme.is_empty()
        || !scheme
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
    {
        return false;
    }
    let Some((path, key)) = after_scheme.split_once('#') else {
        return false;
    };
    is_path(path) && is_path(key)
}

/// `true` for a bank-vaults injector reference (`vault:<path>#<key>`, e.g.
/// `vault:secret/data/db#password`, optionally `#<key>#<version>`): the
/// syntax the bank-vaults mutating webhook and Vault Agent injector resolve
/// from an environment value or annotation before the container starts.
fn is_bank_vaults_reference(value: &str) -> bool {
    let Some(rest) = value.strip_prefix("vault:") else {
        return false;
    };
    let parts: Vec<&str> = rest.split('#').collect();
    if !(2..=3).contains(&parts.len()) {
        return false;
    }
    is_path(parts[0]) && parts[1..].iter().all(|part| is_segment(part))
}

fn is_aws_secretsmanager_partition(value: &str) -> bool {
    matches!(value, "aws" | "aws-cn" | "aws-us-gov")
}

fn is_aws_region(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

fn is_aws_account_id(value: &str) -> bool {
    value.len() == 12 && value.bytes().all(|byte| byte.is_ascii_digit())
}

fn is_secretsmanager_secret_name(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|byte| is_segment_byte(byte) || matches!(byte, b'/' | b'+' | b'=' | b'@'))
}

/// `true` for an AWS Secrets Manager ARN
/// (`arn:aws:secretsmanager:<region>:<12-digit account id>:secret:<name>`):
/// the resource identifier IAM policies, Secrets Manager clients, and
/// `CloudFormation` templates reference in place of a resolved secret value.
fn is_aws_secretsmanager_arn(value: &str) -> bool {
    let segments: Vec<&str> = value.splitn(7, ':').collect();
    let [
        arn,
        partition,
        service,
        region,
        account,
        secret_literal,
        name,
    ] = segments.as_slice()
    else {
        return false;
    };
    *arn == "arn"
        && is_aws_secretsmanager_partition(partition)
        && *service == "secretsmanager"
        && is_aws_region(region)
        && is_aws_account_id(account)
        && *secret_literal == "secret"
        && is_secretsmanager_secret_name(name)
}

/// `true` for a DNS label: 1-63 ASCII letters, digits, or `-`, neither
/// leading nor trailing with `-`.
fn is_dns_label(label: &str) -> bool {
    let bytes = label.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= 63
        && bytes[0] != b'-'
        && bytes[bytes.len() - 1] != b'-'
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'-')
}

/// `true` for a syntactically well-formed HTTPS hostname: at least two
/// dot-separated DNS labels (an FQDN shape, not a bare single-label host),
/// each satisfying [`is_dns_label`]. This validates *shape*, not that the
/// host is a real, resolvable Key Vault domain: Azure Key Vault is reachable
/// under several sovereign-cloud suffixes (`vault.azure.net`,
/// `vault.usgovcloudapi.net`, `vault.azure.cn`, `vault.microsoftazure.de`,
/// and Private Link hostnames) with no fixed, enumerable list, so the
/// grammar bounds the *host's structure* the way the other secret-manager
/// grammars bound an identifier's structure, rather than checking host
/// identity.
fn is_https_hostname(host: &str) -> bool {
    if host.is_empty() || host.len() > 255 {
        return false;
    }
    let labels: Vec<&str> = host.split('.').collect();
    labels.len() >= 2 && labels.into_iter().all(is_dns_label)
}

/// `true` for `https://<host>/secrets/<name>(/<version>)?`, the Key Vault
/// secret identifier an Azure App Service `SecretUri=` field carries.
fn is_azure_keyvault_secret_uri(value: &str) -> bool {
    let Some(rest) = value.strip_prefix("https://") else {
        return false;
    };
    let Some(slash) = rest.find('/') else {
        return false;
    };
    let (host, path) = rest.split_at(slash);
    is_https_hostname(host) && path.strip_prefix("/secrets/").is_some_and(is_path)
}

/// `true` for an Azure App Service / Functions Key Vault reference
/// (`@Microsoft.KeyVault(SecretUri=<vault-uri>)` or
/// `@Microsoft.KeyVault(VaultName=<vault>;SecretName=<secret>[;SecretVersion=<version>])`):
/// the app-setting syntax that is resolved from Key Vault at startup rather
/// than storing the secret value directly.
fn is_azure_keyvault_reference(value: &str) -> bool {
    let Some(inner) = value
        .strip_prefix("@Microsoft.KeyVault(")
        .and_then(|rest| rest.strip_suffix(')'))
    else {
        return false;
    };
    if let Some(uri) = inner.strip_prefix("SecretUri=") {
        return is_azure_keyvault_secret_uri(uri);
    }
    let mut has_vault_name = false;
    let mut has_secret_name = false;
    for field in inner.split(';') {
        let Some((key, value)) = field.split_once('=') else {
            return false;
        };
        if !is_segment(value) {
            return false;
        }
        match key {
            "VaultName" => has_vault_name = true,
            "SecretName" => has_secret_name = true,
            "SecretVersion" => {}
            _ => return false,
        }
    }
    has_vault_name && has_secret_name
}

/// `true` for an OS keychain secret-store reference, `{keychain:<item>}`
/// (issue #730, benchmark gap `product-730`): the whole value is `{keychain:`,
/// one non-empty path-safe item name ([`is_segment`]), then `}`. It names
/// the keychain entry a client resolves at runtime, in the same
/// brace-delimited `{kind:name}` shape as opencode's `{env:VAR}` /
/// `{file:path}` substitutions, and carries no secret material. An empty
/// item, a second `:` or `/`, whitespace, or any byte after the closing `}`
/// keeps the value detected.
fn is_keychain_reference(value: &str) -> bool {
    value
        .strip_prefix("{keychain:")
        .and_then(|rest| rest.strip_suffix('}'))
        .is_some_and(is_segment)
}

fn is_secret_manager_reference(value: &str) -> bool {
    is_onepassword_reference(value)
        || is_litellm_env_reference(value)
        || is_gcp_secret_manager_reference(value)
        || is_vals_reference(value)
        || is_bank_vaults_reference(value)
        || is_aws_secretsmanager_arn(value)
        || is_azure_keyvault_reference(value)
        || is_keychain_reference(value)
}

// --- partially masked display values (issue #264, benchmark gap
// `product-264`) ----------------------------------------------------------

/// The mask characters a console or CLI uses to hide the middle of a
/// credential: `*` and the bullet `•` (U+2022), the same two characters the
/// repeated-character filler exclusion (#264) already recognizes.
fn is_mask_char(ch: char) -> bool {
    matches!(ch, '*' | '\u{2022}')
}

/// The fewest mask characters that make a value a masked display.
const MIN_MASK_RUN: usize = 4;
/// The most visible characters a masked display keeps on either side of its
/// mask run: a provider prefix plus a few identifying characters
/// (`xai-AbCd`, `gsk_`) on the left, the last few characters on the right.
const MAX_MASK_VISIBLE_SIDE: usize = 12;

/// `true` for a byte a masked display leaves visible: `[A-Za-z0-9._-]`.
fn is_mask_visible_char(ch: char) -> bool {
    ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '-')
}

/// `true` for a partially masked display value, the shape a provider
/// console prints after a key is created (`gsk_` + 48 `*` + `Tn4q`,
/// `xai-AbCd****WxYz`): a visible head, one run of at least
/// [`MIN_MASK_RUN`] identical [`is_mask_char`] characters, and a visible
/// tail. Head and tail are each 1 to [`MAX_MASK_VISIBLE_SIDE`] characters of
/// `[A-Za-z0-9._-]`, and the mask run is at least as long as head and tail
/// together, so the value is mostly mask.
///
/// Both visible sides are required. A mask with only a visible tail
/// (`********x`) stays in scope, keeping the near-miss that pins the #264
/// filler exclusion as a whole-value rule. A second mask run, a mixed mask
/// run, or any other byte keeps the value detected. The false-negative
/// tradeoff is a real credential that happens to contain four or more
/// consecutive `*` between two short visible ends, which no documented
/// credential grammar allows.
fn is_partially_masked_display(value: &str) -> bool {
    let Some(mask_start) = value.find(is_mask_char) else {
        return false;
    };
    let Some(mask) = value[mask_start..].chars().next() else {
        return false;
    };
    let mask_end = value[mask_start..]
        .find(|ch: char| ch != mask)
        .map_or(value.len(), |offset| mask_start + offset);
    let (head, tail) = (&value[..mask_start], &value[mask_end..]);
    let run = value[mask_start..mask_end].chars().count();
    let visible_side = |side: &str| {
        (1..=MAX_MASK_VISIBLE_SIDE).contains(&side.len()) && side.chars().all(is_mask_visible_char)
    };
    run >= MIN_MASK_RUN
        && visible_side(head)
        && visible_side(tail)
        && run >= head.len() + tail.len()
}

/// The fewest mask characters that make a value a masked *key* display
/// ([`is_masked_key_display`]): a full-length key shown as mask, never a
/// short password echo such as `********x`.
const MIN_MASKED_KEY_RUN: usize = 16;
/// The longest visible tail a masked key display keeps after its last
/// separator: a region or checksum label such as Mailchimp's `-us6`.
const MAX_MASKED_KEY_TAIL: usize = 4;

/// `true` for a separator a masked key display keeps between its segments.
fn is_mask_separator(ch: char) -> bool {
    matches!(ch, '-' | '_' | '.' | ':' | '=')
}

/// `true` for a full-length key shown as mask with its layout kept, the way
/// a console, a settings page or a template prints it (issue #993):
/// `********-****-****-****-************` (a UUID-shaped key),
/// `PMAK-****…-****…`, `00••••…` (an Okta token), `3518930973:AA****…` (a
/// Telegram bot token), `ATATT3xFfGF0****…=********` (an Atlassian token)
/// and `********…-us6` (a Mailchimp key).
///
/// The value holds only `[A-Za-z0-9]`, one mask character ([`is_mask_char`])
/// and the separators `-`, `_`, `.`, `:` and `=`. Its visible characters
/// sit in a head before the first mask character (at most
/// [`MAX_MASK_VISIBLE_SIDE`] of them) and, optionally, in one tail segment
/// of at most [`MAX_MASKED_KEY_TAIL`] after the last separator; everything
/// between is mask or separators, and there are at least
/// [`MIN_MASKED_KEY_RUN`] mask characters. A visible character between two
/// mask runs, a mixed mask, a longer head, or a short mask (`********x`,
/// `x********`, the #264 near misses) keeps the value detected. No
/// documented credential grammar contains `*` or `•`.
fn is_masked_key_display(value: &str) -> bool {
    let Some(first_mask) = value.find(is_mask_char) else {
        return false;
    };
    let Some(mask) = value[first_mask..].chars().next() else {
        return false;
    };
    let allowed = |ch: char| ch == mask || ch.is_ascii_alphanumeric() || is_mask_separator(ch);
    if !value.chars().all(allowed) {
        return false;
    }
    let head = &value[..first_mask];
    let head_visible = head.chars().filter(char::is_ascii_alphanumeric).count();
    if head_visible > MAX_MASK_VISIBLE_SIDE {
        return false;
    }
    let rest = &value[first_mask..];
    let body = match rest.rfind(is_mask_separator) {
        Some(index)
            if (1..=MAX_MASKED_KEY_TAIL).contains(&(rest.len() - index - 1))
                && rest[index + 1..]
                    .chars()
                    .all(|ch| ch.is_ascii_alphanumeric()) =>
        {
            &rest[..index]
        }
        _ => rest,
    };
    body.chars().all(|ch| ch == mask || is_mask_separator(ch))
        && body.chars().filter(|&ch| ch == mask).count() >= MIN_MASKED_KEY_RUN
}

/// `true` for a documentation display that shows a key's first few
/// characters and elides the rest (issue #993): `ATATT3xFfGF0...`,
/// `sntrys_eyJ...`, `sk-proj-…`. A head of 1 to [`MAX_MASK_VISIBLE_SIDE`]
/// `[A-Za-z0-9_-]` characters followed only by three or more `.` or by
/// `…`. The elided value is not in the text; a longer visible head, or
/// anything after the ellipsis, keeps the value detected.
fn is_ellipsis_truncated_display(value: &str) -> bool {
    let head = value.trim_end_matches(['.', '\u{2026}']);
    let ellipsis = &value[head.len()..];
    let elided = ellipsis.contains('\u{2026}') || ellipsis.len() >= 3;
    elided
        && ((1..=MAX_MASK_VISIBLE_SIDE).contains(&head.len()) || is_elided_vendor_prefix(head))
        && head
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
}

/// The longest vendor prefix [`is_elided_vendor_prefix`] reads as the whole
/// visible head of an ellipsis display.
const MAX_ELIDED_PREFIX_LEN: usize = 24;
/// The longest segment of such a prefix: vendor prefix segments are short
/// words (`pdl`, `sdbx`, `apikey`), random key material is not.
const MAX_ELIDED_PREFIX_SEGMENT_LEN: usize = 8;

/// `true` when an ellipsis display's visible head longer than
/// [`MAX_MASK_VISIBLE_SIDE`] is only a vendor prefix (issue #1042):
/// `pdl_sdbx_apikey_...`, `pdl_live_apikey_…`. The head ends in its `_` or `-`
/// separator, is at most [`MAX_ELIDED_PREFIX_LEN`] bytes of lowercase ASCII
/// letters, digits and separators, and every segment is at most
/// [`MAX_ELIDED_PREFIX_SEGMENT_LEN`] bytes. No key material is shown; a head
/// that ends inside a segment, or carries a longer or uppercase segment,
/// keeps the display reported.
fn is_elided_vendor_prefix(head: &str) -> bool {
    head.len() <= MAX_ELIDED_PREFIX_LEN
        && head.ends_with(['_', '-'])
        && head.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'_' | b'-')
        })
        && head[..head.len() - 1]
            .split(['_', '-'])
            .all(|segment| (1..=MAX_ELIDED_PREFIX_SEGMENT_LEN).contains(&segment.len()))
}

/// `true` for a value that opens a Make-escaped reference (issue #993):
/// `$$(heroku auth:token)`, `$${VAR}` or `$$VAR`, the forms a Makefile
/// recipe writes for a shell command substitution or variable. An
/// unquoted value ends at whitespace, so the command's first word is all
/// the assignment grammar reads (`$$(heroku`); the value is resolved at run
/// time and never holds the secret. A single-`$` opener without its closing
/// delimiter (`$(SYNTHETIC...`, `` `SYNTHETIC... ``) stays detected, as
/// before; a complete `$(...)` or backtick command is already excluded.
fn starts_with_command_substitution(value: &str) -> bool {
    value.starts_with("$$(")
        || value.starts_with("$${")
        || (value.starts_with("$$")
            && value
                .as_bytes()
                .get(2)
                .is_some_and(|byte| byte.is_ascii_alphabetic() || *byte == b'_'))
}

/// Documented public key prefixes: each provider states that a key behind
/// it is safe to expose, and its own detector deliberately never claims it
/// (issue #993). Stripe `pk_live_`/`pk_test_` (see
/// `additional_providers.rs`), Supabase `sb_publishable_`, Langfuse `pk-lf-`
/// (`langfuse.rs`), `PostHog` `phc_` (`posthog.rs`), and Trigger.dev
/// `pk_<env>_` for its four environment slugs (`trigger_dev.rs`).
const PUBLIC_KEY_PREFIXES: &[&str] = &[
    "pk_live_",
    "pk_test_",
    "sb_publishable_",
    "pk-lf-",
    "phc_",
    "pk_dev_",
    "pk_stg_",
    "pk_prod_",
    "pk_preview_",
];

/// `true` for a value that is a documented public key
/// ([`PUBLIC_KEY_PREFIXES`] and a non-empty `[A-Za-z0-9_-]` body), which a
/// secret-named variable sometimes holds by mistake
/// (`STRIPE_WEBHOOK_SECRET=pk_live_...`). A secret key's prefix
/// (`sk_live_`, `sb_secret_`, `sk-lf-`, `phx_`) is not on the list, and a
/// public prefix glued inside a longer value (`xpk_live_...`) does not
/// match.
fn is_public_key_value(value: &str) -> bool {
    PUBLIC_KEY_PREFIXES.iter().any(|prefix| {
        value.len() > prefix.len()
            && value.starts_with(prefix)
            && value[prefix.len()..]
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    })
}

/// `true` for a Confluent Cloud API key id, the public half of a Confluent
/// key pair ("It is not considered secret information", Confluent's
/// overview, example `ABCD1234567890AB`), assigned to a name that carries
/// `confluent` (`CONFLUENT_CLOUD_API_KEY=`, issue #993): exactly 16
/// `[A-Z0-9]`. A Confluent secret is 64 bytes, so the id never hides one.
/// The shape is community-observed rather than published, so it is read
/// only under a Confluent-named key; under any other name
/// (`KAFKA_API_KEY=`) a 16-byte uppercase value stays detected.
fn is_confluent_key_id_assignment(name: &str, value: &str) -> bool {
    name.split('_').any(|segment| segment == "confluent")
        && value.len() == 16
        && value
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit())
}

// --- colon-namespaced scope identifiers (issue #727, benchmark gap
// `product-727`) ----------------------------------------------------------

/// `true` for one segment of a colon-namespaced scope identifier: a
/// lowercase word (`[a-z][a-z0-9_-]*`) or the `*` wildcard.
fn is_scope_segment(segment: &str) -> bool {
    if segment == "*" {
        return true;
    }
    let mut chars = segment.chars();
    matches!(chars.next(), Some(first) if first.is_ascii_lowercase())
        && chars.all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || matches!(ch, '_' | '-'))
}

/// `true` when an assignment is really one colon-namespaced scope or
/// permission identifier (`api-key:endpoint:chat`, `api-key:model:*` in an
/// xAI key's `acls` list): the operator is a bare `:` with nothing between
/// it and the name or the value (`separator`), and the value itself goes on
/// as a chain of two or more [`is_scope_segment`] segments joined by `:`.
///
/// The whole run is then one token, `<resource>:<action>[:...]`, rather
/// than a name followed by a secret. Every other assignment keeps today's
/// behavior: a space after the colon (`api_key: endpoint:chat`, a YAML
/// mapping), a quote around the name (`"api_key":"..."`), an `=` operator,
/// a single-segment value (`Api-Key:<token>`, a curl header with no space),
/// or any uppercase letter, digit-led segment or other byte in the value.
/// The false-negative tradeoff is a colon-joined lowercase passphrase glued
/// to a credential name with no space, which is not how any credential
/// grammar or config format writes a secret.
fn is_colon_scope_identifier(separator: &str, value: &str) -> bool {
    separator == ":" && value.contains(':') && value.split(':').all(is_scope_segment)
}

/// A small, explicit set of source-code roots whose member-access syntax is
/// unambiguous as soon as it opens: a Django/Rails/NestJS `settings`/`config`
/// object, JS/Python/Ruby `self`/`this` instance access, or a Terraform
/// `var`/`local`/`data` lookup. Anchored at the start of the value with a
/// required `.` immediately after the root, so `self` does not also match an
/// unrelated identifier like `selfhosted`.
const CODE_REFERENCE_ROOTS: &[&str] = &[
    "settings", "config", "cfg", "options", "self", "this", "var", "local", "data",
    // Starlark, GitHub Actions and Nushell environment lookups
    // (`env.DEPLOY_PASSWORD`, issue #817).
    "env",
];

fn starts_with_code_reference_root(value: &str) -> bool {
    CODE_REFERENCE_ROOTS.iter().any(|root| {
        value
            .strip_prefix(root)
            .is_some_and(|rest| rest.starts_with('.'))
    })
}

fn is_lower_snake_case_segment(segment: &str) -> bool {
    let mut chars = segment.chars();
    matches!(chars.next(), Some(first) if first.is_ascii_lowercase())
        && chars.all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '_')
}

/// `true` for a dotted chain of two or more `lower_snake_case` segments with
/// at least one underscore somewhere in the chain — the shape of a Terraform
/// resource/data-source attribute reference (`random_password.db.result`,
/// `data.aws_secretsmanager_secret_version.db.secret_string`,
/// `var.db_password`). The underscore requirement is deliberate: it is what
/// keeps this from also matching a real dotted passphrase built from whole
/// words (`my.pass.word`) — see the decision record for the tradeoff.
fn is_snake_case_attribute_chain(value: &str) -> bool {
    if !value.contains('_') || !value.contains('.') {
        return false;
    }
    value
        .split('.')
        .all(|segment| !segment.is_empty() && is_lower_snake_case_segment(segment))
}

/// `true` when an identifier character is immediately followed by `<` or
/// `[` anywhere in the value: `Identifier<...>` / `Identifier[...]`
/// generic-type or subscript syntax (`Option<String>`, `Optional[str`,
/// `&SecretBox<str>`), rather than a literal value.
///
/// The value must also be written only in bytes a type or subscript
/// expression uses (identifier bytes, `.`, `:`, `<`, `>`, `[`, `]`, `,`,
/// `&`, `'`, `*`, `?`, space): a passphrase that happens to contain `x[`
/// next to `{`, `$`, `#`, `(` or `-` (`m{{h}o)p${e]nob(ody[...`) is literal
/// material, not code (issue #815).
fn contains_generic_or_subscript_syntax(value: &str) -> bool {
    let bytes = value.as_bytes();
    let type_expression_bytes_only = bytes.iter().all(|&byte| {
        byte.is_ascii_alphanumeric()
            || matches!(
                byte,
                b'_' | b'.'
                    | b':'
                    | b'<'
                    | b'>'
                    | b'['
                    | b']'
                    | b','
                    | b'&'
                    | b'\''
                    | b'*'
                    | b'?'
                    | b' '
            )
    });
    type_expression_bytes_only
        && bytes.iter().enumerate().any(|(index, &byte)| {
            matches!(byte, b'<' | b'[')
                && index > 0
                && matches!(bytes[index - 1], b'0'..=b'9' | b'a'..=b'z' | b'A'..=b'Z' | b'_')
        })
}

/// `true` when the value ends with an unmatched `(` or `[` — a call or
/// subscript expression truncated at the unquoted-value boundary because its
/// argument is itself a quoted string (`os.environ["OPENAI_API_KEY"]` is
/// captured only as `os.environ[`; a Rust environment-variable-lookup call
/// with a string literal argument is captured only up to its open paren).
/// No real unquoted credential value in the syntaxes this detector targets
/// legitimately ends with an open bracket or parenthesis.
fn ends_with_open_call_or_subscript(value: &str) -> bool {
    matches!(value.as_bytes().last(), Some(b'(' | b'['))
}

fn is_identifier_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}

fn closing_bracket_for(open: u8) -> u8 {
    match open {
        b'(' => b')',
        b'[' => b']',
        _ => b'}',
    }
}

/// From the index of an opening bracket, the index just past its matching
/// closer, or `None` when the group never closes inside `bytes` or a closer
/// arrives out of order.
fn balanced_group_end(bytes: &[u8], open: usize) -> Option<usize> {
    let mut stack: Vec<u8> = Vec::new();
    for (index, &byte) in bytes.iter().enumerate().skip(open) {
        match byte {
            b'(' | b'[' | b'{' => stack.push(byte),
            b')' | b']' | b'}' => {
                let opener = stack.pop()?;
                if byte != closing_bracket_for(opener) {
                    return None;
                }
                if stack.is_empty() {
                    return Some(index + 1);
                }
            }
            _ => {}
        }
    }
    None
}

/// What [`scan_identifier_chain`] made of a value.
enum ChainScan {
    /// The value is, end to end, a `.`-separated chain of identifier
    /// segments; `saw_call` records whether any segment carried a balanced
    /// `(...)` argument group.
    Complete { saw_call: bool },
    /// The chain ran into a `(` or `[` — opened directly on an identifier
    /// segment — that never closes before the value ends.
    Truncated,
    /// Not an identifier chain.
    Other,
}

/// Walks a value as `Segment ( '.' Segment )*`, where a `Segment` is an
/// identifier optionally followed by balanced `(...)` / `[...]` groups.
///
/// Anchoring every bracket group to the identifier that opens it is what
/// separates a source-code call from a value that merely embeds punctuation:
/// `$(`, `#{`, and `{{` all open on a non-identifier character, so the
/// interpolation and template *fragments* that issues #266 and #279
/// deliberately keep detected (`SYNTHETIC_REVOKED_{{`,
/// `$(SYNTHETIC_REVOKED_CONTEXT_VALUE`) scan as [`ChainScan::Other`] rather
/// than as truncated code.
fn scan_identifier_chain(value: &str) -> ChainScan {
    let bytes = value.as_bytes();
    let mut index = 0usize;
    let mut saw_call = false;
    loop {
        let segment_start = index;
        while index < bytes.len() && is_identifier_byte(bytes[index]) {
            index += 1;
        }
        if index == segment_start {
            return ChainScan::Other;
        }
        while let Some(&open @ (b'(' | b'[')) = bytes.get(index) {
            match balanced_group_end(bytes, index) {
                Some(after) => {
                    index = after;
                    saw_call |= open == b'(';
                }
                None => return ChainScan::Truncated,
            }
        }
        match bytes.get(index) {
            None => return ChainScan::Complete { saw_call },
            Some(b'.') => index += 1,
            // Lua method calls (`secrets:get(name)`) and Rust/C++ paths
            // (`vault::read(path)`) join segments with `:` or `::`
            // (issue #911). A chain still needs a balanced `(...)` call to
            // count as one, so a colon-joined literal (`user:pass`) is not.
            Some(b':') => {
                index += if bytes.get(index + 1) == Some(&b':') {
                    2
                } else {
                    1
                }
            }
            Some(_) => return ChainScan::Other,
        }
    }
}

/// `true` when the *whole* value is a call expression: a `.`-separated chain
/// of identifier segments in which at least one segment is immediately
/// followed by a balanced `(...)` argument group, with the value ending
/// exactly where that chain does — `getSecretOrThrow(SECRET_NAME_CONSTANT)`,
/// `SecretManagerServiceClient.access_secret_version(req)`,
/// `django.core.signing.get_cookie_signer(salt=SALT)` (issue #467).
///
/// Requiring the chain to span the entire value is what keeps this from
/// becoming the blanket "value contains `(`" rule issue #467 rejected: a
/// passphrase that merely embeds parentheses (`SYNTHETIC(REVOKED)_CONTEXT_VALUE`)
/// carries trailing characters that are neither `.` nor the end of the value,
/// so it stays detected.
fn is_call_expression(value: &str) -> bool {
    matches!(
        scan_identifier_chain(value),
        ChainScan::Complete { saw_call: true }
    )
}

/// `true` when the value is a call or subscript expression cut short *inside*
/// its bracket group, which is what `unquoted_assignment_value` produces
/// whenever its boundary set (whitespace, `,`, `;`, `}`, `]`, a quote) lands
/// between the brackets: `crypto.createPrivateKey({` from
/// `crypto.createPrivateKey({ key: pem })`, `helper(FIRST` from
/// `helper(FIRST, SECOND)`, `os.environ[` from `os.environ["NAME"]`.
///
/// This generalizes [`ends_with_open_call_or_subscript`] from "ends with an
/// open bracket" to "opens a bracket it never closes", which is what makes
/// the anti-stranding guarantee hold: a value cut mid-group is exactly the
/// value whose redaction would otherwise leave the rest of the group
/// (` key: pem })`) behind as syntactically broken output (issue #467).
fn is_truncated_call_expression(value: &str) -> bool {
    matches!(scan_identifier_chain(value), ChainScan::Truncated)
}

/// Whether an assignment value carried its own `"`/`'` delimiters.
///
/// The distinction matters only for truncation: an unquoted value ends
/// wherever `is_unquoted_value_boundary` says it does, so it can be cut in
/// the middle of a bracket group, while a quoted value always spans its full
/// literal content and never is. Keeping [`is_truncated_call_expression`]
/// off quoted values is what preserves detection of a parenthesized *literal*
/// passphrase such as `password: "SYNTHETIC(REVOKED_CONTEXT_VALUE"`.
#[derive(Clone, Copy, PartialEq, Eq)]
enum ValueForm {
    Quoted,
    Unquoted,
}

/// `true` when the value is structurally a source-code expression — member
/// access, a call, a subscript, or a generic type — that names *where* a
/// value lives rather than containing the value itself (issues #278, #467).
fn is_source_code_expression(value: &str, form: ValueForm) -> bool {
    starts_with_code_reference_root(value)
        || is_snake_case_attribute_chain(value)
        || contains_generic_or_subscript_syntax(value)
        || ends_with_open_call_or_subscript(value)
        || is_call_expression(value)
        || (form == ValueForm::Unquoted && is_truncated_call_expression(value))
}

/// Shared by contextual assignment values and, via [`authorization_candidates`],
/// `Basic`/`Token` HTTP `Authorization` header values. `is_source_code_expression`'s
/// and `is_interpolation_reference`'s checks key on punctuation (`.`, `<`,
/// `[`, `(`, `$`, `#`, `` ` ``) that `is_authorization_value_byte` already
/// excludes from an authorization value's character class, so they can
/// never fire there — this function's behavior for that caller is unchanged by
/// them. That is also why the `form` an authorization value is passed is
/// immaterial: the only check that reads it, [`is_truncated_call_expression`],
/// needs a bracket the character class already forbids.
fn is_non_secret_reference(value: &str, form: ValueForm) -> bool {
    let lower = value.to_ascii_lowercase();
    is_generic_placeholder_word(&lower)
        || is_instructional_token_placeholder(value)
        || is_glued_my_placeholder(value)
        || is_boolean_null_or_digits(&lower)
        || starts_with_env_reference(value)
        || starts_with_path_like(value)
        || ends_with_key_or_pem(value)
        || is_template_reference(value)
        || is_interpolation_reference(value)
        || is_secret_manager_reference(value)
        || is_repeated_character_filler(value)
        || is_partially_masked_display(value)
        || is_masked_key_display(value)
        || is_ellipsis_truncated_display(value)
        || starts_with_command_substitution(value)
        || is_public_key_value(value)
        || is_source_code_expression(value, form)
        || is_windows_env_reference(value)
        || is_sql_bind_parameter(value)
        || is_twilio_public_sid(value)
        || is_vendor_prefixed_placeholder(value)
        || is_prefixed_filler(value)
        || starts_with_digest_label(value)
        || is_html_escaped_angle_reference(value)
        || is_aws_arn(value)
        || (form == ValueForm::Quoted && is_string_concatenation_seam(value))
        || is_quoted_reference(value, form)
        || (form == ValueForm::Unquoted && is_credential_variable_name_value(value))
        || is_reverse_dns_identifier(value)
        || is_composite_with_placeholder_secret_part(value)
}

/// Final segments that make an `UPPER_SNAKE` identifier the *name* of a
/// credential variable (`DB_PASSWORD`, `FAKE_SIGNING_SECRET`).
const CREDENTIAL_NAME_TAIL_WORDS: &[&str] = &[
    "TOKEN",
    "SECRET",
    "PASSWORD",
    "PASSWD",
    "PASSPHRASE",
    "KEY",
    "CREDENTIAL",
    "CREDENTIALS",
];

/// `true` for an unquoted value that is itself a credential variable's
/// name, an `UPPER_SNAKE` identifier of two or more segments ending in a
/// credential word: a keyword argument passing a constant
/// (`signing_secret=FAKE_SIGNING_SECRET)`, the call's `)` included by the
/// unquoted boundary), or an `ExternalSecret` / Helm `secretKey: DB_PASSWORD`
/// naming the key inside a Secret object (issue #911).
///
/// Quoted values are out of scope, and so is any value carrying a
/// placeholder lead word (`YOUR_ACMECLOUD_API_KEY`), which the #756
/// instructional-placeholder rule governs. FN cost: a real secret that is an
/// unquoted all-caps word chain ending in `_KEY`/`_TOKEN`/`_SECRET`/... .
fn is_credential_variable_name_value(value: &str) -> bool {
    let identifier = value.trim_end_matches(')');
    let mut segments = identifier.split('_');
    let segment_count = identifier.split('_').count();
    segment_count >= 2
        && segments.all(|segment| {
            segment
                .bytes()
                .next()
                .is_some_and(|first| first.is_ascii_uppercase())
                && segment
                    .bytes()
                    .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit())
                && !matches!(segment, "YOUR" | "INSERT" | "ENTER" | "PASTE" | "REPLACE")
        })
        && identifier
            .rsplit('_')
            .next()
            .is_some_and(|tail| CREDENTIAL_NAME_TAIL_WORDS.contains(&tail))
}

/// Credential nouns that end a lowercase placeholder phrase.
const CREDENTIAL_PHRASE_TAIL_WORDS: &[&str] = &[
    "key",
    "secret",
    "token",
    "password",
    "passwd",
    "passphrase",
    "credential",
    "credentials",
];

/// `true` for a lowercase word phrase naming a credential rather than
/// holding one: two or more `[a-z]+` words joined by `-` or `_`, ending in a
/// credential noun (`your-admin-key`, `super-secret-key`,
/// `your-fal-key-secret`). Used only for the secret part of a composite
/// value ([`is_composite_with_placeholder_secret_part`]).
fn is_credential_noun_phrase(value: &str) -> bool {
    let words: Vec<&str> = value.split(['-', '_']).collect();
    words.len() >= 2
        && words
            .iter()
            .all(|word| !word.is_empty() && word.bytes().all(|byte| byte.is_ascii_lowercase()))
        && words
            .last()
            .is_some_and(|tail| CREDENTIAL_PHRASE_TAIL_WORDS.contains(tail))
}

/// `true` for a composite value, runs joined by `|` or `:` such as a Convex
/// `<lead>|<body>` key or a fal `<id>:<secret>` key, whose last run (the
/// secret part) is a reference or a placeholder: a `$VAR`/`${VAR}`
/// reference, a `{{ }}` template, an interpolation, an `<angle>`
/// placeholder, placeholder vocabulary, an instructional placeholder,
/// filler, or a lowercase credential-noun phrase
/// (`prod:<name>|${CONVEX_BODY}`, `prod:adjective-animal-123|super-secret-key`,
/// `your-fal-key-id:your-fal-key-secret`), issue #919 follow-up. The lead
/// runs are public names, so they never make the value a secret on their
/// own.
///
/// Only a value with no whitespace, `/` or `@` (outside a `{{ }}` secret
/// part) qualifies, so a URL, a
/// connection string or a `user:pass@host` credential keeps today's reading,
/// and a digits-only last run (a port) is never treated as a placeholder. A
/// real-shaped secret part keeps the whole value high/redact.
fn is_composite_with_placeholder_secret_part(value: &str) -> bool {
    let plain = |part: &str| {
        !part
            .bytes()
            .any(|byte| byte.is_ascii_whitespace() || matches!(byte, b'/' | b'@'))
    };
    let Some(last) = value.rsplit(['|', ':']).next() else {
        return false;
    };
    if last.len() == value.len() {
        return false;
    }
    let head = &value[..value.len() - last.len() - 1];
    // Only a `{{ ... }}` template secret part may carry spaces.
    if head.is_empty()
        || last.is_empty()
        || !plain(head)
        || !(plain(last) || is_template_reference(last))
    {
        return false;
    }
    let lower = last.to_ascii_lowercase();
    starts_with_env_reference(last)
        || is_template_reference(last)
        || is_interpolation_reference(last)
        || starts_with_angle_bracket_reference(last)
        || is_generic_placeholder_word(&lower)
        || is_instructional_token_placeholder(last)
        || is_repeated_character_filler(last)
        || is_credential_noun_phrase(last)
        // A `${VAR}` reference whose braces were split by the `:` join.
        || (last.ends_with('}') && head.contains("${"))
}

/// Leading labels of a reverse-DNS identifier (`com.example.app.apiToken`).
const REVERSE_DNS_ROOTS: &[&str] = &[
    "com", "org", "net", "io", "dev", "app", "co", "me", "ai", "edu", "gov", "de", "uk", "fr",
    "jp", "kr", "us",
];

/// `true` for a reverse-DNS identifier, the naming scheme of Apple keychain
/// items, bundle ids and Android packages: a [`REVERSE_DNS_ROOTS`] label,
/// then two or more further labels of `[A-Za-z][A-Za-z0-9_-]*`, joined by
/// `.` (`com.example.app.accessToken`, issue #911). It names where a secret
/// is stored, never the secret. FN cost: a real secret written as three or
/// more dotted words under one of those roots, which no credential grammar
/// uses.
fn is_reverse_dns_identifier(value: &str) -> bool {
    let mut labels = value.split('.');
    labels
        .next()
        .is_some_and(|root| REVERSE_DNS_ROOTS.contains(&root))
        && value.split('.').count() >= 3
        && labels.all(|label| {
            (1..=63).contains(&label.len())
                && label.as_bytes()[0].is_ascii_alphabetic()
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
        })
}

/// `true` for an HTML-escaped `<...>` placeholder (`&lt;YOUR_PASSWORD&gt;`):
/// the unescaped form is already excluded by [`starts_with_path_like`], and
/// HTML-escaping is how that placeholder reaches a JSON or HTML document
/// (issue #817). The whole value must be the escaped pair around a
/// non-empty run without `<`, `>` or `&`.
fn is_html_escaped_angle_reference(value: &str) -> bool {
    value
        .strip_prefix("&lt;")
        .and_then(|rest| rest.strip_suffix("&gt;"))
        .is_some_and(|inner| !inner.is_empty() && !inner.contains(['<', '>', '&']))
}

/// `true` for a whole AWS ARN,
/// `arn:<aws|aws-cn|aws-us-gov>:<service>:<region?>:<account?>:<resource>`
/// (`arn:aws:iam::aws:policy/IAMUserChangePassword`): an ARN names a
/// resource and never contains its secret (issue #817). The Secrets Manager
/// ARN rule above is the narrower case of the same fact.
fn is_aws_arn(value: &str) -> bool {
    let segments: Vec<&str> = value.splitn(6, ':').collect();
    let [arn, partition, service, region, account, resource] = segments.as_slice() else {
        return false;
    };
    *arn == "arn"
        && is_aws_secretsmanager_partition(partition)
        && !service.is_empty()
        && service
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        && (region.is_empty() || is_aws_region(region))
        && (account.is_empty() || *account == "aws" || is_aws_account_id(account))
        && !resource.is_empty()
        && !resource.bytes().any(|byte| byte.is_ascii_whitespace())
}

/// `true` when a quoted "value" is the seam between two string literals
/// joined by concatenation: the assignment's closing quote was really the
/// end of one literal and the next quote opens another
/// (`"Password: " + getPassword() + ","` yields ` + getPassword() + `,
/// issue #817). The content must open and close with whitespace around a
/// `+` or `.` operator.
fn is_string_concatenation_seam(value: &str) -> bool {
    let trimmed = value.trim_matches(|ch: char| ch == ' ' || ch == '\t');
    trimmed.len() + 2 <= value.len()
        && value.starts_with([' ', '\t'])
        && value.ends_with([' ', '\t'])
        && trimmed.len() >= 2
        && trimmed.starts_with(['+', '.'])
        && trimmed.ends_with(['+', '.'])
}

/// `true` when the value is one matching pair of `'`/`"` around a
/// non-secret reference: shell quote juggling such as
/// `DB_PASSWORD="'$DEPLOY_PASSWORD'"` leaves `'$DEPLOY_PASSWORD'` as the
/// value (issue #817). A quoted literal inside the quotes stays detected.
fn is_quoted_reference(value: &str, form: ValueForm) -> bool {
    let bytes = value.as_bytes();
    bytes.len() >= 3
        && matches!(bytes[0], b'\'' | b'"')
        && bytes[bytes.len() - 1] == bytes[0]
        && is_non_secret_reference(&value[1..value.len() - 1], form)
}

/// The longest alphanumeric lead [`is_prefixed_filler`] allows before the
/// filler.
const MAX_FILLER_PREFIX_LEN: usize = 8;

/// The shortest filler run [`is_prefixed_filler`] accepts.
const MIN_FILLER_LEN: usize = 8;

/// `true` for documentation filler behind an optional short prefix, with
/// `-`, `_` and `.` ignored: `dapixxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx`,
/// `PMAK-xxxxxxxx-xxxxxxxx`, `00000000-0000-0000-0000-000000000000`. After
/// at most [`MAX_FILLER_PREFIX_LEN`] leading alphanumeric bytes, every
/// remaining byte is one repeated character, at least [`MIN_FILLER_LEN`]
/// long (issue #702, the provider-named placeholders its wider name
/// matching exposes). A real credential body is never one repeated
/// character.
fn is_prefixed_filler(value: &str) -> bool {
    // A template keeps a short region label after the filler
    // (`xxxxxxxx…-usX`, a Mailchimp key, issue #993).
    let without_label = value
        .rsplit_once('-')
        .filter(|(head, label)| {
            !head.is_empty()
                && (1..=MAX_MASKED_KEY_TAIL).contains(&label.len())
                && label.bytes().all(|byte| byte.is_ascii_alphanumeric())
        })
        .map(|(head, _)| head);
    is_prefixed_filler_body(value) || without_label.is_some_and(is_prefixed_filler_body)
}

/// [`is_prefixed_filler`] without the label rule.
///
/// Issue #1042: a `:` between layout segments and trailing `=` Base64
/// padding are layout too, so a multi-part filler template
/// (`0.xxxxxxxx-xxxx-....xxxx:xxxx==`, a Bitwarden Secrets Manager access
/// token) reads as filler. Padding counts only at the end.
fn is_prefixed_filler_body(value: &str) -> bool {
    let body: Vec<u8> = value
        .trim_end_matches('=')
        .bytes()
        .filter(|byte| !matches!(byte, b'-' | b'_' | b'.' | b':'))
        .collect();
    if !body.iter().all(u8::is_ascii_alphanumeric) {
        return false;
    }
    (0..=MAX_FILLER_PREFIX_LEN.min(body.len())).any(|split| {
        let filler = &body[split..];
        filler.len() >= MIN_FILLER_LEN && filler.iter().all(|&byte| byte == filler[0])
    })
}

/// The longest vendor prefix [`is_vendor_prefixed_placeholder`] strips.
const MAX_VENDOR_PLACEHOLDER_PREFIX_LEN: usize = 12;

/// Dedicated-detector prefixes longer than
/// [`MAX_VENDOR_PLACEHOLDER_PREFIX_LEN`] that are stripped all the same, each
/// written without its trailing separator. Issue #1015: `sk-ant-admin01` is
/// the Anthropic Admin prefix, and its documentation placeholders
/// (`sk-ant-admin01-<your-key>`) get the same treatment as the 12-byte
/// `sk-ant-api01`/`sk-ant-api03` siblings. Listing the exact prefix keeps the
/// general 12-byte cap for every other lowercase lead (`longvendorname_`).
const LONG_VENDOR_PLACEHOLDER_PREFIXES: &[&str] = &["sk-ant-admin01"];

/// The longest entry of [`LONG_VENDOR_PLACEHOLDER_PREFIXES`].
const MAX_LONG_VENDOR_PLACEHOLDER_PREFIX_LEN: usize = 14;

/// `true` for a documentation placeholder behind a short vendor prefix:
/// `pplx-your-api-key-here`, `lsv2_pt_your_key_here`, `pcsk_***`,
/// `pul-xxxxxxxx`, `xapp-<your-app-level-token>`. The prefix is at most
/// [`MAX_VENDOR_PLACEHOLDER_PREFIX_LEN`] lowercase alphanumeric bytes and
/// separators, the way vendor prefixes are written (an uppercase lead such
/// as `KEY_YOUR_API_KEY` stays detected, #756),
/// and the rest, after one of its `_`/`-` separators, is an instructional
/// placeholder (also glued into one word, `re_yourkey`), an ascending digit
/// run (`signkey-test-12345`, `re_123456789`; issue #949), an `<...>`
/// reference, repeated filler, or a placeholder word.
///
/// Issue #702: provider-named assignments (`PERPLEXITY_API_KEY=`) now reach
/// the generic detector, and their documentation examples keep the vendor
/// prefix in front of the placeholder. A real token's body is random
/// material, which fails all three checks, so the prefix alone never
/// excludes a value.
pub(super) fn is_vendor_prefixed_placeholder(value: &str) -> bool {
    value
        .char_indices()
        .take_while(|&(index, _)| index <= MAX_LONG_VENDOR_PLACEHOLDER_PREFIX_LEN)
        .filter(|&(index, ch)| {
            index > 0
                && matches!(ch, '_' | '-')
                && (index <= MAX_VENDOR_PLACEHOLDER_PREFIX_LEN
                    || LONG_VENDOR_PLACEHOLDER_PREFIXES.contains(&&value[..index]))
        })
        .any(|(index, _)| {
            let rest = &value[index + 1..];
            let prefix = &value[..index];
            // An uppercase vendor prefix (`PMAK-<your-api-key>`) qualifies
            // only in front of a whole `<...>` placeholder (issue #993).
            let upper_prefix_ok = prefix
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
                && rest.len() > 2
                && rest.starts_with('<')
                && rest.ends_with('>')
                && !rest[1..rest.len() - 1].contains(['<', '>']);
            !rest.is_empty()
                && (upper_prefix_ok
                    || prefix.bytes().all(|byte| {
                        byte.is_ascii_lowercase()
                            || byte.is_ascii_digit()
                            || matches!(byte, b'_' | b'-')
                    }))
                && (is_instructional_token_placeholder(rest)
                    || is_glued_instructional_placeholder(rest)
                    || is_lead_word_phrase_placeholder(rest)
                    || is_ascending_digit_run(rest)
                    || is_counting_run_body(rest)
                    || starts_with_angle_bracket_reference(rest)
                    || is_repeated_character_filler(rest)
                    || is_generic_placeholder_word(&rest.to_ascii_lowercase()))
        })
}

/// Shortest digit run [`is_ascending_digit_run`] accepts.
const MIN_ASCENDING_DIGITS: usize = 4;

/// `true` for a counting run of digits such as `12345`, `123456789` or
/// `4567890`: at least [`MIN_ASCENDING_DIGITS`] ASCII digits, each one more
/// than the one before (`9` is followed by `0`). Documentation writes these
/// behind a vendor prefix (`signkey-test-12345`, `re_123456789`, issue
/// #949); a random numeric body is an ascending run with probability
/// 10^-(n-1), so only a placeholder matches. Any other digit sequence, even
/// all digits, is not excluded here.
fn is_ascending_digit_run(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.len() >= MIN_ASCENDING_DIGITS
        && bytes.iter().all(u8::is_ascii_digit)
        && bytes
            .windows(2)
            .all(|pair| pair[1] == if pair[0] == b'9' { b'0' } else { pair[0] + 1 })
}

/// Shortest segment [`is_counting_run_body`] accepts.
const MIN_COUNTING_SEGMENT: usize = 3;

/// `true` for one counting run: consecutive lowercase letters (`abc`),
/// consecutive digits (`123`, `9` then `0`), or a letter run followed by a
/// digit run (`abc123`), at least [`MIN_COUNTING_SEGMENT`] bytes.
fn is_counting_segment(segment: &str) -> bool {
    let bytes = segment.as_bytes();
    let digits_from = bytes
        .iter()
        .position(u8::is_ascii_digit)
        .unwrap_or(bytes.len());
    let (letters, digits) = bytes.split_at(digits_from);
    let counts =
        |run: &[u8], next: fn(u8) -> u8| run.windows(2).all(|pair| pair[1] == next(pair[0]));
    bytes.len() >= MIN_COUNTING_SEGMENT
        && letters.iter().all(u8::is_ascii_lowercase)
        && digits.iter().all(u8::is_ascii_digit)
        && counts(letters, |byte| byte + 1)
        && counts(digits, |byte| if byte == b'9' { b'0' } else { byte + 1 })
}

/// The body length range [`is_counting_run_body`] accepts, separators
/// excluded: a short documentation stand-in, never a full-length synthetic
/// key body (`key-abcdefghijklmnopqrstuvwxyz012345` stays reported).
const COUNTING_BODY_LEN: std::ops::RangeInclusive<usize> = 6..=12;

/// `true` for a documentation body made of counting runs joined by `-` or
/// `_`: `abc123` in `ghp_abc123`, `glpat-abc123` and `npm_abc123`, and
/// `123-456-abc` in `xoxb-123-456-abc` (issue #993, the #949 counting-run
/// rule widened to letters). Read only behind a vendor prefix
/// ([`is_vendor_prefixed_placeholder`]) and only at
/// [`COUNTING_BODY_LEN`]; random key material is a counting run with
/// vanishing probability, so any other character keeps the value detected
/// (`ghp_abd123`, `ghp_abc124`).
fn is_counting_run_body(value: &str) -> bool {
    let body_len = value
        .bytes()
        .filter(|byte| !matches!(byte, b'-' | b'_'))
        .count();
    COUNTING_BODY_LEN.contains(&body_len) && value.split(['-', '_']).all(is_counting_segment)
}

/// `true` when the whole value is a Twilio Account SID (`AC`) or API Key
/// SID (`SK`) in Twilio's documented SID shape: the two-letter uppercase
/// prefix followed by exactly 32 lowercase hex bytes (issue #746).
///
/// Twilio documents both as identifiers, not secrets: the Account SID names
/// the account and the API Key SID is the username sent alongside the API
/// Key Secret (`https://www.twilio.com/docs/iam/api-keys`). The
/// `twilio-auth-token` and `twilio-api-key-secret` detectors already use
/// them only as context and never report them, so a SID after a
/// credential-like name (`credentials: SK...`) is excluded here too. Only
/// the exact shape counts: a different prefix, a different length, or an
/// uppercase hex byte in the body keeps the value in scope.
fn is_twilio_public_sid(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.len() == 34
        && (bytes.starts_with(b"AC") || bytes.starts_with(b"SK"))
        && bytes[2..]
            .iter()
            .all(|&byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

// --- names: built-in vs. ruleset-supplied ----------------------------------

/// Where [`assignment_confidence`] draws its high-signal/ambiguous name
/// vocabulary from. `BuiltIn` is exactly today's behavior — unchanged code
/// path, so a caller who never loads a ruleset sees byte-identical output.
/// `Ruleset` is the declarative ruleset's names section (issue #484): it
/// checks only the caller-supplied list, never [`HIGH_SIGNAL_NAMES`] (point
/// 1's "ambiguous names only" decision — a ruleset cannot add to the
/// high-signal bucket in this revision), always at
/// [`AMBIGUOUS_ENTROPY_THRESHOLD`] and always [`Confidence::Medium`], never
/// promoted to [`Confidence::High`] regardless of entropy. That fixed
/// ceiling is what re-establishes issue #495's containment argument for
/// this path: registered as a separate custom detector
/// ([`RULESET_NAMES_DETECTOR_ID`]) after every built-in, claiming only
/// `Specificity::Contextual` and `Confidence::Medium`, it can never overturn
/// a built-in's resolved finding through the pipeline's specificity or
/// registration-order tie-break, the same property a value-section ruleset
/// detector already has.
#[derive(Clone, Debug, PartialEq, Eq)]
enum NameSource {
    /// The built-in [`HIGH_SIGNAL_NAMES`]/[`AMBIGUOUS_NAMES`] vocabulary.
    BuiltIn,
    /// A ruleset's caller-supplied ambiguous-bucket names, already
    /// normalized and deduplicated against the built-in vocabulary by
    /// `crate::ruleset`.
    Ruleset(Vec<String>),
}

// --- confidence -----------------------------------------------------------

fn assignment_confidence(
    name: &str,
    value: &str,
    form: ValueForm,
    names: &NameSource,
    query: bool,
) -> Option<Confidence> {
    // Only an eligible name can yield a confidence, so an ineligible one
    // (`status=200`, `latency_ms=12`) is rejected before the value's
    // reference checks and entropy are computed. Every check here is pure,
    // so the order changes the cost, never the result (issue #950).
    let (high_signal, ambiguous) = match names {
        NameSource::BuiltIn => {
            let high_signal = is_high_signal_name(name);
            let ambiguous = (!high_signal && is_ambiguous_vocabulary_name(name))
                || (query && QUERY_ONLY_AMBIGUOUS_NAMES.contains(&name));
            (high_signal, ambiguous)
        }
        NameSource::Ruleset(extra_ambiguous_names) => (
            false,
            extra_ambiguous_names.iter().any(|extra| extra == name),
        ),
    };
    if !high_signal && !ambiguous {
        return None;
    }
    if value.len() < MIN_CONTEXT_VALUE_LENGTH
        || value.len() > MAX_CONTEXT_VALUE_LENGTH
        || is_non_secret_reference(value, form)
        || is_confluent_key_id_assignment(name, value)
    {
        return None;
    }

    let entropy = crate::shannon_entropy(value);

    if high_signal {
        return Some(
            if value.len() >= MIN_HIGH_ENTROPY_LENGTH && entropy >= HIGH_ENTROPY_THRESHOLD {
                Confidence::High
            } else {
                Confidence::Medium
            },
        );
    }

    (value.len() >= MIN_HIGH_ENTROPY_LENGTH && entropy >= AMBIGUOUS_ENTROPY_THRESHOLD)
        .then_some(Confidence::Medium)
}

// --- assignment value spans ------------------------------------------------

/// A quote character (`"`/`'`) is a valid trailing boundary alongside the
/// existing whitespace/structural set: when a quoted value's own closing
/// quote is immediately followed by another quote rather than whitespace or
/// a structural character, that adjacent quote is closing an *enclosing*
/// quoted context with no separator of its own (`value="api_key="TOKEN""`,
/// issue #294) rather than continuing the same value. `is_unquoted_value_boundary`
/// already treats a bare quote as ending an unquoted value on the same
/// reasoning. A backtick is accepted for the same reason (issue #552): the
/// closing backtick of an enclosing Markdown inline-code span
/// (`` `api_key="TOKEN"` ``) sits directly against the value's own closing
/// quote with no separator, and rejecting it would silently drop the whole
/// assignment rather than merely mis-span it.
fn is_quoted_value_boundary(ch: Option<char>) -> bool {
    match ch {
        None => true,
        Some(c) => matches!(
            c,
            ' ' | '\t'
                | '\u{0B}'
                | '\u{0C}'
                | '\r'
                | '\n'
                | ','
                | ';'
                | '}'
                | ']'
                // The closing parenthesis of a single-line call whose last
                // argument is the quoted literal (`Client(api_key="...")`,
                // issue #866). Only a quoted value accepts it: an unquoted
                // value keeps `)` inside the value.
                | ')'
                | '"'
                | '\''
                | '`'
        ),
    }
}

/// A backtick terminates an unquoted value for the same reason it opens
/// one in [`is_prefix_boundary_char`] (issue #552): a Markdown inline-code
/// span wraps the whole assignment. Without it, `` `password=********` ``
/// read the closing backtick into the value, which slipped a masked filler
/// past its repeated-character exclusion and mis-scoped every unquoted
/// value's range by one byte under that envelope (issue #548, the
/// `context.markdown` metamorphic failure on `generic-token`). A real
/// secret containing a literal backtick, unquoted, is the accepted false
/// negative.
fn is_unquoted_value_boundary(ch: Option<char>) -> bool {
    match ch {
        None => true,
        Some(c) => matches!(
            c,
            ' ' | '\t'
                | '\u{0B}'
                | '\u{0C}'
                | '\r'
                | '\n'
                | ','
                | ';'
                | '}'
                | ']'
                | '"'
                | '\''
                | '`'
        ),
    }
}

/// Scans a `"..."` or `'...'` value starting at the opening quote, honoring
/// backslash-escaped quotes by parity, and returns its interior span.
/// Rejects values that cross a physical line or exceed the shared bound.
fn quoted_assignment_value(input: &str, opening_quote: usize) -> Option<(usize, usize)> {
    let quote = char_at(input, opening_quote)?;
    if quote != '"' && quote != '\'' {
        return None;
    }
    let start = opening_quote + quote.len_utf8();
    let mut cursor = start;
    let mut backslash_run: u32 = 0;

    while let Some(ch) = char_at(input, cursor) {
        if ch == '\r' || ch == '\n' {
            return None;
        }
        if cursor - start > MAX_CONTEXT_VALUE_LENGTH {
            return None;
        }
        if ch == '\\' {
            backslash_run += 1;
            cursor += ch.len_utf8();
            continue;
        }
        if ch == quote && backslash_run.is_multiple_of(2) {
            let after = char_at(input, cursor + ch.len_utf8());
            return is_quoted_value_boundary(after).then_some((start, cursor));
        }
        backslash_run = 0;
        cursor += ch.len_utf8();
    }
    None
}

/// An interpolation/command-substitution opener whose closing delimiter
/// (`)`, `]`, or `}`) is also a generic unquoted-value boundary character --
/// so a plain boundary scan reaches it and stops *before* consuming it,
/// truncating the value one byte short of its real close (issue #279).
struct DelimitedOpener {
    open: &'static str,
    nest_open: char,
    close: char,
}

const DELIMITED_REFERENCE_OPENERS: &[DelimitedOpener] = &[
    DelimitedOpener {
        open: "$(",
        nest_open: '(',
        close: ')',
    },
    DelimitedOpener {
        open: "$[",
        nest_open: '[',
        close: ']',
    },
    DelimitedOpener {
        open: "#{",
        nest_open: '{',
        close: '}',
    },
    DelimitedOpener {
        open: "{env:",
        nest_open: '{',
        close: '}',
    },
    DelimitedOpener {
        open: "{file:",
        nest_open: '{',
        close: '}',
    },
];

/// Scans from `start` (an opener already matched at this position) to the
/// close that balances `nest_open`, rejecting a span that crosses a
/// physical line or exceeds the shared bound, mirroring
/// `quoted_assignment_value`. Nesting is honored so `$(echo $(date))`
/// resolves to its outer close rather than its first one.
fn scan_nested_delimiter(
    input: &str,
    start: usize,
    open_len: usize,
    nest_open: char,
    close: char,
) -> Option<usize> {
    let mut cursor = start + open_len;
    let mut depth: u32 = 1;
    while let Some(ch) = char_at(input, cursor) {
        if matches!(ch, '\r' | '\n') || cursor - start > MAX_CONTEXT_VALUE_LENGTH {
            return None;
        }
        if ch == nest_open {
            depth += 1;
        } else if ch == close {
            depth -= 1;
            if depth == 0 {
                return Some(cursor + ch.len_utf8());
            }
        }
        cursor += ch.len_utf8();
    }
    None
}

/// Scans from the opening backtick at `start` to its matching close,
/// honoring backslash-escaped backticks by parity like
/// `quoted_assignment_value`.
fn scan_backtick_delimiter(input: &str, start: usize) -> Option<usize> {
    let mut cursor = start + 1;
    let mut backslash_run: u32 = 0;
    while let Some(ch) = char_at(input, cursor) {
        if matches!(ch, '\r' | '\n') || cursor - start > MAX_CONTEXT_VALUE_LENGTH {
            return None;
        }
        if ch == '\\' {
            backslash_run += 1;
            cursor += ch.len_utf8();
            continue;
        }
        if ch == '`' && backslash_run.is_multiple_of(2) {
            return Some(cursor + ch.len_utf8());
        }
        backslash_run = 0;
        cursor += ch.len_utf8();
    }
    None
}

/// `true` when the character immediately after a matched delimiter close is
/// a legitimate unquoted-value boundary -- so `$(cmd)EXTRA` (the delimiter
/// embedded in a larger value) is rejected here and falls through to the
/// generic scan below, which captures it whole and leaves it detected.
fn delimited_reference_value(input: &str, start: usize) -> Option<(usize, usize)> {
    for opener in DELIMITED_REFERENCE_OPENERS {
        if input[start..].starts_with(opener.open) {
            let end = scan_nested_delimiter(
                input,
                start,
                opener.open.len(),
                opener.nest_open,
                opener.close,
            )?;
            return is_unquoted_value_boundary(char_at(input, end)).then_some((start, end));
        }
    }
    if char_at(input, start) == Some('`') {
        let end = scan_backtick_delimiter(input, start)?;
        return is_unquoted_value_boundary(char_at(input, end)).then_some((start, end));
    }
    None
}

/// `true` when `input[start..]` opens with a recognized opencode
/// substitution prefix (`{env:`/`{file:`), regardless of whether it goes on
/// to close with a matching `}` before the value ends.
fn starts_with_opencode_prefix(input: &str, start: usize) -> bool {
    OPENCODE_REFERENCE_OPENERS
        .iter()
        .any(|open| input[start..].starts_with(open))
}

/// Scans an unquoted value up to the next boundary character, rejecting
/// values that exceed the shared bound.
///
/// A value starting with `{` or `[` opens a YAML/JSON flow structure rather
/// than a scalar (`secret: {secretName: web-tls-cert}`), so scanning it as
/// an unquoted value would capture the nested key as if it were the
/// credential (issue #266, the same shape as #262). No real unquoted
/// credential in the syntaxes this detector targets legitimately begins
/// with either character, so treating them as an immediate boundary costs
/// no true positive.
///
/// `{env:...}`/`{file:...}` are exempt from that guard even when
/// `delimited_reference_value` above didn't resolve them to a bare
/// reference (i.e. one is embedded in a larger value, `{env:x}_EXTRA`):
/// without the exemption, the guard would return no value at all for the
/// whole assignment, silently dropping a candidate the paired-positive
/// requirement in issue #279 says must still be reported, rather than
/// merely mis-scoping its range. The narrow cost is a flow mapping whose
/// first key happens to be spelled `env`/`file` (`secret: {file: "/etc/x"}`)
/// losing the #266 guard's protection -- accepted because it is far rarer
/// than a real secret embedding one of these substitution prefixes.
fn unquoted_assignment_value(input: &str, start: usize) -> Option<(usize, usize)> {
    if let Some(span) = delimited_reference_value(input, start) {
        return Some(span);
    }
    if matches!(char_at(input, start), Some('{' | '['))
        && !starts_with_opencode_prefix(input, start)
    {
        return None;
    }
    let mut cursor = start;
    // `{`/`[` opened inside the value itself. While one is open, a `}`/`]`
    // closes it instead of ending the value (issue #815): a passphrase such
    // as `ab{{c}d$e]f` was otherwise cut at its first `}`, below the length
    // floor. The flow-mapping guard above still returns no value for a value
    // that *starts* with `{`/`[`.
    let mut open_brackets: u32 = 0;
    while let Some(ch) = char_at(input, cursor) {
        match ch {
            '{' | '[' => open_brackets += 1,
            '}' | ']' if open_brackets > 0 => {
                open_brackets -= 1;
                cursor += 1;
                continue;
            }
            _ => {}
        }
        // A backtick closes an inline-code span around the value, but one
        // *opening* the value with no closing partner (`delimited_reference_value`
        // has already declined it) is an unterminated template literal or
        // command substitution whose interior must still be reported.
        if is_unquoted_value_boundary(Some(ch)) && !(ch == '`' && cursor == start) {
            break;
        }
        // `refresh_token=VALUE&client_id=...`: the next form or query
        // parameter is not part of this value (issue #816).
        if cursor > start && starts_query_parameter(input, cursor) {
            break;
        }
        cursor += ch.len_utf8();
        if cursor - start > MAX_CONTEXT_VALUE_LENGTH {
            return None;
        }
    }
    (cursor > start).then_some((start, cursor))
}

/// Scans a value opened by an escaped quote (`\"...\"`), the form a JSON
/// document takes once it is serialized into another JSON string
/// (`{"body":"{\"access_token\":\"...\"}"}`, issue #815). The value ends at
/// the first quote preceded by exactly one backslash; a deeper escape
/// (`\\\"`) belongs to the inner string's own content. Like
/// [`quoted_assignment_value`], it never crosses a line.
fn escaped_quoted_assignment_value(input: &str, backslash: usize) -> Option<(usize, usize)> {
    let quote = char_at(input, backslash + 1)?;
    if quote != '"' && quote != '\'' {
        return None;
    }
    let start = backslash + 1 + quote.len_utf8();
    let mut cursor = start;
    let mut backslash_run: u32 = 0;
    while let Some(ch) = char_at(input, cursor) {
        if ch == '\r' || ch == '\n' || cursor - start > MAX_CONTEXT_VALUE_LENGTH {
            return None;
        }
        if ch == '\\' {
            backslash_run += 1;
            cursor += 1;
            continue;
        }
        if ch == quote && backslash_run == 1 {
            let after = char_at(input, cursor + ch.len_utf8());
            return is_quoted_value_boundary(after).then_some((start, cursor - 1));
        }
        backslash_run = 0;
        cursor += ch.len_utf8();
    }
    None
}

fn assignment_value(input: &str, start: usize) -> Option<(usize, usize, ValueForm)> {
    match char_at(input, start) {
        Some('"' | '\'') => quoted_assignment_value(input, start)
            .map(|(value_start, value_end)| (value_start, value_end, ValueForm::Quoted)),
        // An Objective-C / C# verbatim string literal (`@"..."`, issue #815).
        Some('@') if char_at(input, start + 1) == Some('"') => {
            quoted_assignment_value(input, start + 1)
                .map(|(value_start, value_end)| (value_start, value_end, ValueForm::Quoted))
        }
        Some('\\') if matches!(char_at(input, start + 1), Some('"' | '\'')) => {
            escaped_quoted_assignment_value(input, start)
                .map(|(value_start, value_end)| (value_start, value_end, ValueForm::Quoted))
        }
        _ => unquoted_assignment_value(input, start)
            .map(|(value_start, value_end)| (value_start, value_end, ValueForm::Unquoted)),
    }
}

// --- `ASSIGNMENT_PREFIX_PATTERN`: (?:^|[\s{,;])["']?([A-Za-z][A-Za-z0-9_.-]*)["']?\s*(?:=|:)\s* ---
//
// A raw `"`/`'` is also accepted here, extending the mirrored alternation
// (issue #294). It never collides with the `["']?` name-quoting lookahead
// already consumed inside `parse_name_and_operator`: that optional quote is
// stripped from the position *after* a boundary char, so a name can be
// preceded by at most one quote either way, and the two never fire on the
// same character. Treating a bare quote as a boundary lets a nested
// assignment be recognized immediately inside an enclosing quoted value with
// no separator between them (`value="api_key="TOKEN""`), the same way `;`
// already does when a separator is present
// (`nested_assignments_emit_overlapping_contextual_candidates`).
// A backtick is accepted for the same reason (issue #552): Markdown inline
// code (a value wrapped in a matching pair of backticks) opens directly on
// the name with no whitespace or other separator, so without a backtick
// alternative the whole assignment is invisible rather than merely
// mis-spanned -- a metamorphic markdown-context transform of an
// otherwise-detected assignment turns into a silent miss, not a
// shifted-offset match.
fn is_prefix_boundary_char(ch: char) -> bool {
    is_js_whitespace(ch) || matches!(ch, '{' | ',' | ';' | '"' | '\'' | '`')
}

/// Parses `["']?([A-Za-z][A-Za-z0-9_.-]*)["']?\s*(?:=|:)\s*` starting at
/// `start`, returning the captured name span and the offset right after the
/// trailing whitespace.
///
/// The optional quotes are pure lookahead in effect: a quote character can
/// never satisfy `[A-Za-z]`, so greedily consuming an optional quote when
/// present never forecloses a match that skipping it would have found.
///
/// The `\s*` run after the operator stops at a line terminator instead of
/// crossing it, unlike the ECMAScript oracle's `\s` class (and unlike the
/// `\s*` run before the operator, which is unchanged: a name legitimately
/// arrives on one physical line and its operator on the next when an
/// incremental caller's chunk boundary falls between them). A value belongs
/// on the operator's own line, so a key with no value before end-of-line
/// (`secret:\n  nested: ...`, an interactive `Password:\n` prompt) never
/// walks onto the next line's first token as if it were the value. See
/// `docs/specs/contextual-detection.md`.
fn parse_name_and_operator(input: &str, start: usize) -> Option<(usize, usize, usize)> {
    let mut cursor = start;
    if let Some(ch @ ('"' | '\'')) = char_at(input, cursor) {
        cursor += ch.len_utf8();
    }

    let name_start = cursor;
    let first = char_at(input, cursor)?;
    if !first.is_ascii_alphabetic() {
        return None;
    }
    cursor += 1;
    while let Some(ch) = char_at(input, cursor) {
        if ch.is_ascii_alphanumeric() || matches!(ch, '_' | '.' | '-') {
            cursor += 1;
        } else {
            break;
        }
    }
    let name_end = cursor;

    if let Some(ch @ ('"' | '\'')) = char_at(input, cursor) {
        cursor += ch.len_utf8();
    } else if char_at(input, cursor) == Some('\\')
        && let Some(ch @ ('"' | '\'')) = char_at(input, cursor + 1)
    {
        // A JSON document serialized into another JSON string escapes its
        // quotes (`{\"access_token\":\"...\"}`, issue #815).
        cursor += 1 + ch.len_utf8();
    }
    cursor = skip_while_chars(input, cursor, is_js_whitespace);
    match char_at(input, cursor) {
        Some('=') => cursor += 1,
        Some(':') => {
            cursor += 1;
            // Go, Pascal and Makefile `:=` (issue #815): without this the
            // `=` became the first byte of the value.
            if char_at(input, cursor) == Some('=') {
                cursor += 1;
            }
        }
        _ => return None,
    }
    cursor = skip_while_chars(input, cursor, is_horizontal_js_whitespace);

    Some((name_start, name_end, cursor))
}

/// `true` at `&name=` — the start of the next `application/x-www-form-urlencoded`
/// or URL query parameter (issue #816).
fn starts_query_parameter(input: &str, pos: usize) -> bool {
    char_at(input, pos) == Some('&') && parse_query_parameter(input, pos + 1).is_some()
}

/// Parses `([A-Za-z][A-Za-z0-9_.-]*)=` at `start`: a URL query, fragment or
/// form-body parameter name followed directly by `=` (issue #816). No
/// whitespace or quote is allowed around the name, which is what keeps a
/// prose `?`, `&` or `#` from opening an assignment.
fn parse_query_parameter(input: &str, start: usize) -> Option<(usize, usize, usize)> {
    let bytes = input.as_bytes();
    if !bytes.get(start)?.is_ascii_alphabetic() {
        return None;
    }
    let mut cursor = start + 1;
    while bytes
        .get(cursor)
        .is_some_and(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'-'))
    {
        cursor += 1;
    }
    (bytes.get(cursor) == Some(&b'=')).then_some((start, cursor, cursor + 1))
}

/// A query parameter value ends at the next parameter (`&`), the fragment
/// (`#`), or anything that ends a URL in running text.
fn query_parameter_value(input: &str, start: usize) -> Option<(usize, usize)> {
    let mut cursor = start;
    while let Some(ch) = char_at(input, cursor) {
        if is_unquoted_value_boundary(Some(ch)) || matches!(ch, '&' | '#' | ')' | '<' | '>') {
            break;
        }
        cursor += ch.len_utf8();
        if cursor - start > MAX_CONTEXT_VALUE_LENGTH {
            return None;
        }
    }
    (cursor > start).then_some((start, cursor))
}

/// The byte spans of every `otpauth://` URI (scheme matched
/// case-insensitively, up to the end of the line or the next quote, so a
/// label with an unencoded space still counts), in one linear
/// pass. A query parameter inside one belongs to `otpauth-uri`'s contract,
/// which decides whether the URI is valid; a URI it declines stays silent
/// instead of being claimed here, the same deference a provider-named
/// assignment gets (issue #702, applied by issue #816).
fn otpauth_uri_spans(input: &str) -> Vec<(usize, usize)> {
    const SCHEME: &[u8] = b"otpauth://";
    let bytes = input.as_bytes();
    let mut spans = Vec::new();
    let mut index = 0usize;
    while index + SCHEME.len() <= bytes.len() {
        if bytes[index..index + SCHEME.len()].eq_ignore_ascii_case(SCHEME) {
            let mut end = index + SCHEME.len();
            while end < bytes.len() && !matches!(bytes[end], b'\r' | b'\n' | b'"' | b'\'' | b'`') {
                end += 1;
            }
            spans.push((index, end));
            index = end;
        } else {
            index += 1;
        }
    }
    spans
}

/// JSON Web Key members that hold secret key material: the symmetric key
/// `k` (RFC 7518 section 6.4.1) and the RSA/EC/OKP private members `d`,
/// `p`, `q`, `dp`, `dq`, `qi` (sections 6.2.2 and 6.3.2, RFC 8037).
/// Public members (`n`, `e`, `x`, `y`, `crv`, `kid`) are never listed.
const JWK_SECRET_MEMBERS: &[&str] = &["k", "d", "p", "q", "dp", "dq", "qi"];

/// The byte spans of every line ([`super::text::lines`]) that carries a
/// quoted `"kty"` member, in one linear pass, so a JWK member check never
/// rescans a line.
fn jwk_line_spans(input: &str) -> Vec<(usize, usize)> {
    super::text::lines(input)
        .filter(|&(start, end)| input[start..end].contains("\"kty\""))
        .collect()
}

/// `true` when the assignment name at `name_start..name_end` is a quoted
/// JWK secret member (`"k":`, `"d":`) on a line that also carries `"kty"`
/// (issue #821). The `"kty"` requirement is what keeps a one-letter JSON
/// key elsewhere out of scope; a pretty-printed JWK whose `"kty"` is on
/// another line is the accepted false negative, because whole-input and
/// incremental scans must agree and neither holds a line open for it.
fn is_jwk_secret_member(
    input: &str,
    name_start: usize,
    name_end: usize,
    jwk_lines: &[(usize, usize)],
) -> bool {
    JWK_SECRET_MEMBERS.contains(&&input[name_start..name_end])
        && input[..name_start].ends_with('"')
        && input[name_end..].starts_with('"')
        && jwk_lines
            .partition_point(|&(start, _)| start <= name_start)
            .checked_sub(1)
            .is_some_and(|index| name_start < jwk_lines[index].1)
}

/// A matched assignment prefix: the name span, the offset where the value
/// starts, and whether the name was a URL query/fragment/form parameter.
struct AssignmentPrefix {
    name_start: usize,
    name_end: usize,
    prefix_end: usize,
    query: bool,
    /// The name directly follows a `(`: a keyword argument opening a
    /// single-line call. Only a quoted literal value qualifies (issue #866).
    call_open: bool,
}

/// Tries the `(?:^|[\s{,;])` prefix alternative at `pos` (line start first,
/// per regex alternation order) followed by the rest of the pattern, then
/// the URL query/fragment/form alternative `[?&#]name=` (issue #816).
fn try_match_assignment_prefix(input: &str, pos: usize) -> Option<AssignmentPrefix> {
    let plain = |(name_start, name_end, prefix_end)| AssignmentPrefix {
        name_start,
        name_end,
        prefix_end,
        query: false,
        call_open: false,
    };
    if is_line_start(input, pos)
        && let Some(m) = parse_name_and_operator(input, pos)
    {
        return Some(plain(m));
    }
    let ch = char_at(input, pos)?;
    if is_prefix_boundary_char(ch) {
        return parse_name_and_operator(input, pos + ch.len_utf8()).map(plain);
    }
    // Issue #1038: a keyed environment store, `os.environ["NAME"] = "<v>"`
    // or `os.environ.setdefault("NAME", "<v>")`, is the assignment
    // `NAME = "<v>"`; a call takes only a quoted literal.
    if matches!(ch, '[' | '(')
        && let Some(store) = super::text::keyed_store_prefix(input, pos)
    {
        return Some(AssignmentPrefix {
            name_start: store.name_start,
            name_end: store.name_end,
            prefix_end: store.value_start,
            query: false,
            call_open: store.call,
        });
    }
    if ch == '(' {
        return parse_name_and_operator(input, pos + 1).map(
            |(name_start, name_end, prefix_end)| AssignmentPrefix {
                name_start,
                name_end,
                prefix_end,
                query: false,
                call_open: true,
            },
        );
    }
    if matches!(ch, '?' | '&' | '#') {
        return parse_query_parameter(input, pos + 1).map(|(name_start, name_end, prefix_end)| {
            AssignmentPrefix {
                name_start,
                name_end,
                prefix_end,
                query: true,
                call_open: false,
            }
        });
    }
    None
}

fn assignment_candidates(input: &str, names: &NameSource) -> Vec<Candidate> {
    let mut candidates = Vec::new();
    let mut cursor = 0usize;
    let otpauth_spans = otpauth_uri_spans(input);
    let jwk_lines = jwk_line_spans(input);
    let mut templates = OpenTemplateTracker::default();
    // One buffer for every assignment's normalized name (issue #984).
    let mut normalized = String::new();

    while cursor < input.len() {
        let Some(AssignmentPrefix {
            name_start,
            name_end,
            prefix_end,
            query,
            call_open,
        }) = try_match_assignment_prefix(input, cursor).filter(|prefix| {
            // The spans are sorted and disjoint: only the last one that
            // starts before `cursor` can contain it.
            !prefix.query
                || otpauth_spans
                    .partition_point(|&(start, _)| start < cursor)
                    .checked_sub(1)
                    .is_none_or(|index| otpauth_spans[index].1 <= cursor)
        })
        else {
            cursor += char_at(input, cursor).map_or(1, char::len_utf8);
            continue;
        };

        let value_span = if query {
            query_parameter_value(input, prefix_end)
                .map(|(value_start, value_end)| (value_start, value_end, ValueForm::Unquoted))
        } else {
            assignment_value(input, prefix_end)
        };
        if let Some((value_start, value_end, form)) = value_span
            && (!call_open || form == ValueForm::Quoted)
        {
            let value = &input[value_start..value_end];
            normalize_name_into(&input[name_start..name_end], &mut normalized);
            if matches!(names, NameSource::BuiltIn)
                && is_jwk_secret_member(input, name_start, name_end, &jwk_lines)
            {
                // A JWK secret member is private key material; it takes the
                // `private_key` name's high-signal bucket (issue #821).
                normalized.clear();
                normalized.push_str("private_key");
            } else if matches!(names, NameSource::BuiltIn)
                && is_unmasked_under_masking_lead(&normalized, value)
                && let Some((_, rest)) = value_checked_lead_rest(&normalized)
            {
                // Issue #1018: an unmasked value under `masked_api_key` is
                // judged under `api_key`.
                let rest = rest.to_owned();
                normalized.clear();
                normalized.push_str(&rest);
            } else if matches!(names, NameSource::BuiltIn)
                && &input[name_start..name_end] == "value"
                && let Some(paired) = super::text::list_item_paired_name(
                    input,
                    super::text::line_around(input, name_start, name_end),
                )
            {
                // Issue #1016: a Kubernetes-style `env` entry's `value:` is
                // assigned to the name its sibling `name:` key gives.
                normalize_name_into(paired, &mut normalized);
            }
            // The templated-lookup check runs only for a pair that would
            // otherwise be reported (issue #989).
            if !is_colon_scope_identifier(&input[name_end..value_start], value)
                && let Some(confidence) =
                    assignment_confidence(&normalized, value, form, names, query)
                && !is_templated_lookup_path(&mut templates, input, name_start, value)
                && let Some(range) = ByteRange::new(value_start, value_end)
            {
                let name_signal =
                    if matches!(names, NameSource::BuiltIn) && is_high_signal_name(&normalized) {
                        "high-signal-name"
                    } else {
                        "ambiguous-name"
                    };
                let entropy_signal = if confidence == Confidence::High {
                    "bounded-entropy"
                } else {
                    "context-only"
                };
                candidates.push(
                    Candidate::new("contextual_secret", confidence, range)
                        .with_specificity(Specificity::Contextual)
                        .with_signals([name_signal, entropy_signal]),
                );
            }
        }

        // Resume on the last whitespace byte the operator consumed, not after
        // it: that byte is still the prefix boundary of whatever name opens
        // the value. Resuming past it made an unquoted value that is itself
        // an assignment unreachable, so `login failed: password=V` read only
        // `failed: ...` and never evaluated `password=V` (issue #812). A
        // quoted value was already reached through its opening quote.
        cursor = prev_char(input, prefix_end)
            .filter(|&ch| is_horizontal_js_whitespace(ch))
            .map_or(prefix_end, |ch| prefix_end - ch.len_utf8());
    }

    candidates
}

/// `true` when the assignment starting at `name_start` sits inside a
/// `{{ ... }}` template expression still open on its line and its value is
/// a secret-manager path: a lookup-plugin term such as
/// `'secret=kv/data/app:token'` inside
/// `{{ lookup('community.hashi_vault.hashi_vault', ...) }}` (issue #911).
/// The term names where the secret lives; the template renders it later.
///
/// A path is two or more `/`-joined segments of `[A-Za-z0-9_.-]`, with an
/// optional `:field` suffix. A literal term inside a lookup
/// (`token=<value>` with no `/`) stays detected, and so does any assignment
/// outside an open template.
///
/// Whether a template is open comes from `templates`, which the assignment
/// loop carries forward, so a long single line costs linear time rather than
/// one look back to the line start per assignment (issue #989).
fn is_templated_lookup_path(
    templates: &mut OpenTemplateTracker,
    input: &str,
    name_start: usize,
    value: &str,
) -> bool {
    is_secret_manager_path(value) && templates.is_open_at(input, name_start)
}

/// `true` for a two-or-more-segment `/`-joined path of `[A-Za-z0-9_.-]`
/// segments with an optional non-empty `:[A-Za-z0-9_-]+` field suffix.
fn is_secret_manager_path(value: &str) -> bool {
    let path = value.split_once(':').map_or(value, |(path, _)| path);
    let field_ok = value.split_once(':').is_none_or(|(_, field)| {
        !field.is_empty()
            && field
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'))
    });
    field_ok
        && path.split('/').count() >= 2
        && path.split('/').all(|segment| {
            !segment.is_empty()
                && segment
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'-'))
        })
}

/// Forward state for "is a `{{` still open on this line": whether the text
/// from the line start up to `position` contains a `{{` with no `}}` after
/// the last one.
///
/// It answers exactly what a look back would: find the last `{{` between
/// the line start (after the last `\n` or `\r`) and the query position, and
/// report it open unless a `}}` follows it there. Overlapping runs such as
/// `{{{` and `}}}` resolve the same way, because the last `{{` of a run
/// starts on the run's second-to-last brace and a `}}` needs two closing
/// braces after it. Each byte is visited once while queries move forward.
#[derive(Default)]
struct OpenTemplateTracker {
    /// Bytes before this offset have been folded into the state.
    position: usize,
    /// The byte before `position`, or `0` at the start of the input.
    previous: u8,
    /// A `{{` occurs on the current line before `position`.
    opened: bool,
    /// A `}}` occurs after the last such `{{`.
    closed: bool,
}

impl OpenTemplateTracker {
    /// Whether a `{{` is still open on the line containing `position`, just
    /// before `position`.
    fn is_open_at(&mut self, input: &str, position: usize) -> bool {
        let end = position.min(input.len());
        if end < self.position {
            // Queries only move forward; restart rather than answer wrongly.
            *self = Self::default();
        }
        let bytes = input.as_bytes();
        for &byte in &bytes[self.position..end] {
            match byte {
                b'\n' | b'\r' => {
                    self.opened = false;
                    self.closed = false;
                }
                b'{' if self.previous == b'{' => {
                    self.opened = true;
                    self.closed = false;
                }
                b'}' if self.previous == b'}' && self.opened => self.closed = true,
                _ => {}
            }
            self.previous = byte;
        }
        self.position = end;
        self.opened && !self.closed
    }
}

// --- single-line call with one positional literal (issue #866) ---------------

/// Candidates for `callee("literal")` where the callee's own name is a
/// high-signal credential name (`api_key("...")`, `client.setApiKey("...")`,
/// `WithAPIKey("...")`) and the quoted literal is the call's only argument.
///
/// The callee is the name-vocabulary evidence, so a constructor with no
/// secret-bearing name (`new Client("...")`, `Exa("...")`) is deliberately not
/// matched here; provider-named constructors belong to their provider
/// detectors. Because a positional literal has no `name =` operator to
/// vouch for it, the value must clear the stricter of the existing floors:
/// the high-confidence length and entropy floors, no whitespace, and at least
/// one ASCII letter and one ASCII digit, and a value containing `-`, `_` or
/// `.` must mix letter cases. That keeps prompt and label strings
/// (`password("Enter your password")`) and identifier-like names
/// (`secret("aws-credentials-prod")`) silent. Ambiguous names (`auth`,
/// `credential`) never qualify.
fn call_argument_candidates(input: &str) -> Vec<Candidate> {
    let bytes = input.as_bytes();
    let mut candidates = Vec::new();
    for (open, _) in input.match_indices('(') {
        let mut callee_start = open;
        while callee_start > 0 && is_identifier_byte(bytes[callee_start - 1]) {
            callee_start -= 1;
        }
        if callee_start == open || !bytes[callee_start].is_ascii_alphabetic() {
            continue;
        }
        let normalized = normalize_name(&input[callee_start..open]);
        if !is_high_signal_name(&normalized) {
            continue;
        }
        let quote_pos = skip_while_chars(input, open + 1, is_horizontal_js_whitespace);
        let Some((value_start, value_end)) = quoted_assignment_value(input, quote_pos) else {
            continue;
        };
        // The closing quote must be followed, past spaces, by the call's own
        // closing parenthesis: the literal is the whole argument list.
        let after_quote = skip_while_chars(input, value_end + 1, is_horizontal_js_whitespace);
        if char_at(input, after_quote) != Some(')') {
            continue;
        }
        let value = &input[value_start..value_end];
        let separated = value.bytes().any(|byte| matches!(byte, b'-' | b'_' | b'.'));
        if !value.bytes().all(|byte| byte.is_ascii_graphic())
            || !value.bytes().any(|byte| byte.is_ascii_alphabetic())
            || !value.bytes().any(|byte| byte.is_ascii_digit())
            // A separated value in one letter case is a slug or an
            // environment-variable name, not a token.
            || (separated
                && !(value.bytes().any(|byte| byte.is_ascii_uppercase())
                    && value.bytes().any(|byte| byte.is_ascii_lowercase())))
        {
            continue;
        }
        if assignment_confidence(
            &normalized,
            value,
            ValueForm::Quoted,
            &NameSource::BuiltIn,
            false,
        ) != Some(Confidence::High)
        {
            continue;
        }
        if let Some(range) = ByteRange::new(value_start, value_end) {
            candidates.push(
                Candidate::new("contextual_secret", Confidence::High, range)
                    .with_specificity(Specificity::Contextual)
                    .with_signals(["high-signal-name", "bounded-entropy", "sdk-call-argument"]),
            );
        }
    }
    candidates
}

// --- `AUTHORIZATION_PATTERN`: (?:^|[\r\n])[ \t]*authorization[ \t]*:[ \t]*(basic|token|key)[ \t]+([A-Za-z0-9+/=_-]{12,}) ---

fn is_space_or_tab_byte(byte: u8) -> bool {
    byte == b' ' || byte == b'\t'
}

fn is_authorization_value_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/' | b'=' | b'_' | b'-')
}

/// A `Key` scheme value byte: the authorization alphabet plus `:`, because
/// fal's documented `Authorization: Key <key_id>:<key_secret>` joins its two
/// halves with a colon (issue #919). Ending the value at the colon would
/// redact the public id half and leave the secret half readable.
fn is_key_scheme_value_byte(byte: u8) -> bool {
    is_authorization_value_byte(byte) || byte == b':'
}

struct AuthorizationMatch {
    scheme: &'static str,
    value_start: usize,
    value_end: usize,
}

fn parse_authorization_from(input: &str, start: usize) -> Option<AuthorizationMatch> {
    let bytes = input.as_bytes();
    let mut cursor = start + ascii_run_len(bytes, start, is_space_or_tab_byte);
    // `Proxy-Authorization` carries the same credentials grammar
    // (RFC 7235 section 4.4, issue #818).
    if starts_with_ci(input, cursor, "proxy-authorization") {
        cursor += "proxy-".len();
    }
    if !starts_with_ci(input, cursor, "authorization") {
        return None;
    }
    cursor += "authorization".len();
    // A quoted header-map key (`"authorization": "Basic ..."`, issue #818).
    if matches!(bytes.get(cursor), Some(b'"' | b'\'')) {
        cursor += 1;
    }
    cursor += ascii_run_len(bytes, cursor, is_space_or_tab_byte);
    if bytes.get(cursor) != Some(&b':') {
        return None;
    }
    cursor += 1;
    cursor += ascii_run_len(bytes, cursor, is_space_or_tab_byte);
    if matches!(bytes.get(cursor), Some(b'"' | b'\'')) {
        cursor += 1;
    }

    let scheme = if starts_with_ci(input, cursor, "basic") {
        cursor += "basic".len();
        "basic"
    } else if starts_with_ci(input, cursor, "token") {
        cursor += "token".len();
        "token"
    } else if starts_with_ci(input, cursor, "key") {
        // fal's scheme (issue #919): `Authorization: Key <id>:<secret>`.
        cursor += "key".len();
        "key"
    } else {
        return None;
    };

    let ws_len = ascii_run_len(bytes, cursor, is_space_or_tab_byte);
    if ws_len == 0 {
        return None;
    }
    let value_start = cursor + ws_len;
    let mut value_len = if scheme == "key" {
        ascii_run_len(bytes, value_start, is_key_scheme_value_byte)
    } else {
        ascii_run_len(bytes, value_start, is_authorization_value_byte)
    };
    // A trailing colon joins nothing (`Key <value>: prose`).
    while value_len > 0 && bytes[value_start + value_len - 1] == b':' {
        value_len -= 1;
    }
    if value_len < MIN_AUTHORIZATION_VALUE_LENGTH {
        return None;
    }

    Some(AuthorizationMatch {
        scheme,
        value_start,
        value_end: value_start + value_len,
    })
}

fn try_match_authorization_at(input: &str, pos: usize) -> Option<AuthorizationMatch> {
    if is_line_start(input, pos)
        && let Some(m) = parse_authorization_from(input, pos)
    {
        return Some(m);
    }
    match char_at(input, pos) {
        Some(ch @ ('\r' | '\n')) => parse_authorization_from(input, pos + ch.len_utf8()),
        // Mid-line, after any byte that cannot continue a header name: a
        // quoted `curl -H 'Authorization: Basic ...'` argument, a JSON
        // string, a log prefix (issue #818). `bearer-token` already matches
        // `Bearer` in the same positions. Only `Basic` is taken mid-line: a
        // mid-line `Authorization: token ...` is the header provider
        // detectors (`travisci-api-token`, `github-token`) key on, and an
        // always-redact generic candidate would take the span from them.
        // `Key` is taken mid-line too (issue #919): fal documents it in a
        // curl `-H` argument, and no provider detector keys on it.
        Some(ch)
            if matches!(ch, 'a' | 'A' | 'p' | 'P')
                && prev_char(input, pos).is_some_and(|previous| {
                    !previous.is_ascii_alphanumeric()
                        && !matches!(previous, '_' | '-' | '\r' | '\n')
                }) =>
        {
            parse_authorization_from(input, pos).filter(|m| matches!(m.scheme, "basic" | "key"))
        }
        _ => None,
    }
}

fn authorization_candidates(input: &str) -> Vec<Candidate> {
    let mut candidates = Vec::new();
    let mut cursor = 0usize;

    while cursor < input.len() {
        let Some(m) = try_match_authorization_at(input, cursor) else {
            cursor += char_at(input, cursor).map_or(1, char::len_utf8);
            continue;
        };

        let value = &input[m.value_start..m.value_end];
        if !is_non_secret_reference(value, ValueForm::Unquoted)
            && let Some(range) = ByteRange::new(m.value_start, m.value_end)
        {
            let confidence = if value.len() >= MIN_HIGH_ENTROPY_LENGTH
                && crate::shannon_entropy(value) >= HIGH_ENTROPY_THRESHOLD
            {
                Confidence::High
            } else {
                Confidence::Medium
            };
            candidates.push(
                Candidate::new("authorization_credential", confidence, range)
                    .with_specificity(Specificity::Structural)
                    .with_signals([format!("authorization-{}-scheme", m.scheme)]),
            );
        }

        cursor = m.value_end.max(cursor + 1);
    }

    candidates
}

// --- bare vendor-prefixed policy candidates -----------------------------

/// `OpenAI` `sk-` namespaces whose legacy and early-project/service-account/
/// admin body width is documented as exactly 48 `[A-Za-z0-9]` bytes
/// (`docs/decisions/2026-09-17-freeze-precision-contracts-for-seven-provider-families.md`,
/// `OpenAI` row, issue #368). That decision requires the `T3BlbkFJ` marker for `openai-token`'s
/// own `openai_api_key` classification; a value in this exact shape that
/// lacks the marker — an unrotated pre-2024 legacy key, or a near-miss that
/// merely mutated the marker — is not reclassified as one here. It is still
/// the credential most likely to leak bare, in a `.env` file, a notebook, or
/// a chat log, and no other default detector claims it (issue #552).
/// Classified generic rather than `openai_api_key`, at [`Confidence::Medium`]
/// and [`Specificity::Entropy`] — below every provider contract's
/// [`Specificity::Provider`] — so an in-contract key always wins overlap and
/// keeps its own finding untouched.
const VENDOR_PREFIXED_POLICY_PREFIXES: [&str; 4] = ["sk-proj-", "sk-svcacct-", "sk-admin-", "sk-"];
const VENDOR_PREFIXED_POLICY_BODY_LEN: usize = 48;

/// Every boundary-delimited, high-entropy `sk-`-family bare value, left to
/// right. [`pattern::scan_prefixed_shapes`] picks the longest matching
/// namespace at each position, so `sk-proj-...` is never misread as a bare
/// `sk-` run over the `proj-` literal. Exact length and an
/// alphanumeric-only body are the whole discriminator: unlike Anthropic's
/// `sk-ant-...` or `OpenRouter`'s `sk-or-...`, whose namespace dash sits well
/// inside the first 48 bytes and so never reaches the required run length,
/// no reject list is needed.
fn bare_vendor_prefix_candidates(input: &str) -> Vec<Candidate> {
    let shapes: Vec<PrefixShape<'_>> = VENDOR_PREFIXED_POLICY_PREFIXES
        .iter()
        .map(|prefix| {
            PrefixShape::exact(
                prefix,
                VENDOR_PREFIXED_POLICY_BODY_LEN,
                pattern::is_alnum,
                &[],
            )
            .with_post_check(vendor_prefixed_policy_body_is_high_entropy)
        })
        .collect();
    pattern::scan_prefixed_shapes(input, &shapes, pattern::is_alnum_dash)
        .into_iter()
        .filter_map(|(start, end, _signals)| {
            let range = ByteRange::new(start, end)?;
            Some(
                Candidate::new("vendor_prefixed_credential", Confidence::Medium, range)
                    .with_specificity(Specificity::Entropy)
                    .with_signals(["vendor-prefix-policy"]),
            )
        })
        .collect()
}

/// The 48-byte body is genuinely high entropy, not ordinary prose or an
/// identifier that merely happens to start with a known prefix. Mirrors the
/// bar a high-signal contextual assignment's value already has to clear
/// ([`HIGH_ENTROPY_THRESHOLD`]).
fn vendor_prefixed_policy_body_is_high_entropy(bytes: &[u8], _start: usize, end: usize) -> bool {
    let body_start = end - VENDOR_PREFIXED_POLICY_BODY_LEN;
    // The alphabet is `[A-Za-z0-9]` only, so this slice is always ASCII.
    let body = std::str::from_utf8(&bytes[body_start..end]).unwrap_or_default();
    crate::shannon_entropy(body) >= HIGH_ENTROPY_THRESHOLD
}

// --- `.npmrc` credential keys (issue #1024) ----------------------------------

/// The `.npmrc` keys that carry a registry credential: a bearer token, the
/// Base64 of `user:password`, and the Base64 of a password. The leading `_`
/// keeps them outside the assignment grammar (a name starts with a letter),
/// so before issue #1024 `//registry.npmjs.org/:_authToken=<value>` gave no
/// finding unless the value was an `npm_` token.
const NPMRC_CREDENTIAL_KEYS: [&str; 3] = ["_authToken", "_auth", "_password"];

/// Candidates for the value of an `.npmrc` credential key, registry-scoped
/// (`//host/path/:_authToken=...`, the `:` directly after a `/`) or bare at
/// the start of a line (optionally indented), then `=` with optional
/// horizontal whitespace around it (issue #1024,
/// `docs/audits/evidence/1012/npm-legacy-token.md`). The value is one
/// quoted literal or the unquoted run up to whitespace or a quote. These keys carry a
/// credential by construction, whatever the registry and token shape, so
/// every value that survives the shared reference and placeholder
/// exclusions (`${NPM_TOKEN}`, `<token>`, masked displays) is `High`
/// `contextual_secret`; the host, not the shape, decides the issuer, so no
/// provider type is claimed. Other `.npmrc` keys (`username`, `email`,
/// `registry`) are not credentials and stay silent.
fn npmrc_credential_candidates(input: &str) -> Vec<Candidate> {
    let mut candidates = Vec::new();
    // Key starts in input order, so a value run measured once can be
    // reused by every later key inside it.
    let mut key_starts: Vec<usize> = input
        .match_indices("_auth")
        .chain(input.match_indices("_password"))
        .map(|(start, _)| start)
        .collect();
    key_starts.sort_unstable();
    let mut run_end = 0usize;
    for key_start in key_starts {
        let Some(key) = NPMRC_CREDENTIAL_KEYS
            .iter()
            .filter(|key| input[key_start..].starts_with(**key))
            .max_by_key(|key| key.len())
        else {
            continue;
        };
        let bytes = input.as_bytes();
        let scoped = key_start >= 2 && bytes[key_start - 1] == b':' && bytes[key_start - 2] == b'/';
        let indented_line_start = {
            let lead = rskip_while_chars(input, key_start, is_horizontal_js_whitespace);
            is_line_start(input, lead)
        };
        if !scoped && !indented_line_start {
            continue;
        }
        let mut cursor =
            skip_while_chars(input, key_start + key.len(), is_horizontal_js_whitespace);
        if char_at(input, cursor) != Some('=') {
            continue;
        }
        cursor = skip_while_chars(input, cursor + 1, is_horizontal_js_whitespace);
        let (value_start, value_end, form) = match char_at(input, cursor) {
            Some('"' | '\'') => {
                let Some((start, end)) = quoted_assignment_value(input, cursor) else {
                    continue;
                };
                (start, end, ValueForm::Quoted)
            }
            Some(_) => {
                // A quote ends the run: the line may itself sit inside a
                // quoted shell string (`echo "//host/:_authToken=V" > .npmrc`).
                // A run already measured for an earlier key on it ends at
                // the same byte, which keeps a line of repeated keys linear.
                let end = if cursor < run_end {
                    run_end
                } else {
                    skip_while_chars(input, cursor, |ch| {
                        !is_js_whitespace(ch) && !matches!(ch, '"' | '\'' | '`')
                    })
                };
                run_end = end;
                (cursor, end, ValueForm::Unquoted)
            }
            None => continue,
        };
        let value = &input[value_start..value_end];
        if value.len() < MIN_CONTEXT_VALUE_LENGTH
            || value.len() > MAX_CONTEXT_VALUE_LENGTH
            || is_non_secret_reference(value, form)
        {
            continue;
        }
        if let Some(range) = ByteRange::new(value_start, value_end) {
            candidates.push(
                Candidate::new("contextual_secret", Confidence::High, range)
                    .with_specificity(Specificity::Contextual)
                    .with_signals(["npmrc-credential-key", "credential-by-construction"]),
            );
        }
    }
    candidates
}

struct GenericTokenDetector {
    names: NameSource,
}

impl Detector for GenericTokenDetector {
    fn id(&self) -> &'static str {
        match &self.names {
            NameSource::BuiltIn => "generic-token",
            NameSource::Ruleset(_) => RULESET_NAMES_DETECTOR_ID,
        }
    }

    fn detect(
        &self,
        input: &str,
        _context: &DetectorContext,
    ) -> Result<Vec<Candidate>, DetectorFailure> {
        let mut candidates = assignment_candidates(input, &self.names);
        // Authorization-scheme matching (`Basic`/`Token`/`Key`) and the bare
        // vendor-prefixed policy layer have nothing to do with names, so
        // only the built-in instance runs them — the ruleset names
        // extension would otherwise duplicate the built-in's own candidates
        // for the same spans.
        if matches!(self.names, NameSource::BuiltIn) {
            candidates.extend(authorization_candidates(input));
            candidates.extend(bare_vendor_prefix_candidates(input));
            candidates.extend(call_argument_candidates(input));
            candidates.extend(npmrc_credential_candidates(input));
        }
        Ok(candidates)
    }
}

/// The contextual assignment and `Basic`/`Token` authorization detector.
#[must_use]
pub fn generic_token_detector() -> Box<dyn Detector> {
    Box::new(GenericTokenDetector {
        names: NameSource::BuiltIn,
    })
}

/// The declarative ruleset names-section detector (issue #484): matches
/// contextual assignments whose normalized name is one of `names`, at the
/// same [`AMBIGUOUS_ENTROPY_THRESHOLD`] and always [`Confidence::Medium`]
/// the built-in ambiguous bucket already uses, never the high-signal
/// bucket's lower entropy bar or `Confidence::High`. `names` must already be
/// normalized and deduplicated against the built-in vocabulary —
/// `crate::ruleset` does this at load time, so this constructor performs no
/// further filtering.
#[must_use]
pub(crate) fn generic_token_ruleset_names_detector(names: Vec<String>) -> Box<dyn Detector> {
    Box::new(GenericTokenDetector {
        names: NameSource::Ruleset(names),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn detect(input: &str) -> Vec<Candidate> {
        GenericTokenDetector {
            names: NameSource::BuiltIn,
        }
        .detect(input, &DetectorContext::new(input.len()))
        .unwrap()
    }

    fn detect_with_ruleset_names(input: &str, names: &[&str]) -> Vec<Candidate> {
        GenericTokenDetector {
            names: NameSource::Ruleset(names.iter().map(|name| (*name).to_owned()).collect()),
        }
        .detect(input, &DetectorContext::new(input.len()))
        .unwrap()
    }

    // --- issue #989: forward templated-lookup state ------------------------

    /// The #911 look-back check exactly as it shipped before #989: the
    /// reference the forward tracker must agree with.
    fn templated_lookup_path_reference(input: &str, name_start: usize, value: &str) -> bool {
        let line_start = input[..name_start].rfind(['\n', '\r']).map_or(0, |i| i + 1);
        let before = &input[line_start..name_start];
        let inside_template = before
            .rfind("{{")
            .is_some_and(|open| !before[open..].contains("}}"));
        if !inside_template {
            return false;
        }
        let path = value.split_once(':').map_or(value, |(path, _)| path);
        let field_ok = value.split_once(':').is_none_or(|(_, field)| {
            !field.is_empty()
                && field
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'))
        });
        field_ok
            && path.split('/').count() >= 2
            && path.split('/').all(|segment| {
                !segment.is_empty()
                    && segment.bytes().all(|byte| {
                        byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'-')
                    })
            })
    }

    /// Only the "template still open" half of the reference.
    fn template_open_reference(input: &str, position: usize) -> bool {
        templated_lookup_path_reference(input, position, "kv/app")
    }

    /// Queries every char boundary of `input` in order through one tracker,
    /// as the assignment loop does, and checks each answer.
    fn assert_tracker_matches_reference(input: &str) {
        let mut tracker = OpenTemplateTracker::default();
        for position in (0..=input.len()).filter(|&p| input.is_char_boundary(p)) {
            assert_eq!(
                tracker.is_open_at(input, position),
                template_open_reference(input, position),
                "{input:?} at {position}"
            );
        }
    }

    #[test]
    fn open_template_tracker_matches_the_look_back_on_every_short_brace_string() {
        // Every string of up to seven symbols over braces, both line breaks
        // and a filler byte: covers `{{{`, `}}}`, `{{}}`, `{}}{{`, a `}}`
        // before the last `{{`, and a template split by `\r` or `\n`.
        const ALPHABET: [char; 5] = ['{', '}', '\n', '\r', 'a'];
        let mut checked = 0usize;
        for len in 0..=7u32 {
            for mut code in 0..ALPHABET.len().pow(len) {
                let mut input = String::new();
                for _ in 0..len {
                    input.push(ALPHABET[code % ALPHABET.len()]);
                    code /= ALPHABET.len();
                }
                assert_tracker_matches_reference(&input);
                checked += 1;
            }
        }
        assert_eq!(checked, 97_656);
    }

    #[test]
    fn open_template_tracker_matches_the_look_back_on_named_overlap_cases() {
        for input in [
            "{{{ a",
            "{{{}} a",
            "{{{}}} a",
            "{{ a }}} b {{{ c",
            "}}{{ a",
            "{{ a }} b {{ c",
            "{{ a }}\n{{ b",
            "{{ a\r b",
            "{{ a\r\n}} b {{",
            "{ { a } }",
            "x: \"{{ lookup('hashi_vault', 'secret=kv/data/app:token') }}\" y=z",
            "é{{ é }} é{{é",
        ] {
            assert_tracker_matches_reference(input);
        }
    }

    #[test]
    fn templated_lookup_path_matches_the_look_back_on_generated_lines() {
        // A deterministic generator (64-bit LCG), not a random seed: the
        // same inputs every run.
        const PIECES: [&str; 12] = [
            "{", "}", "{{", "}}", "\n", "\r\n", " ", "a=", "é", "{{{", "}}}", "'secret=",
        ];
        const VALUES: [&str; 6] = [
            "kv/app",
            "kv/data/app:token",
            "plain",
            "kv/",
            "a/b:",
            "x/y:z-1",
        ];
        let mut state = 0x9e37_79b9_7f4a_7c15u64;
        let mut next = |bound: usize| {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            usize::try_from(state >> 33).unwrap() % bound
        };
        for _ in 0..2_000 {
            let mut input = String::new();
            for _ in 0..next(40) {
                input.push_str(PIECES[next(PIECES.len())]);
            }
            let mut tracker = OpenTemplateTracker::default();
            for position in (0..=input.len()).filter(|&p| input.is_char_boundary(p)) {
                // Skip some positions, as the loop skips non-assignments.
                if next(3) == 0 {
                    continue;
                }
                let value = VALUES[next(VALUES.len())];
                assert_eq!(
                    is_templated_lookup_path(&mut tracker, &input, position, value),
                    templated_lookup_path_reference(&input, position, value),
                    "{input:?} at {position} with {value:?}"
                );
            }
        }
    }

    #[test]
    fn open_template_tracker_restarts_on_a_backward_query() {
        let input = "{{ a\nb }} {{ c";
        let mut tracker = OpenTemplateTracker::default();
        assert!(tracker.is_open_at(input, input.len()));
        assert!(tracker.is_open_at(input, 3));
        assert!(!tracker.is_open_at(input, 6));
        assert!(tracker.is_open_at(input, input.len()));
    }

    fn only_range(candidates: &[Candidate]) -> (usize, usize) {
        assert_eq!(candidates.len(), 1);
        (candidates[0].range().start(), candidates[0].range().end())
    }

    #[test]
    fn nested_assignments_emit_overlapping_contextual_candidates() {
        let input = "client_secret=\"SYNTHETIC_REVOKED_OUTER_MARKER; api_key=SYNTHETIC_REVOKED_CONTEXT_OVERLAP_1234\"";
        let candidates = detect(input);

        assert_eq!(candidates.len(), 2);
        assert!(
            candidates
                .iter()
                .all(|candidate| candidate.type_name() == "contextual_secret")
        );
        assert_eq!(candidates[0].confidence(), Confidence::High);
        assert_eq!(candidates[0].range(), ByteRange::new(15, 93).unwrap());
        assert_eq!(candidates[1].confidence(), Confidence::High);
        assert_eq!(candidates[1].range(), ByteRange::new(55, 93).unwrap());
        assert!(candidates[0].range().overlaps(candidates[1].range()));
    }

    /// The #812 reproduction value: unmistakably synthetic.
    const COLON_PREFIX_VALUE: &str = "Synthetic-EXAMPLE-pw-9f3k2";

    fn assert_only_value(input: &str, value: &str) {
        let start = input.rfind(value).unwrap();
        assert_eq!(
            only_range(&detect(input)),
            (start, start + value.len()),
            "{input:?}"
        );
    }

    // issue #812: the whitespace after an operator is also the prefix
    // boundary of a name that opens the value. The loop used to resume past
    // it, so an unquoted value that is itself an assignment was never
    // evaluated. Every reproduction row, the missed ones and the ones that
    // were already detected, reports exactly the value.
    #[test]
    fn a_credential_assignment_after_a_colon_prefix_is_detected() {
        for prefix in [
            "",
            "login failed with ",
            "login failed; ",
            "user=bob: ",
            "login failed: ",
            "error: ",
            "request failed:\t",
            "error:  ",
            "error = ",
            "msg := ",
            "[auth] login failed: ",
        ] {
            let input = format!("{prefix}password={COLON_PREFIX_VALUE}");
            assert_only_value(&input, COLON_PREFIX_VALUE);
            let input = format!("{prefix}api_key: {COLON_PREFIX_VALUE}");
            assert_only_value(&input, COLON_PREFIX_VALUE);
        }
    }

    // issue #812: a credential name on both sides of the colon emits the
    // outer and the nested candidate; the engine's overlap resolution keeps
    // one finding (`tests/overlap_resolution.rs`).
    #[test]
    fn a_credential_assignment_nested_in_a_credential_colon_value_emits_both_candidates() {
        let input = format!("secret: password={COLON_PREFIX_VALUE}");
        let candidates = detect(&input);
        assert_eq!(candidates.len(), 2, "{candidates:?}");
        let inner = input.len() - COLON_PREFIX_VALUE.len();
        assert_eq!(
            candidates[0].range(),
            ByteRange::new(8, input.len()).unwrap()
        );
        assert_eq!(
            candidates[1].range(),
            ByteRange::new(inner, input.len()).unwrap()
        );
    }

    // issue #812: the fix only makes a nested name reachable; every existing
    // name and value rule still judges it. Benign colon-prefixed text and
    // URLs stay non-matches.
    #[test]
    fn benign_assignments_after_a_colon_prefix_stay_unmatched() {
        for input in [
            "note: value=hello",
            "note: value=Synthetic-EXAMPLE-pw-9f3k2",
            "status: ok=true",
            "error: user=bob",
            "error: token=Synthetic-EXAMPLE-pw-9f3k2",
            "login failed: password=",
            "login failed: password=********",
            "login failed: password=${DB_PASSWORD}",
            "login failed: password=<password>",
            "url: https://example.test/callback?a=b",
            "redirect: https://example.test/cb?state=abc&a=b",
            "see https://example.test/?a=b&c=d",
            "time: 12:30:45",
            "scope: api-key:endpoint:chat",
        ] {
            let candidates = detect(input);
            assert!(candidates.is_empty(), "{input:?}: {candidates:?}");
        }
    }

    // issue #812: a name glued to the operator of the text before it, with no
    // whitespace, still has no prefix boundary, as `x=password=V` never had.
    // Widening the boundary set to `:`/`=` would split whole-input and
    // incremental results for a name whose operator is on the next line,
    // because `has_open_contextual_assignment` does not treat them as a
    // boundary either.
    #[test]
    fn a_credential_name_glued_to_a_preceding_operator_stays_unmatched() {
        for input in [
            format!("error:password={COLON_PREFIX_VALUE}"),
            format!("x=password={COLON_PREFIX_VALUE}"),
        ] {
            assert!(detect(&input).is_empty(), "{input:?}");
        }
    }

    // issue #552: `redact-secret-benchmarks`' `context.markdown` metamorphic
    // operator wraps a whole fixture in a matching pair of backticks with no
    // other change (Markdown inline code). Before this fix, the opening
    // backtick sat directly against the key name with no recognized
    // boundary before it, and the matching closing backtick sat directly
    // against the quoted value's own closing quote with no recognized
    // boundary after it -- either alone was enough to make a quoted
    // assignment like this one invisible to `assignment_candidates`, a
    // silent miss rather than a shifted-offset match.
    #[test]
    fn a_high_signal_assignment_wrapped_in_markdown_inline_code_is_still_detected() {
        let input = "`api_key=\"SYNTHETIC_REVOKED_CONTEXT_VALUE\"`";
        let candidates = detect(input);

        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].confidence(), Confidence::High);
        let value_start = "`api_key=\"".len();
        let value_end = value_start + "SYNTHETIC_REVOKED_CONTEXT_VALUE".len();
        assert_eq!(
            candidates[0].range(),
            ByteRange::new(value_start, value_end).unwrap()
        );
    }

    // issue #548: the same `context.markdown` envelope over an *unquoted*
    // value. `is_unquoted_value_boundary` did not know the backtick, so the
    // closing delimiter was read into the value: a masked filler became
    // `********`` and escaped the #264 repeated-character exclusion, and a
    // real value's range ran one byte long.
    #[test]
    fn a_masked_value_wrapped_in_markdown_inline_code_stays_excluded() {
        assert!(detect("`password=********`").is_empty());
    }

    #[test]
    fn an_unquoted_assignment_in_markdown_inline_code_excludes_the_closing_backtick() {
        let input = "`api_key=SYNTHETIC_REVOKED_CONTEXT_VALUE`";
        let candidates = detect(input);

        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].confidence(), Confidence::High);
        let value_start = "`api_key=".len();
        let value_end = value_start + "SYNTHETIC_REVOKED_CONTEXT_VALUE".len();
        assert_eq!(
            candidates[0].range(),
            ByteRange::new(value_start, value_end).unwrap()
        );
    }

    #[test]
    fn high_signal_assignment_with_bounded_entropy_is_high_confidence() {
        let input = "api_key=SYNTHETIC_REVOKED_CONTEXT_VALUE";
        let candidates = detect(input);
        assert_eq!(only_range(&candidates), (8, input.len()));
        assert_eq!(candidates[0].confidence(), Confidence::High);
        assert_eq!(candidates[0].specificity(), Some(Specificity::Contextual));
    }

    // issue #702: a high-signal name behind a generic prefix, and a prefixed
    // `_token` name, is the same evidence as the bare name.
    #[test]
    fn a_generically_prefixed_high_signal_name_is_high_confidence() {
        for name in [
            "MYAPP_API_KEY",
            "backendSecretKey",
            "DB_PASSWORD",
            "jwt.secret",
            "CI_DEPLOY_TOKEN",
            "internal-service-token",
            "SMTP_PASSWORD",
            "ADMIN_TOKEN",
        ] {
            let input = format!("{name}=SYNTHETIC_REVOKED_CONTEXT_VALUE");
            let candidates = detect(&input);
            assert_eq!(candidates.len(), 1, "{input}");
            assert_eq!(candidates[0].confidence(), Confidence::High, "{input}");
            assert_eq!(only_range(&candidates), (name.len() + 1, input.len()));
            assert!(
                has_open_contextual_assignment(&format!("{name}=")),
                "{name}"
            );
        }
    }

    // issue #702: a lead that says the value is redacted, hashed or public
    // is not a secret name. Issue #1018 narrowed it: the lead excludes a
    // value only when the value shows masking or hashing, except
    // `publishable`, which is public by the provider's documentation.
    #[test]
    fn non_secret_prefixes_are_not_generic_names() {
        let hex64 = "0123456789abcdef".repeat(4);
        for input in [
            "publishable_key=SYNTHETIC_REVOKED_CONTEXT_VALUE".to_owned(),
            "hashed_token=SYNTHETIC_REVOKED_CONTEXT_VALUE".to_owned(),
            format!("masked_api_key=9ctA{}lwCk", "*".repeat(32)),
            format!("masked_api_key=abcd{}", "x".repeat(28)),
            "redactedApiKey=SYNTHETIC...VALUE_TAIL".to_owned(),
            "masked_secret=[REDACTED]-SYNTHETIC-VALUE".to_owned(),
            format!("hashed_api_key={hex64}"),
            "hash_secret=$2b$12$SYNTHETICsaltSYNTHETIChashvalue0000".to_owned(),
            format!("hashed_password=sha256:{hex64}"),
            "masked_api_key=Ab3\u{2022}\u{2022}\u{2022}\u{2022}Cd4Ef5Gh6Jk7".to_owned(),
        ] {
            assert!(detect(&input).is_empty(), "{input}");
        }
    }

    // issue #1018: a complete, unmasked value under a value-checked lead is
    // judged under the name the lead stands in front of.
    #[test]
    fn an_unmasked_value_under_a_masking_lead_is_judged_under_the_rest_of_the_name() {
        for name in [
            "masked_api_key",
            "redactedApiKey",
            "hashed_password",
            "obfuscated_client_secret",
            "sanitized_access_token",
        ] {
            let input = format!("{name}=SYNTHETIC_REVOKED_CONTEXT_VALUE");
            let candidates = detect(&input);
            assert_eq!(
                only_range(&candidates),
                (name.len() + 1, input.len()),
                "{input}"
            );
            assert_eq!(candidates[0].confidence(), Confidence::High, "{input}");
            assert!(
                has_open_contextual_assignment(&format!("{name}=")),
                "{name}"
            );
        }
        // The bare `token` name stays unmatched behind a lead too.
        assert!(detect("hashed_token=SYNTHETIC_REVOKED_CONTEXT_VALUE").is_empty());
        assert!(!has_open_contextual_assignment("publishable_key="));
    }

    // issue #948: a provider prefix no longer hands a high-signal name to
    // the provider detector alone. `generic-token` proposes the value like
    // it does under `MYAPP_API_KEY`, and overlap resolution lets a provider
    // finding on the same value win on specificity.
    #[test]
    fn provider_prefixed_high_signal_names_are_generic_names() {
        for name in [
            "POSTMAN_API_KEY",
            "GITHUB_TOKEN",
            "GH_TOKEN",
            "DD_API_KEY",
            "NEW_RELIC_API_KEY",
            "stripeSecretKey",
            "SLACK_BOT_TOKEN",
            "OPENAI_API_KEY",
            "ANTHROPIC_API_KEY",
            "HUGGING_FACE_HUB_TOKEN",
            "GITHUB_CLIENT_SECRET",
        ] {
            let input = format!("{name}=SYNTHETIC_REVOKED_CONTEXT_VALUE");
            let candidates = detect(&input);
            assert_eq!(candidates.len(), 1, "{input}");
            assert_eq!(candidates[0].type_name(), "contextual_secret", "{input}");
            assert_eq!(candidates[0].confidence(), Confidence::High, "{input}");
            assert_eq!(
                candidates[0].specificity(),
                Some(Specificity::Contextual),
                "{input}"
            );
        }
    }

    // issue #948: every prefix of the rule-2 list, one segment or a phrase,
    // qualifies for the high-signal bucket and stays out of the ambiguous
    // one; the retention hint and the ruleset reserved-name check follow.
    #[test]
    fn every_dedicated_provider_prefix_qualifies_for_high_signal_names() {
        for prefix in DEDICATED_PROVIDER_SEGMENTS
            .iter()
            .chain(DEDICATED_PROVIDER_PHRASES)
        {
            for suffix in [
                "api_key",
                "token",
                "secret_key",
                "client_secret",
                "password",
            ] {
                let name = format!("{prefix}_{suffix}");
                assert!(is_high_signal_name(&name), "{name}");
                assert!(is_reserved_name(&name), "{name}");
                assert!(
                    has_open_contextual_assignment(&format!("{name}=")),
                    "{name}"
                );
            }
            for suffix in [
                "credentials",
                "auth",
                "signing_key",
                "csrf_token",
                "api_key_id",
            ] {
                let name = format!("{prefix}_{suffix}");
                assert!(!is_high_signal_name(&name), "{name}");
                assert!(!is_ambiguous_name(&name), "{name}");
            }
        }
    }

    // issue #948 keeps the provider exclusion for the ambiguous bucket and
    // for the request-scoped `_token` names, and a provider-prefixed
    // identifier sibling was never a credential name.
    #[test]
    fn provider_prefixed_ambiguous_request_scoped_and_identifier_names_stay_clean() {
        for name in [
            "GITHUB_CREDENTIALS",
            "OKTA_AUTH",
            "SLACK_SIGNING_KEY",
            "GITHUB_CSRF_TOKEN",
            "STRIPE_NEXT_PAGE_TOKEN",
            "SLACK_DEVICE_TOKEN",
            "OPENAI_API_KEY_ID",
            "STRIPE_API_URL",
            "TWILIO_ACCOUNT_SID",
            "OPENAI_ORG_ID",
        ] {
            let input = format!("{name}=SYNTHETIC_REVOKED_CONTEXT_VALUE_9f3K");
            assert!(detect(&input).is_empty(), "{input}");
        }
        // Issue #1018: a masking lead excludes only a value that shows the
        // masking; an unmasked one is judged under the rest of the name.
        for name in ["redacted_openai_api_key", "MASKED_STRIPE_SECRET_KEY"] {
            let masked = format!("{name}=SYNTHETIC{}9f3K", "*".repeat(16));
            assert!(detect(&masked).is_empty(), "{masked}");
            let unmasked = format!("{name}=SYNTHETIC_REVOKED_CONTEXT_VALUE_9f3K");
            assert_eq!(detect(&unmasked).len(), 1, "{unmasked}");
        }
    }

    #[test]
    fn a_prefixed_ambiguous_name_stays_medium_at_the_ambiguous_entropy_bar() {
        let input = "SERVICE_CREDENTIALS=SYNTHETIC_REVOKED_CONTEXT_VALUE_9f3K";
        let candidates = detect(input);
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].confidence(), Confidence::Medium);
    }

    #[test]
    fn request_scoped_token_names_and_unprefixed_suffix_lookalikes_stay_clean() {
        for name in [
            "csrf_token",
            "X_CSRF_TOKEN",
            "next_page_token",
            "nextPageToken",
            "cancellation_token",
            "device_token",
            "token",
            "tokens",
            "api_keys_count",
            "passwordless",
            "secretary",
            "_token",
        ] {
            let input = format!("{name}=SYNTHETIC_REVOKED_CONTEXT_VALUE");
            assert!(detect(&input).is_empty(), "{input}");
        }
    }

    #[test]
    fn a_vendor_prefixed_placeholder_is_not_a_secret() {
        for input in [
            "api_key=pplx-your-api-key-here",
            "app_token: xapp-<your-app-level-token>",
            "api_key=lsv2_pt_your_key_here",
            "api_key=pcsk_***",
            "access_token=pul-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
            "api_key=sk-proj-YOUR_API_KEY",
            "api_key=sk-placeholder",
            "access_token=dapixxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
            "api_key=PMAK-xxxxxxxxxxxxxxxxxxxxxxxx-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
            "api_key=00000000-0000-0000-0000-000000000000",
            "client_token=hmac-sha256:3122799486cdfa0be2445049d8a1f0c2",
            "secret=sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b",
        ] {
            assert!(detect(input).is_empty(), "{input}");
        }
    }

    #[test]
    fn the_vendor_placeholder_prefix_limit_covers_the_anthropic_admin_prefix() {
        // Issue #1015: the 14-byte `sk-ant-admin01` prefix is stripped like
        // its 12-byte siblings; any other lead over 12 bytes is not.
        assert!(is_vendor_prefixed_placeholder("sk-ant-admin01-<your-key>"));
        assert!(is_vendor_prefixed_placeholder("sk-ant-admin01-YOUR_KEY"));
        assert!(is_vendor_prefixed_placeholder("sk-ant-admin01-..."));
        assert!(!is_vendor_prefixed_placeholder("sk-ant-admin02-<your-key>"));
        assert!(!is_vendor_prefixed_placeholder("abcdefghijklmn-<your-key>"));
        assert!(!is_vendor_prefixed_placeholder(
            "sk-ant-admin01-Ab3Cd4Ef5Gh6"
        ));
    }

    #[test]
    fn issue_1042_placeholder_shapes_are_excluded_and_their_twins_are_not() {
        // A lead-word phrase behind a vendor prefix, never bare.
        assert!(is_vendor_prefixed_placeholder(
            "rpa_your_key_for_ci_pipeline_test_fixture_only"
        ));
        assert!(is_lead_word_phrase_placeholder("YOUR_TOKEN_FOR_STAGING"));
        for twin in [
            "your_key_for_ci_7",
            "your_Key_for_ci",
            "my_key_for_ci",
            "your_for_ci",
            "your",
        ] {
            assert!(!is_lead_word_phrase_placeholder(twin), "{twin}");
        }
        // A vendor prefix shown before an ellipsis.
        for value in [
            "pdl_sdbx_apikey_...",
            "pdl_live_apikey_\u{2026}",
            "wandb_v1_...",
        ] {
            assert!(is_ellipsis_truncated_display(value), "{value}");
        }
        for twin in [
            "pdl_sdbx_apikey_01hq7zyx9...",
            "pdl_sdbx_apikeyzz...",
            "pdl_sdbx_verylongsegment_...",
            "PDL_SDBX_APIKEY_...",
            "pdl_sdbx_apikey_",
        ] {
            assert!(!is_ellipsis_truncated_display(twin), "{twin}");
        }
        // A multi-part filler layout with `:` and trailing padding.
        let x = |n: usize| "x".repeat(n);
        let bitwarden = format!("0.{}-{}.{}:{}==", x(8), x(4), x(30), x(22));
        assert!(is_prefixed_filler(&bitwarden));
        assert!(!is_prefixed_filler(&format!("0.{}:{}y==", x(8), x(22))));
        assert!(!is_prefixed_filler(&format!("0.{}=={}", x(8), x(22))));
        // `my` + two or more credential words, bare.
        for value in ["mykeysecret", "mykeyid", "myapikey", "mysecretaccesskey"] {
            assert!(is_glued_my_placeholder(value), "{value}");
        }
        for twin in [
            "mysecret",
            "mykey",
            "mykeysecret7",
            "myKeySecret",
            "mykeysecretq",
            "keysecret",
        ] {
            assert!(!is_glued_my_placeholder(twin), "{twin}");
        }
    }

    #[test]
    fn a_phrase_led_by_a_distinctive_placeholder_word_is_a_placeholder() {
        for value in [
            "placeholder-not-a-key",
            "placeholder-value",
            "PLACEHOLDER_API_KEY",
            "example-token",
            "sample.secret.value",
            "changeme-only",
        ] {
            assert!(is_placeholder_led_phrase(value), "{value}");
            assert!(
                is_generic_placeholder_word(&value.to_ascii_lowercase()),
                "{value}"
            );
        }
        for value in [
            "placeholder",
            "placeholder-",
            "placeholder--key",
            "placeholder-key9",
            "placeholder-hunter",
            "secret-not-a-key",
            "password-value",
            "not-a-real-key",
            "key-placeholder",
        ] {
            assert!(!is_placeholder_led_phrase(value), "{value}");
        }
    }

    #[test]
    fn a_counting_digit_run_or_glued_your_word_behind_a_vendor_prefix_is_a_placeholder() {
        // Issue #949.
        for value in [
            "signkey-test-12345",
            "re_123456789",
            "re_1234567890",
            "re_7890123",
            "re_yourkey",
            "re_YourApiKeyHere",
            "signkey-prod-yoursigningkey",
        ] {
            assert!(is_vendor_prefixed_placeholder(value), "{value}");
        }
        for value in [
            "re_123",
            "re_12346",
            "re_98765",
            "re_193847562",
            "re_yourkeyq",
            "re_yourkey7",
            "re_yourdog",
            "re_your",
            "RE_yourkey",
            "longvendorname_12345",
        ] {
            assert!(!is_vendor_prefixed_placeholder(value), "{value}");
        }
        assert!(!is_ascending_digit_run("123"));
        assert!(is_ascending_digit_run("8901"));
        assert!(!is_glued_instructional_placeholder("your"));
        assert!(!is_glued_instructional_placeholder("your_key"));
    }

    #[test]
    fn a_vendor_prefix_before_random_material_stays_detected() {
        for input in [
            "api_key=pplx-9f2cQ7xLm4Rt8Wz3Nc6Bh1Jd",
            "access_token=pul-xxxx9f2cQ7xLm4Rt8Wz3Nc6Bh1Jd",
            "api_key=verylongvendorprefix_your_api_key_here",
            "access_token=dapixxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx9",
            "secret=sha256x9f86d081884c7d659a2feaa0c55ad015",
            "api_key=abcdefghixxxxxxxxxxxxxxx",
        ] {
            assert_eq!(detect(input).len(), 1, "{input}");
        }
    }

    #[test]
    fn a_prefixed_name_keeps_every_non_secret_value_exclusion() {
        for input in [
            "MYAPP_API_KEY=${MYAPP_API_KEY}",
            "DB_PASSWORD=<your-db-password>",
            "CI_DEPLOY_TOKEN=YOUR_ACCESS_TOKEN",
            "ADMIN_TOKEN=short",
        ] {
            assert!(detect(input).is_empty(), "{input}");
        }
    }

    // issue #473: `assignment_confidence` returns `Some` unconditionally for
    // any `HIGH_SIGNAL_NAMES` match — entropy and length only choose between
    // `High` and `Medium`, they never reject. Ordinary documentation prose
    // that names a credential parameter is, at the character-grammar level,
    // indistinguishable from a real weak credential of the same shape: both
    // are short, low-entropy, single unquoted "words" immediately after the
    // assignment delimiter. See
    // `docs/decisions/2026-09-20-warn-unconditionally-on-high-signal-contextual-names.md`
    // for why no threshold separates them and this is an accepted tradeoff,
    // the way `bearer_token.rs`'s
    // `ordinary_prose_usage_of_bearer_is_safe_but_a_long_incidental_word_is_an_accepted_tradeoff`
    // documents the equivalent tradeoff for that detector.
    #[test]
    fn high_signal_names_warn_on_ordinary_prose_as_an_accepted_precision_tradeoff() {
        for (input, captured) in [
            (
                "The otpauth URI format includes a secret= parameter holding the shared seed.",
                "parameter",
            ),
            (
                "Set password= followed by your chosen passphrase.",
                "followed",
            ),
            (
                "The api_key: parameter is required for all authenticated endpoints.",
                "parameter",
            ),
            (
                "Use client_secret: obtained from the developer console.",
                "obtained",
            ),
            (
                "Each request needs an access_token: retrieved during the OAuth exchange.",
                "retrieved",
            ),
            (
                "The private_key: argument accepts a PEM-encoded string.",
                "argument",
            ),
            (
                "Pass secret: whichever value your provider issued.",
                "whichever",
            ),
            (
                "Configure password: something memorable but strong.",
                "something",
            ),
            (
                "The webhook_secret= configuration determines signature validation.",
                "configuration",
            ),
            (
                "Note that api_key= supports environment interpolation.",
                "supports",
            ),
        ] {
            let candidates = detect(input);
            assert_eq!(candidates.len(), 1, "{input:?}");
            assert_eq!(candidates[0].type_name(), "contextual_secret");
            assert_eq!(candidates[0].confidence(), Confidence::Medium);
            let (start, end) = only_range(&candidates);
            assert_eq!(&input[start..end], captured, "{input:?}");
        }

        // A real weak credential of the same shape — short, low-entropy, a
        // single unquoted word — classifies identically to the prose cases
        // above: the constraint that makes them unfixable by threshold.
        let input = "password=hunter2xyz";
        let candidates = detect(input);
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].confidence(), Confidence::Medium);
    }

    #[test]
    fn escaped_quote_stays_inside_one_structured_value_span() {
        let input = "{\"api_key\":\"SYNTHETIC_REVOKED_\\\"QUOTED_VALUE\"}";
        let candidates = detect(input);
        assert_eq!(only_range(&candidates), (12, 44));
    }

    // --- issue #294: a nested key immediately following an enclosing
    // quote's opening quote, with no separator between them
    // (`value="api_key="TOKEN""`), now starts its own contextual assignment
    // scan, and its value's closing quote is recognized as a valid close
    // even when the very next character is the enclosing quote rather than
    // whitespace or a structural character.

    #[test]
    fn a_nested_assignment_with_no_separator_inside_an_enclosing_quote_is_detected() {
        for (input, start, end) in [
            // The three published-package reproducers from issue #294.
            (
                "value=\"api_key=\"I9RBasVzoPPDPIErHTQcrdjnmKvu\"\"\n",
                16,
                44,
            ),
            (
                "value=\"password=\"yrdhd5QrRabaY9e8KnFuTTALQClH\"\"\n",
                17,
                45,
            ),
            (
                "value=\"client_secret=\"rs06I0rFoRw0mKTRs9hZIDfyQqXw\"\"\n",
                22,
                50,
            ),
        ] {
            let candidates = detect(input);
            assert_eq!(only_range(&candidates), (start, end), "input: {input:?}");
            assert_eq!(candidates[0].confidence(), Confidence::High);
        }
    }

    #[test]
    fn a_single_quoted_nested_assignment_with_no_separator_is_detected() {
        let input = "value='api_key='SYNTHETIC_REVOKED_NESTED_SINGLE_QUOTE_1234''\n";
        let candidates = detect(input);
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].confidence(), Confidence::High);
    }

    #[test]
    fn a_plain_quoted_assignment_with_no_nesting_is_unaffected() {
        let input = "api_key=\"SYNTHETIC_REVOKED_PLAIN_QUOTED_VALUE_1234\"";
        let candidates = detect(input);
        assert_eq!(only_range(&candidates), (9, input.len() - 1));
    }

    fn only_value(input: &str) -> &str {
        let candidates = detect(input);
        let (start, end) = only_range(&candidates);
        &input[start..end]
    }

    #[test]
    fn an_assignment_inside_an_escaped_json_string_is_detected() {
        // Issue #815: a JSON document serialized into another JSON string.
        let input = r#"{"level":"debug","body":"{\"access_token\":\"SYNTHETICq8vN3xR7tLm2Kp9Wd\",\"expires_in\":3600}"}"#;
        assert_eq!(only_value(input), "SYNTHETICq8vN3xR7tLm2Kp9Wd");
        // An inner escaped quote (`\\\"`) belongs to the value.
        let nested = r#"{"body":"{\"password\":\"SYNTHETIC\\\"q8vN3xR7tLm2Kp9Wd\",\"x\":1}"}"#;
        assert_eq!(only_value(nested), r#"SYNTHETIC\\\"q8vN3xR7tLm2Kp9Wd"#);
        // A reference stays excluded in the escaped form too.
        assert!(detect(r#"{"body":"{\"password\":\"${DB_PASSWORD}\"}"}"#).is_empty());
    }

    #[test]
    fn url_query_fragment_and_form_body_parameters_are_detected() {
        // Issue #816.
        const V: &str = "SYNTHETICq8vN3xR7tLm2Kp9Wd";
        for input in [
            format!("https://api.example.test/r?access_token={V}&p=q"),
            format!("GET /resource?access_token={V} HTTP/1.1"),
            format!("Location: https://client.example.test/cb#access_token={V}&state=xyz"),
            format!("grant_type=refresh_token&refresh_token={V}"),
            format!("&client_secret={V}"),
            format!("[docs](https://api.example.test/r?access_token={V})"),
        ] {
            assert_eq!(only_value(&input), V, "{input}");
        }
        // A leading parameter ends at the next `&name=`.
        assert_eq!(only_value(&format!("refresh_token={V}&client_id=s6Bhd")), V);
        // PKCE verifier.
        let verifier = format!("code_verifier={V}{V}");
        assert_eq!(only_value(&verifier), format!("{V}{V}"));
    }

    #[test]
    fn the_authorization_code_is_ambiguous_and_only_as_a_query_parameter() {
        // Issue #816.
        let input = "https://client.example.test/cb?code=SYNTHETICq8vN3xR7tLm2Kp9Wd&state=xyz";
        let candidates = detect(input);
        assert_eq!(&input[36..62], "SYNTHETICq8vN3xR7tLm2Kp9Wd");
        assert_eq!(only_range(&candidates), (36, 62));
        assert_eq!(candidates[0].confidence(), Confidence::Medium);
        for clean in [
            "https://x.example.test/?code=200",
            "https://x.example.test/?code=US&lang=en",
            "code = SYNTHETICq8vN3xR7tLm2Kp9Wd",
            "error code=SYNTHETICq8vN3xR7tLm2Kp9Wd",
            "code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
            "access_token_type=Bearer&refresh_token_expires_in=3600",
            "see docs?password=hunter",
        ] {
            assert!(detect(clean).is_empty(), "{clean}");
        }
    }

    #[test]
    fn query_parameters_inside_an_otpauth_uri_are_left_to_otpauth_uri() {
        // Issue #816, deferring like a provider-named assignment (#702).
        for input in [
            "otpauth://push/Example:alice@example.com?secret=SYNTHETICOTPAUTHSEEDVALUEQPWKYV",
            "OTPAUTH://TOTP/Example:alice@example.com?secret=SYNTHETICOTPAUTHSEEDVALUEQPWKYV",
            "otpauth://totp/Example Label:alice?issuer=x&secret=SYNTHETICOTPAUTHSEEDVALUEQPWKYV",
        ] {
            assert!(detect(input).is_empty(), "{input}");
        }
        // The deference ends with the URI's line.
        let input = "otpauth://totp/x?secret=SYNTHETICOTPAUTHSEEDVALUEQPWKYV\nhttps://api.example.test/r?access_token=SYNTHETICq8vN3xR7tLm2Kp9Wd";
        assert_eq!(only_value(input), "SYNTHETICq8vN3xR7tLm2Kp9Wd");
    }

    #[test]
    fn escaped_placeholders_quoted_references_env_lookups_seams_and_arns_are_not_secrets() {
        // Issue #817.
        const V: &str = "SYNTHETICq8vN3xR7tLm2Kp9Wd";
        for clean in [
            "\"password\": \"&lt;YOUR_PASSWORD&gt;\"",
            "- echo 'export DB_PASSWORD=\"'$DEPLOY_PASSWORD'\"' >> .env",
            "password = env.DEPLOY_TEST_PASSWORD",
            "sb.append(\"UserPassword: \" + getUserPassword() + \",\");",
            "$msg = \"password: \" . $password . \"\\n\";",
            "ChangePassword = \"arn:aws:iam::aws:policy/ChangePassword\"",
            "secret_arn: arn:aws-us-gov:kms:us-gov-west-1:123456789012:key/SYNTHETIC-key-id",
        ] {
            assert!(detect(clean).is_empty(), "{clean}");
        }
        // Each exclusion needs the whole value in its shape.
        for (input, value) in [
            (
                format!("\"password\": \"&lt;x&gt;{V}\""),
                format!("&lt;x&gt;{V}"),
            ),
            (format!("DB_PASSWORD=\"'{V}'\""), format!("'{V}'")),
            (format!("password = envx{V}"), format!("envx{V}")),
            (format!("password = \"{V}+ x +\""), format!("{V}+ x +")),
            (format!("password = \"arn:{V}\""), format!("arn:{V}")),
        ] {
            assert_eq!(only_value(&input), value, "{input}");
        }
    }

    #[test]
    fn jwk_secret_members_are_detected_only_on_a_kty_line() {
        // Issue #821. The values are base64url of `SYNTHETIC_...` text.
        let symmetric = r#"{"kty":"oct","k":"U1lOVEhFVElDX1JFVk9LRURfSldLX1NZTU1FVFJJQ19LRVk"}"#;
        assert_eq!(
            only_value(symmetric),
            "U1lOVEhFVElDX1JFVk9LRURfSldLX1NZTU1FVFJJQ19LRVk"
        );
        let rsa = r#"{"kty":"RSA","n":"U1lOVEhFVElDX1BVQkxJQ19NT0RVTFVT","e":"AQAB","d":"U1lOVEhFVElDX1JFVk9LRURfUlNBX0Q","qi":"U1lOVEhFVElDX1JFVk9LRURfUlNBX1FJ"}"#;
        let values: Vec<&str> = detect(rsa)
            .iter()
            .map(|candidate| &rsa[candidate.range().start()..candidate.range().end()])
            .collect();
        assert_eq!(
            values,
            [
                "U1lOVEhFVElDX1JFVk9LRURfUlNBX0Q",
                "U1lOVEhFVElDX1JFVk9LRURfUlNBX1FJ"
            ]
        );
        for clean in [
            r#"{"k":"U1lOVEhFVElDX1JFVk9LRURfSldLX1NZTU1FVFJJQ19LRVk"}"#,
            r#"{"kty":"RSA","n":"U1lOVEhFVElDX1BVQkxJQ19NT0RVTFVT","e":"AQAB"}"#,
            "{\"kty\":\"oct\",\n\"k\":\"U1lOVEhFVElDX1JFVk9LRURfSldLX1NZTU1FVFJJQ19LRVk\"}",
            r#"{"kty":"oct","k":"placeholder"}"#,
        ] {
            assert!(detect(clean).is_empty(), "{clean}");
        }
    }

    #[test]
    fn go_short_assignment_and_objective_c_string_literals_are_detected() {
        // Issue #815.
        assert_eq!(
            only_value("apikey := \"SYNTHETICq8vN3xR7tLm2Kp9Wd\""),
            "SYNTHETICq8vN3xR7tLm2Kp9Wd"
        );
        assert_eq!(
            only_value("password := SYNTHETICq8vN3xR7tLm2Kp9Wd"),
            "SYNTHETICq8vN3xR7tLm2Kp9Wd"
        );
        assert_eq!(
            only_value("password = @\"SYNTHETICq8vN3xR7tLm2Kp9Wd\";"),
            "SYNTHETICq8vN3xR7tLm2Kp9Wd"
        );
        assert!(detect("password := os.Getenv(\"DB_PASSWORD\")").is_empty());
    }

    #[test]
    fn a_value_containing_braces_and_brackets_is_literal_material() {
        // Issue #815: `x[` next to `{`, `$`, `#` or `(` is not type syntax,
        // and a `}`/`]` closing a brace the value opened does not end it.
        let quoted = "apikey = \"SYN{{t}h)e${t]ic(al[value>-_$#x}}\"";
        assert_eq!(only_value(quoted), "SYN{{t}h)e${t]ic(al[value>-_$#x}}");
        let unquoted = "apikey = SYN{{t}h)e${t]ic(al[value>-_$#x}}";
        assert_eq!(only_value(unquoted), "SYN{{t}h)e${t]ic(al[value>-_$#x}}");
        // Type annotations, subscripts, flow mappings and templates stay clean.
        for input in [
            "password: Option<String>",
            "password: \"Optional[SecretStr]\"",
            "token: HashMap<String, Vec<u8>>",
            "api_key: settings[API_KEY_NAME]",
            "secret: {secretName: web-tls-cert}",
            "password: {{ vault_db_password }}",
            "password = ${DB_PASSWORD}",
            "secret = request.headers[\"apikey\"]",
        ] {
            assert!(detect(input).is_empty(), "{input}");
        }
    }

    #[test]
    fn a_masked_value_nested_with_no_separator_inside_an_enclosing_quote_stays_excluded() {
        let input = "value=\"password=\"********\"\"\n";
        assert!(
            detect(input).is_empty(),
            "expected no findings for {input:?}"
        );
    }

    #[test]
    fn a_template_reference_nested_with_no_separator_inside_an_enclosing_quote_stays_excluded() {
        let input = "value=\"password=\"{{ vault_db_password }}\"\"\n";
        assert!(
            detect(input).is_empty(),
            "expected no findings for {input:?}"
        );
    }

    #[test]
    fn nested_assignment_with_no_separator_is_detected_across_crlf_and_unicode_prefix() {
        for input in [
            // CRLF line ending after the outer close.
            "value=\"api_key=\"SYNTHETIC_REVOKED_NESTED_QUOTE_CRLF_1234\"\"\r\n",
            // A multi-byte Unicode character preceding the assignment,
            // exercising byte-offset (not char-count) boundary handling.
            "note: caf\u{e9} \u{2014} value=\"api_key=\"SYNTHETIC_REVOKED_NESTED_QUOTE_UNICODE_1234\"\"\n",
        ] {
            assert!(
                !detect(input).is_empty(),
                "expected a finding for {input:?}"
            );
        }
    }

    #[test]
    fn documented_aws_secret_access_key_name_is_high_signal() {
        let input = "AWS_SECRET_ACCESS_KEY=SYNTHETIC_REVOKED_AWS_CONTEXT_VALUE";
        let candidates = detect(input);
        assert_eq!(only_range(&candidates), (22, 57));
    }

    #[test]
    fn documented_aws_session_token_name_is_high_signal() {
        let input = "aws_session_token=SYNTHETIC_REVOKED_AWS_CONTEXT_VALUE";
        let candidates = detect(input);
        assert_eq!(only_range(&candidates), (18, 53));
    }

    #[test]
    fn db_pass_is_a_high_signal_name_only_as_the_whole_name() {
        // Issue #823: `db_pass` is the conventional database password name.
        for input in [
            "db_pass: 'SYNTHETIC_REVOKED_DB_PASS_VALUE'",
            "DB_PASS=SYNTHETIC_REVOKED_DB_PASS_VALUE",
            "dbPass = \"SYNTHETIC_REVOKED_DB_PASS_VALUE\"",
        ] {
            let candidates = detect(input);
            assert_eq!(candidates.len(), 1, "{input}");
            assert_eq!(candidates[0].confidence(), Confidence::High, "{input}");
        }
        // The prefixed spellings were already covered through `password`/`passwd`.
        assert_eq!(detect("db_passwd=SYNTHETIC_REVOKED_DB_PASS_VALUE").len(), 1);
        assert_eq!(
            detect("db_password=SYNTHETIC_REVOKED_DB_PASS_VALUE").len(),
            1
        );
    }

    #[test]
    fn fal_and_convex_credential_variables_are_exact_high_signal_names() {
        // Issue #919: a bare `_key` suffix is not a name token, so these
        // provider variables produced no finding at all.
        const FAL: &str = "5e7c0ded-feed-4bad-9ace-0ddba11c0de5:5a1ed0ff5e7c0dedfeedbadacef00d42";
        const CONVEX: &str = "prod:happy-otter-123|01SYNTHETICrevokedCONVEXdeployKEY0042";
        for (input, value) in [
            (format!("FAL_KEY={FAL}"), FAL),
            (format!("export FAL_KEY=\"{FAL}\""), FAL),
            (format!("falKey: '{FAL}'"), FAL),
            (format!("{{\"FAL_KEY\": \"{FAL}\"}}"), FAL),
            (format!("CONVEX_DEPLOY_KEY={CONVEX}"), CONVEX),
            (format!("CONVEX_SELF_HOSTED_ADMIN_KEY={CONVEX}"), CONVEX),
            (
                format!("  CONVEX_SELF_HOSTED_ADMIN_KEY: \"{CONVEX}\""),
                CONVEX,
            ),
            (
                "FAL_KEY=SYNTHETICrevokedNEUTRALvalue0042xyzw".to_owned(),
                "SYNTHETICrevokedNEUTRALvalue0042xyzw",
            ),
        ] {
            let candidates = detect(&input);
            let (start, end) = only_range(&candidates);
            assert_eq!(&input[start..end], value, "{input}");
            assert_eq!(candidates[0].type_name(), "contextual_secret");
            assert_eq!(candidates[0].confidence(), Confidence::High, "{input}");
        }
    }

    #[test]
    fn a_composite_value_with_a_placeholder_or_reference_secret_part_is_excluded() {
        // Issue #919 follow-up (benchmarks #436): the Convex and fal docs
        // placeholders and interpolations under the new exact names.
        for input in [
            "CONVEX_DEPLOY_KEY=prod:your-deployment-name|your-admin-key",
            "CONVEX_DEPLOY_KEY=prod:adjective-animal-123|super-secret-key",
            "CONVEX_DEPLOY_KEY=prod:happy-otter-123|${CONVEX_BODY}",
            "CONVEX_SELF_HOSTED_ADMIN_KEY=convex-self-hosted|$ADMIN_KEY",
            "CONVEX_SELF_HOSTED_ADMIN_KEY: \"convex-self-hosted|{{ admin_key }}\"",
            "CONVEX_DEPLOY_KEY=preview:acme:web|<DEPLOY_KEY_BODY>",
            "CONVEX_DEPLOY_KEY=prod:happy-otter-123|xxxxxxxxxxxxxxxxxxxx",
            "FAL_KEY=your-fal-key-id:your-fal-key-secret",
            "FAL_KEY=${FAL_KEY_ID}:${FAL_KEY_SECRET}",
            "Authorization: Key your-fal-key-id:your-fal-key-secret",
        ] {
            assert!(detect(input).is_empty(), "{input}");
        }
        // Twins: a real-shaped secret part keeps the whole value high.
        let hex: String = (0..76)
            .map(|i| char::from(b"0123456789abcdef"[(i * 7 + 3) % 16]))
            .collect();
        for (input, value) in [
            (
                format!("CONVEX_DEPLOY_KEY=prod:happy-otter-123|01{hex}"),
                format!("prod:happy-otter-123|01{hex}"),
            ),
            (
                "CONVEX_DEPLOY_KEY=prod:happy-otter-123|eyJ2SyntheticRevokedGatedCloudBody0Aq7Zx9"
                    .to_owned(),
                "prod:happy-otter-123|eyJ2SyntheticRevokedGatedCloudBody0Aq7Zx9".to_owned(),
            ),
            (
                "FAL_KEY=your-fal-key-id:5a1ed0ff5e7c0dedfeedbadacef00d42".to_owned(),
                "your-fal-key-id:5a1ed0ff5e7c0dedfeedbadacef00d42".to_owned(),
            ),
            // A lowercase phrase that is not the last run, and a port-like
            // last run, do not make a value a placeholder.
            (
                "FAL_KEY=super-secret-key:Zx81QpVn4Lk7Tr2Wm9Hs6Dc3".to_owned(),
                "super-secret-key:Zx81QpVn4Lk7Tr2Wm9Hs6Dc3".to_owned(),
            ),
            (
                "password=Zx81QpVn4Lk7Tr2Wm9Hs6Dc3:5432".to_owned(),
                "Zx81QpVn4Lk7Tr2Wm9Hs6Dc3:5432".to_owned(),
            ),
        ] {
            let candidates = detect(&input);
            let (start, end) = only_range(&candidates);
            assert_eq!(&input[start..end], value, "{input}");
            assert_eq!(candidates[0].confidence(), Confidence::High, "{input}");
        }
    }

    #[test]
    fn a_bare_key_suffix_stays_outside_the_vocabulary() {
        // Issue #919 benign twins: only the three whole names were added.
        for input in [
            "PRIMARY_KEY=SYNTHETICrevokedNEUTRALvalue0042xyzw",
            "SORT_KEY=SYNTHETICrevokedNEUTRALvalue0042xyzw",
            "CACHE_KEY=SYNTHETICrevokedNEUTRALvalue0042xyzw",
            "PARTITION_KEY=SYNTHETICrevokedNEUTRALvalue0042xyzw",
            "IDEMPOTENCY_KEY=SYNTHETICrevokedNEUTRALvalue0042xyzw",
            "CONVEX_KEY=SYNTHETICrevokedNEUTRALvalue0042xyzw",
            "MY_FAL_KEY=SYNTHETICrevokedNEUTRALvalue0042xyzw",
            "FAL_KEY_ID=5e7c0ded-feed-4bad-9ace-0ddba11c0de5",
            "CONVEX_DEPLOYMENT=dev:happy-otter-123",
            "FAL_KEY=${FAL_KEY}",
            "FAL_KEY=your_fal_key",
        ] {
            assert!(detect(input).is_empty(), "{input}");
        }
    }

    #[test]
    fn the_key_authorization_scheme_is_detected_whole() {
        // Issue #919: fal's `Authorization: Key <id>:<secret>`.
        const FAL: &str = "5e7c0ded-feed-4bad-9ace-0ddba11c0de5:5a1ed0ff5e7c0dedfeedbadacef00d42";
        for input in [
            format!("Authorization: Key {FAL}"),
            format!("authorization: key {FAL}\r\n"),
            format!("curl -H \"Authorization: Key {FAL}\" https://example.invalid/run"),
            format!("{{\"headers\":{{\"Authorization\":\"Key {FAL}\"}}}}"),
            format!("Proxy-Authorization: Key {FAL}"),
            format!("Authorization: Key {FAL}: sent"),
        ] {
            let candidates: Vec<Candidate> = detect(&input)
                .into_iter()
                .filter(|candidate| candidate.type_name() == "authorization_credential")
                .collect();
            let (start, end) = only_range(&candidates);
            assert_eq!(&input[start..end], FAL, "{input}");
            assert_eq!(candidates[0].confidence(), Confidence::High, "{input}");
            assert!(
                candidates[0]
                    .signals()
                    .iter()
                    .any(|signal| signal == "authorization-key-scheme")
            );
        }
    }

    #[test]
    fn key_as_prose_or_a_short_value_is_not_an_authorization_scheme() {
        for input in [
            "The Key to authorization is a signed request.",
            "Authorization: Key rotation",
            "authorization: keyring SYNTHETICrevokedNEUTRALvalue0042xyzw",
            "Authorization: Key $FAL_KEY",
            "Authorization: Key ${FAL_KEY}",
            "X-Authorization: Key 5e7c0ded-feed-4bad-9ace-0ddba11c0de5:5a1ed0ff",
            "notAuthorization: Key 5e7c0ded-feed-4bad-9ace-0ddba11c0de5:5a1ed0ff",
        ] {
            assert!(
                detect(input)
                    .iter()
                    .all(|candidate| candidate.type_name() != "authorization_credential"),
                "{input}"
            );
        }
    }

    // --- issue #911: secret-reference names and identifiers -------------

    /// A random literal, built at run time, for the redacted twins.
    fn random_literal() -> String {
        (0..32)
            .map(|i| char::from(b"aZ3kQ9xL2mV7pR4tW8nB5cD1fG6hJ0sY"[(i * 11 + 3) % 32]))
            .collect()
    }

    #[test]
    fn existing_secret_names_an_object_not_a_secret() {
        for input in [
            "auth:\n  existingSecret: postgres-credentials\n",
            "  existingSecret: app-db-credentials-v2\n",
            "redisAuthExistingSecret: redis-auth-prod\n",
            "existingSecretName: postgres-credentials\n",
            "secretName: tls-cert-prod\n",
        ] {
            assert!(detect(input).is_empty(), "{input}");
        }
        // `secret` and other `<prefix>_secret` names are unchanged.
        let literal = random_literal();
        for input in [
            format!("webhookSecret: {literal}\n"),
            format!("clientSecret: {literal}\n"),
            format!("secret: {literal}\n"),
        ] {
            assert_eq!(detect(&input).len(), 1, "{input}");
        }
    }

    #[test]
    fn an_unquoted_credential_variable_name_is_a_reference() {
        for input in [
            "    verify(payload, signing_secret=FAKE_SIGNING_SECRET)",
            "- secretKey: DB_PASSWORD\n",
            "  secretKey: STRIPE_WEBHOOK_SECRET\n",
            "client = Client(api_key=OPENAI_API_KEY)",
            "password=ADMIN_PASSWORD",
        ] {
            assert!(detect(input).is_empty(), "{input}");
        }
        // Twins: a literal in the same position, a quoted name, a
        // placeholder lead word (#756) and a non-credential tail stay
        // detected.
        let literal = random_literal();
        for input in [
            format!("    verify(payload, signing_secret={literal})"),
            format!("- secretKey: {literal}\n"),
            "password=\"ADMIN_PASSWORD_2f9QxL7m\"".to_owned(),
            "API_KEY=YOUR_ACMECLOUD_API_KEY".to_owned(),
            "password=SYNTHETIC_REVOKED_DB_PASS_VALUE".to_owned(),
            "password=Admin_Password".to_owned(),
        ] {
            assert!(!detect(&input).is_empty(), "{input}");
        }
    }

    #[test]
    fn a_reverse_dns_identifier_is_a_reference() {
        for input in [
            "case accessToken = \"com.example.app.accessToken\"",
            "case clientSecret = \"com.example.app.clientSecret\"",
            "userPassword = \"io.example.keychain.user-password\"",
            "static let refreshToken = \"dev.example.auth.refresh_token\"",
        ] {
            assert!(detect(input).is_empty(), "{input}");
        }
        let literal = random_literal();
        for input in [
            format!("case accessToken = \"{literal}\""),
            // A JWT and a two-label dotted value are not reverse-DNS.
            "accessToken = \"eyJhbGciOi.eyJzdWIiOi.SflKxwRJSMeKKF2QT4\"".to_owned(),
            "accessToken = \"com.Zx81QpVn4Lk7Tr2Wm9\"".to_owned(),
            "accessToken = \"xq.Zx81QpVn4Lk7.Tr2Wm9Hs6Dc3\"".to_owned(),
        ] {
            assert!(!detect(&input).is_empty(), "{input}");
        }
    }

    #[test]
    fn a_lua_or_path_method_call_is_a_source_code_expression() {
        for input in [
            "local secret = secrets:get(partner)",
            "local token = vault:read(\"app/token\")",
            "let password = vault::read(path);",
        ] {
            assert!(detect(input).is_empty(), "{input}");
        }
        // A colon-joined literal with no call stays detected.
        let literal = random_literal();
        for input in [
            format!("local secret = user:{literal}"),
            format!("secret = {literal}"),
        ] {
            assert!(!detect(&input).is_empty(), "{input}");
        }
    }

    #[test]
    fn a_secret_path_term_inside_a_template_lookup_is_a_reference() {
        for input in [
            "vault_token: \"{{ lookup('community.hashi_vault.hashi_vault', 'secret=kv/data/app:token') }}\"",
            "db_password: \"{{ lookup('hashi_vault', 'secret=secret/data/db:password url=https://vault.example.invalid') }}\"",
            "api_key: \"{{ lookup('hashi_vault', 'secret=kv/app') }}\"",
        ] {
            assert!(detect(input).is_empty(), "{input}");
        }
        // A literal lookup term, and a path outside a template, stay
        // detected.
        let literal = random_literal();
        for input in [
            format!("vault: \"{{{{ lookup('hashi_vault', 'secret={literal}') }}}}\""),
            format!("secret=kv/data/{literal}"),
            format!("{{{{ x }}}} secret=kv/data/{literal}"),
        ] {
            assert!(!detect(&input).is_empty(), "{input}");
        }
    }

    #[test]
    fn pass_is_not_a_name_token() {
        // Issue #823: `pass` alone, or as a suffix, is an ordinary identifier.
        for input in [
            "pass=SYNTHETIC_REVOKED_DB_PASS_VALUE",
            "render_pass = \"SYNTHETIC_REVOKED_DB_PASS_VALUE\"",
            "first_pass: SYNTHETIC_REVOKED_DB_PASS_VALUE",
            "second_pass=SYNTHETIC_REVOKED_DB_PASS_VALUE",
            "shadowPass = 'SYNTHETIC_REVOKED_DB_PASS_VALUE'",
            "app_db_pass=SYNTHETIC_REVOKED_DB_PASS_VALUE",
        ] {
            assert!(detect(input).is_empty(), "{input}");
        }
    }

    #[test]
    fn generic_token_name_is_an_explicit_exclusion() {
        assert!(detect("token=SYNTHETIC_REVOKED_CONTEXT_VALUE").is_empty());
    }

    #[test]
    fn value_below_the_minimum_length_is_ignored() {
        assert!(detect("api_key=abcdefg").is_empty());
    }

    #[test]
    fn value_above_the_detector_bound_is_ignored_deterministically() {
        let input = format!("api_key={}", "A".repeat(100_008));
        assert!(detect(&input).is_empty());
    }

    #[test]
    fn common_high_entropy_or_identifier_like_values_stay_unchanged() {
        for input in [
            "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            "checksum=9e107d9d372bb6826bd81d3542a419d6",
            "550e8400-e29b-41d4-a716-446655440000",
            "01ARZ3NDEKTSV4RRFFQ69G5FAV",
            "request_01_SYNTHETIC_GENERATED_IDENTIFIER_987654321",
            "styles.module.css?hash=7f3a9c2d1e",
            "//# sourceMappingURL=app.7f3a9c2d1e.js.map",
            "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAAB",
            "header.payload.signature",
            "sha512-SYNTHETICPACKAGEINTEGRITYBASE64VALUE==",
            "model=gpt-5.6-codex-2026-08-31",
        ] {
            assert!(
                detect(input).is_empty(),
                "expected no findings for {input:?}"
            );
        }
    }

    /// A synthetic `prefix` + 32-byte SID body. Built at runtime rather than
    /// written as a literal: GitHub push protection rejects a literal
    /// `SK` + 32 hex value, even a synthetic one.
    fn synthetic_sid(prefix: &str, body_half: &str) -> String {
        format!("{prefix}{body_half}{body_half}")
    }

    #[test]
    fn twilio_account_and_api_key_sids_are_public_identifiers() {
        // Issue #746. Locally constructed synthetic SIDs.
        let api_key_sid = synthetic_sid("SK", "0123456789abcdef");
        let account_sid = "AC0123456789abcdef0123456789abcde0";
        for input in [
            format!("twilio credentials: {api_key_sid} {account_sid}"),
            format!("credentials: {account_sid}"),
            format!("credentials: {api_key_sid}"),
            format!("api_key={api_key_sid}"),
            format!("secret: \"{account_sid}\""),
        ] {
            assert!(detect(&input).is_empty(), "{input}");
        }
    }

    #[test]
    fn values_near_a_twilio_sid_shape_stay_detected() {
        let full = synthetic_sid("SK", "0123456789abcdef");
        for value in [
            // Uppercase hex in the body: not Twilio's SID shape.
            synthetic_sid("SK", "0123456789ABCDEF"),
            "AC0123456789ABCDEF0123456789ABCDEF".to_owned(),
            // One byte short and one byte long.
            full[..full.len() - 1].to_owned(),
            format!("{full}0"),
            // Another prefix.
            synthetic_sid("XK", "0123456789abcdef"),
        ] {
            let input = format!("credentials: {value}");
            assert_eq!(only_range(&detect(&input)), (13, input.len()), "{input}");
        }
    }

    #[test]
    fn instructional_placeholders_in_key_assignments_are_excluded() {
        // Issue #756: the same predicate `bearer-token` applies (#745).
        for input in [
            "mailchimp.setConfig({ apiKey: \"YOUR_API_KEY\", server: \"us19\" });",
            "apiKey: \"YOUR_API_KEY\"",
            "const apiKey = \"YOUR_API_KEY\";",
            "api_key = \"YOUR_API_KEY\"",
            "API_KEY=YOUR_API_KEY",
            "apiKey: \"your_api_key\"",
            "apiKey: \"YOUR_KEY\"",
            "client_secret: 'YOUR_CLIENT_SECRET'",
            "access_token=YOUR_ACCESS_TOKEN",
            "API_KEY=your-api-key-here",
            "SECRET_KEY=INSERT_SECRET_KEY_HERE",
            "api_key: ENTER_YOUR_API_KEY",
            "Authorization: Token YOUR_API_TOKEN",
        ] {
            assert!(detect(input).is_empty(), "{input}");
        }
    }

    #[test]
    fn real_values_in_placeholder_style_assignments_stay_detected() {
        for (prefix, value, suffix) in [
            ("apiKey: \"", "YOUR_API_KEY_9f2cQ7xLm4Rt", "\""),
            ("apiKey: \"", "YOUR_API_KEY9f2cQ7xLm4Rt", "\""),
            ("API_KEY=", "YOUR_ACMECLOUD_API_KEY", ""),
            ("API_KEY=", "KEY_YOUR_API_KEY", ""),
            (
                "mailchimp.setConfig({ apiKey: \"",
                "q7Lm2Xv9Rt4Kp8Wz3Nc6Bh1Jd5Fs0GyTa",
                "\", server: \"us19\" });",
            ),
            (
                "const apiKey = \"",
                "Zx81QpVn4Lk7Tr2Wm9Hs6Dc3Jf0Gb5Ye8Ua1Io4",
                "\";",
            ),
        ] {
            let input = format!("{prefix}{value}{suffix}");
            let start = prefix.len();
            assert_eq!(
                only_range(&detect(&input)),
                (start, start + value.len()),
                "{input}"
            );
        }
    }

    #[test]
    fn a_bounded_entropy_value_never_overrides_an_unrecognized_name() {
        for input in [
            "id=SYNTHETIC_UNQUALIFIED_HIGH_ENTROPY_VALUE",
            "note=SYNTHETIC_REVOKED_CONTEXT_VALUE",
            "Reminder: SYNTHETIC_REVOKED_CONTEXT_VALUE was already rotated last week.",
        ] {
            assert!(
                detect(input).is_empty(),
                "expected no findings for {input:?}"
            );
        }
    }

    #[test]
    fn additional_placeholder_words_are_excluded_at_the_minimum_length() {
        for input in ["webhook_secret=redacted", "client_secret=replaceme"] {
            assert!(
                detect(input).is_empty(),
                "expected no findings for {input:?}"
            );
        }
    }

    // --- issue #264: masked values are excluded as repeated-character
    // filler, the same exclusion #256 gave the connection-string detector.

    #[test]
    fn masked_values_are_excluded_as_repeated_character_filler() {
        for input in [
            "Password: ********",
            "Password: \u{2022}\u{2022}\u{2022}\u{2022}\u{2022}\u{2022}\u{2022}\u{2022}",
        ] {
            assert!(
                detect(input).is_empty(),
                "expected no findings for {input:?}"
            );
        }
    }

    #[test]
    fn a_near_miss_of_repeated_character_filler_is_still_detected() {
        // A trailing, distinct character breaks the uniform run.
        assert!(!detect("Password: ********x").is_empty());
    }

    // --- issue #257: placeholder-word exclusion is exact-string equality --
    //
    // `is_generic_placeholder_word` used to require the whole value to equal
    // one listed word. `matches_placeholder_vocabulary` (super::text) closes
    // the trivial lexical variants below while still requiring every token
    // in the value to reduce to a listed word, so a listed word merely
    // embedded in a larger, unrelated value is not swept in for free (see
    // `a_placeholder_word_embedded_in_a_larger_high_entropy_value_is_still_detected`
    // below).

    #[test]
    fn a_leading_separator_inside_the_value_does_not_defeat_the_exclusion() {
        assert!(detect("secret=\" changeme\"").is_empty());
    }

    #[test]
    fn an_appended_digit_does_not_defeat_the_exclusion() {
        assert!(detect("secret_key=\"changeme2\"").is_empty());
    }

    #[test]
    fn hyphenating_two_listed_words_does_not_defeat_the_exclusion() {
        // The issue's own reproduction hyphenates three words
        // (`REDACTED-EXAMPLE-VALUE`); `value` is not itself a listed
        // placeholder word, so it is dropped here per the issue's "or the
        // maintainers' chosen equivalent minimal set" allowance -- every
        // token in the value must reduce to a listed word, which keeps a
        // value like `secret-CFj9...` (a real high-entropy secret hyphenated
        // after an unrelated leading word) from being excluded for free.
        assert!(detect("secret_key: \"REDACTED-EXAMPLE\"").is_empty());
    }

    #[test]
    fn a_placeholder_word_embedded_in_a_larger_high_entropy_value_is_still_detected() {
        let input = "api_key=SecretSyntheticRevokedContextValue9fQ";
        assert!(
            !detect(input).is_empty(),
            "expected a finding for {input:?}"
        );
    }

    #[test]
    fn a_listed_word_followed_by_unrelated_tokens_is_still_detected() {
        // Same shape as the hyphenation bypass above, but the extra token
        // (`over`, `there`) is not itself a listed word, so the value must
        // not be excluded -- a token-boundary fix must not degrade into
        // "any token is a listed word".
        assert!(!detect("client_secret=password_over_there").is_empty());
    }

    #[test]
    fn documented_aws_names_retain_classification_with_a_colon_separator_and_quoting() {
        let input = "AWS_SECRET_ACCESS_KEY: \"SYNTHETIC_REVOKED_AWS_CONTEXT_VALUE\"";
        let candidates = detect(input);
        assert_eq!(only_range(&candidates), (24, 59));
        assert_eq!(candidates[0].confidence(), Confidence::High);
        assert_eq!(candidates[0].specificity(), Some(Specificity::Contextual));
    }

    #[test]
    fn basic_and_token_authorization_schemes_are_detected() {
        let basic_input = "Authorization: Basic U1lOVEhFVElDX1JFVk9LRUQ=";
        let basic = detect(basic_input);
        let (start, end) = only_range(&basic);
        assert_eq!(&basic_input[start..end], "U1lOVEhFVElDX1JFVk9LRUQ=");
        assert_eq!(basic[0].type_name(), "authorization_credential");
        assert_eq!(basic[0].confidence(), Confidence::High);
        assert_eq!(basic[0].specificity(), Some(Specificity::Structural));

        let token_input = "Authorization: Token SYNTHETIC_REVOKED_TOKEN_VALUE_1234";
        let token = detect(token_input);
        let (start, end) = only_range(&token);
        assert_eq!(
            &token_input[start..end],
            "SYNTHETIC_REVOKED_TOKEN_VALUE_1234"
        );
        assert_eq!(token[0].type_name(), "authorization_credential");
        assert_eq!(token[0].confidence(), Confidence::High);
        assert_eq!(token[0].specificity(), Some(Specificity::Structural));
    }

    #[test]
    fn token_authorization_and_nested_assignment_emit_overlapping_candidates() {
        let input = "Authorization: Token api_key=SYNTHETIC_REVOKED_AUTHORIZATION_OVERLAP_1234";
        let candidates = detect(input);

        assert_eq!(candidates.len(), 2);
        assert_eq!(candidates[0].type_name(), "contextual_secret");
        assert_eq!(candidates[0].confidence(), Confidence::High);
        assert_eq!(candidates[0].specificity(), Some(Specificity::Contextual));
        assert_eq!(candidates[0].range(), ByteRange::new(29, 73).unwrap());
        assert_eq!(candidates[1].type_name(), "authorization_credential");
        assert_eq!(candidates[1].confidence(), Confidence::High);
        assert_eq!(candidates[1].specificity(), Some(Specificity::Structural));
        assert_eq!(candidates[1].range(), ByteRange::new(21, 73).unwrap());
        assert!(candidates[0].range().overlaps(candidates[1].range()));
    }

    #[test]
    fn authorization_value_at_the_minimum_accepted_length_is_medium_confidence() {
        let input = "Authorization: Token TOKENVALUE12";
        let candidates = detect(input);
        let (start, end) = only_range(&candidates);
        assert_eq!(&input[start..end], "TOKENVALUE12");
        assert_eq!(candidates[0].type_name(), "authorization_credential");
        assert_eq!(candidates[0].confidence(), Confidence::Medium);
        assert_eq!(candidates[0].specificity(), Some(Specificity::Structural));
    }

    #[test]
    fn authorization_value_below_the_minimum_accepted_length_is_ignored() {
        assert!(detect("Authorization: Basic short-value").is_empty());
    }

    #[test]
    fn authorization_scheme_other_than_basic_or_token_is_ignored() {
        assert!(detect("Authorization: Digest SYNTHETIC_REVOKED_DIGEST_VALUE_1234").is_empty());
    }

    #[test]
    fn proxy_authorization_and_mid_line_basic_headers_are_detected() {
        // Issue #818. `U1lOVEhFVElDOmZpeHR1cmU=` is base64 of `SYNTHETIC:fixture`.
        const BASIC: &str = "U1lOVEhFVElDOmZpeHR1cmU=";
        for input in [
            format!("Proxy-Authorization: Basic {BASIC}"),
            format!("curl -H 'Authorization: Basic {BASIC}' https://api.example.test"),
            format!("{{\"headers\":{{\"authorization\":\"Basic {BASIC}\"}}}}"),
            format!("[req] authorization: basic {BASIC}"),
        ] {
            let candidates: Vec<Candidate> = detect(&input)
                .into_iter()
                .filter(|candidate| candidate.type_name() == "authorization_credential")
                .collect();
            let (start, end) = only_range(&candidates);
            assert_eq!(&input[start..end], BASIC, "{input}");
        }
        // A wider header name or identifier does not open one.
        for input in [
            format!("notAuthorization: Basic {BASIC}"),
            format!("X-Authorization: Basic {BASIC}"),
            format!("reverse_proxy-authorization: Basic {BASIC}"),
            // Mid-line `Token` stays with the provider detectors.
            format!("curl -H \"Authorization: token {BASIC}\""),
        ] {
            assert!(
                detect(&input)
                    .iter()
                    .all(|candidate| candidate.type_name() != "authorization_credential"),
                "{input}"
            );
        }
    }

    // --- issue #263: a value fully delimited by `{{ ... }}` is a template
    // reference (Ansible/Helm/Salt Jinja, Go templates), not a secret -------

    #[test]
    fn a_quoted_jinja_template_reference_is_excluded() {
        for input in [
            "password: \"{{ vault_db_password }}\"",
            "password: \"{{ lookup('env', 'DB_PASSWORD') }}\"",
            "password: '{{ pillar[\"postgres\"][\"password\"] }}'",
            "\"password\": \"{{ vault_db_password }}\"",
        ] {
            assert!(
                detect(input).is_empty(),
                "expected no findings for {input:?}"
            );
        }
    }

    #[test]
    fn a_quoted_helm_or_go_template_reference_is_excluded() {
        for input in [
            "password: \"{{ .Values.postgresql.auth.password }}\"",
            "client_secret: \"{{ .ClientSecretRef }}\"",
        ] {
            assert!(
                detect(input).is_empty(),
                "expected no findings for {input:?}"
            );
        }
    }

    #[test]
    fn a_value_only_starting_with_a_template_delimiter_is_still_detected() {
        let input = "password=\"{{ SYNTHETIC_REVOKED_CONTEXT_VALUE\"";
        assert!(
            !detect(input).is_empty(),
            "expected a finding for {input:?}"
        );
    }

    #[test]
    fn a_template_delimiter_pair_embedded_in_a_larger_value_is_still_detected() {
        let input = "password=SYNTHETIC_REVOKED_{{ x }}_CONTEXT_VALUE";
        assert!(
            !detect(input).is_empty(),
            "expected a finding for {input:?}"
        );
    }

    // --- issue #279: an interpolation, macro-expansion, or
    // command-substitution reference other than `${...}`, `$name`, or
    // `{{...}}` -- a shell/Makefile/Kustomize `$(...)`, an Azure Pipelines
    // `$[...]` runtime expression, a Ruby `#{...}` interpolation, an
    // opencode `{env:...}`/`{file:...}` substitution, or a backtick-quoted
    // command substitution / JS template literal -- is excluded like the
    // existing `{{...}}` template-reference exclusion (#263): only a value
    // fully delimited by the syntax, not merely starting with it, is a bare
    // reference.

    #[test]
    fn interpolation_and_command_substitution_references_are_excluded() {
        for input in [
            // Azure Pipelines macro, unquoted YAML.
            "password: $(registryPassword)",
            // Shell command substitution, quoted.
            "PASSWORD=\"$(pass show db/prod)\"",
            // Ruby interpolation, quoted YAML.
            "password: \"#{ENV['DB_PASSWORD']}\"",
            // opencode env substitution, quoted JSON.
            "\"apiKey\": \"{env:ANTHROPIC_API_KEY}\"",
            // opencode file substitution, quoted JSON.
            "\"apiKey\": \"{file:./secrets/api-key}\"",
            // Azure Pipelines runtime expression, unquoted -- exercises the
            // delimited-span scan, since `]` is otherwise a generic
            // unquoted-value boundary that would truncate this one short.
            "password: $[variables.x]",
            // Backtick-quoted JS template literal, unquoted -- exercises
            // the delimited-span scan for the same reason (`}` truncation).
            "password: `${process.env.X}`",
            // Backtick command substitution.
            "password=`date +%s`",
            // Nested command substitution.
            "password=$(echo $(date))",
        ] {
            assert!(
                detect(input).is_empty(),
                "expected no findings for {input:?}"
            );
        }
    }

    #[test]
    fn a_value_only_starting_with_an_interpolation_delimiter_is_still_detected() {
        for input in [
            "password=$(SYNTHETIC_REVOKED_CONTEXT_VALUE",
            "password=$[SYNTHETIC_REVOKED_CONTEXT_VALUE",
            "password=\"#{SYNTHETIC_REVOKED_CONTEXT_VALUE\"",
            "password=\"{env:SYNTHETIC_REVOKED_CONTEXT_VALUE\"",
            "password=`SYNTHETIC_REVOKED_CONTEXT_VALUE",
        ] {
            assert!(
                !detect(input).is_empty(),
                "expected a finding for {input:?}"
            );
        }
    }

    #[test]
    fn an_interpolation_delimiter_pair_embedded_in_a_larger_value_is_still_detected() {
        for input in [
            "password=SYNTHETIC_REVOKED_$(x)_CONTEXT_VALUE",
            "password=SYNTHETIC_REVOKED_#{x}_CONTEXT_VALUE",
            "password=SYNTHETIC_REVOKED_`x`_CONTEXT_VALUE",
            // A well-formed `{env:...}`/`{file:...}` pair at the very start
            // of an unquoted value, followed by more content rather than
            // ending the value there, previously fell into the `{`/`[`
            // flow-mapping guard (issue #266) and was silently dropped with
            // no candidate at all, instead of being reported like the other
            // delimiter shapes above.
            "password={env:ANTHROPIC_API_KEY}_SYNTHETIC_REVOKED_CONTEXT_VALUE",
            "password={file:SYNTHETIC_REVOKED_PATH}_CONTEXT_VALUE",
        ] {
            assert!(
                !detect(input).is_empty(),
                "expected a finding for {input:?}"
            );
        }
    }

    #[test]
    fn interpolation_references_are_excluded_across_crlf_tab_operator_and_json_escaping() {
        for input in [
            // CRLF line ending after the value.
            "password: $(registryPassword)\r\n",
            // A tab, instead of a space, after the `:` operator.
            "password:\t$(registryPassword)",
            // JSON-escaped double quotes inside a Ruby interpolation that
            // would use single quotes unescaped.
            "{\"password\": \"#{ENV[\\\"DB_PASSWORD\\\"]}\"}",
        ] {
            assert!(
                detect(input).is_empty(),
                "expected no findings for {input:?}"
            );
        }
    }

    // --- issue #292: a cmd.exe/batch-style Windows environment-variable
    // reference (`%VAR%`) or a SQL named bind parameter (`:identifier`) is
    // excluded like the existing reference-syntax exclusions -- deferred
    // out of issue #279 (`docs/specs/contextual-detection.md`)
    // so each gets its own explicit fixture coverage. Only a value fully
    // shaped as the syntax, with an identifier as its content, is a bare
    // reference; a missing delimiter, or the pair embedded inside a larger
    // value, stays detected.

    #[test]
    fn windows_env_and_sql_bind_parameter_references_are_excluded() {
        for input in [
            // Windows cmd-style env expansion, unquoted.
            "PASSWORD=%DB_PASSWORD%",
            // Windows cmd-style env expansion, quoted.
            "PASSWORD=\"%DB_PASSWORD%\"",
            // SQL named bind parameter, unquoted.
            "password = :new_password_hash",
            // SQL named bind parameter, quoted YAML.
            "password: ':new_password_hash'",
        ] {
            assert!(
                detect(input).is_empty(),
                "expected no findings for {input:?}"
            );
        }
    }

    #[test]
    fn a_windows_env_reference_missing_either_delimiter_is_still_detected() {
        for input in [
            // Missing the closing `%`.
            "PASSWORD=%DB_PASSWORD_SYNTHETIC_REVOKED",
            // Missing the opening `%`.
            "PASSWORD=DB_PASSWORD_SYNTHETIC_REVOKED%",
        ] {
            assert!(
                !detect(input).is_empty(),
                "expected a finding for {input:?}"
            );
        }
    }

    #[test]
    fn a_windows_env_reference_pair_embedded_in_a_larger_value_is_still_detected() {
        assert!(
            !detect("PASSWORD=SYNTHETIC_%DB_PASSWORD%_REVOKED_CONTEXT_VALUE").is_empty(),
            "expected a finding for an embedded %VAR% pair"
        );
    }

    #[test]
    fn a_windows_env_reference_whose_content_is_not_an_identifier_is_still_detected() {
        assert!(
            !detect("PASSWORD=\"%not an identifier%\"").is_empty(),
            "expected a finding when the %...% content is not identifier-shaped"
        );
    }

    #[test]
    fn a_sql_bind_parameter_missing_its_colon_is_still_detected() {
        assert!(
            !detect("password = new_password_hash_SYNTHETIC_REVOKED").is_empty(),
            "expected a finding for a bare identifier with no leading colon"
        );
    }

    #[test]
    fn a_sql_bind_parameter_embedded_in_a_larger_value_is_still_detected() {
        assert!(
            !detect("password=SYNTHETIC_:new_password_hash_REVOKED_CONTEXT_VALUE").is_empty(),
            "expected a finding for an embedded :identifier pair"
        );
    }

    #[test]
    fn windows_env_and_sql_bind_parameter_references_are_excluded_across_crlf_and_unicode_prefix() {
        for input in [
            // CRLF line ending after the value.
            "PASSWORD=%DB_PASSWORD%\r\n",
            // A tab, instead of a space, after the `=` operator.
            "PASSWORD=\t%DB_PASSWORD%",
            // A multi-byte Unicode character preceding the assignment,
            // exercising byte-offset (not char-count) boundary handling.
            "note: caf\u{e9} \u{2014} PASSWORD=%DB_PASSWORD%",
            "note: caf\u{e9} \u{2014} password = :new_password_hash",
        ] {
            assert!(
                detect(input).is_empty(),
                "expected no findings for {input:?}"
            );
        }
    }

    // --- issue #280: a secret-manager reference -- a pointer `op run`,
    // LiteLLM, `vals`, the bank-vaults injector, or a cloud secret manager
    // resolves at runtime -- is excluded like the existing `${...}` and
    // `{{...}}` reference exclusions. Each grammar requires the whole value
    // to satisfy that scheme's reference shape, not merely start with its
    // prefix.

    #[test]
    fn secret_manager_references_are_excluded() {
        for input in [
            "PASSWORD=op://Engineering/db-prod/password",
            "api_key: os.environ/ANTHROPIC_API_KEY",
            "secret: projects/example-project/secrets/api-key/versions/latest",
            "secret: projects/example-project/secrets/api-key",
            "secret: projects/123456789012/secrets/api-key",
            "password=ref+vault://secret/data/db-prod#/password",
            "password=vault:secret/data/db-prod#password",
            "secret=arn:aws:secretsmanager:us-east-1:123456789012:secret:prod/db/password-Ab12Cd",
            "password=@Microsoft.KeyVault(SecretUri=https://myvault.vault.azure.net/secrets/mysecret/abc123)",
            "password=\"@Microsoft.KeyVault(VaultName=myvault;SecretName=mysecret;SecretVersion=abc123)\"",
        ] {
            assert!(
                detect(input).is_empty(),
                "expected no findings for {input:?}"
            );
        }
    }

    #[test]
    fn a_secret_manager_scheme_prefix_that_does_not_satisfy_its_grammar_is_still_detected() {
        for input in [
            // `op://` with no vault/item/field segmentation at all.
            "password=op://SYNTHETIC_REVOKED_NO_SLASH_CONTEXT_VALUE",
            // `os.environ/` followed by characters outside an env-var identifier.
            "api_key=os.environ/SYNTHETIC-REVOKED-CONTEXT-VALUE!!!",
            // `projects/...` with no `secrets/` segment.
            "secret: projects/SYNTHETIC_REVOKED_MISSING_SECRETS_SEGMENT_CONTEXT_VALUE",
            // `ref+` with no `://` scheme delimiter.
            "password=ref+SYNTHETIC_REVOKED_NO_SCHEME_DELIMITER_CONTEXT_VALUE",
            // `vault:` with no `#` key selector.
            "password=vault:SYNTHETIC_REVOKED_NO_FRAGMENT_CONTEXT_VALUE",
            // An ARN whose account-id segment is not 12 digits.
            "secret=arn:aws:secretsmanager:us-east-1:SYNTHETIC_REVOKED_NOT_TWELVE_DIGITS:secret:name",
            // `@Microsoft.KeyVault(...)` whose interior is neither `SecretUri=`
            // nor `Key=value;...` fields.
            "password=@Microsoft.KeyVault(SYNTHETIC_REVOKED_CONTEXT_VALUE)",
        ] {
            assert!(
                !detect(input).is_empty(),
                "expected a finding for {input:?}"
            );
        }
    }

    // --- issue #293: an Azure Key Vault `SecretUri=` reference is excluded
    // for any syntactically well-formed HTTPS host, not only a literal
    // `*.vault.azure.net` suffix. Key Vault is reachable under several
    // sovereign-cloud domains (and Private Link hostnames) with no fixed,
    // enumerable list, so the grammar bounds the host's *shape* -- an FQDN
    // of two or more DNS labels -- the same way the sibling GCP/AWS
    // grammars bound an identifier's shape rather than checking a specific
    // known value.

    #[test]
    fn azure_keyvault_secreturi_is_excluded_for_any_well_formed_https_host() {
        for input in [
            // A non-Azure host: the reference grammar validates host
            // *shape*, not domain identity.
            "password: @Microsoft.KeyVault(SecretUri=https://example.invalid/secrets/benchmark)",
            // Azure Government sovereign-cloud Key Vault suffix.
            "password=@Microsoft.KeyVault(SecretUri=https://myvault.vault.usgovcloudapi.net/secrets/mysecret)",
            // Azure China sovereign-cloud Key Vault suffix.
            "password=@Microsoft.KeyVault(SecretUri=https://myvault.vault.azure.cn/secrets/mysecret/abc123)",
        ] {
            assert!(
                detect(input).is_empty(),
                "expected no findings for {input:?}"
            );
        }
    }

    #[test]
    fn azure_keyvault_secreturi_with_a_malformed_host_is_still_detected() {
        for input in [
            // A single-label host: not an FQDN shape.
            "password=@Microsoft.KeyVault(SecretUri=https://localhost/secrets/SYNTHETIC_REVOKED)",
            // An empty host.
            "password=@Microsoft.KeyVault(SecretUri=https:///secrets/SYNTHETIC_REVOKED)",
            // A host containing a character outside the DNS label charset.
            "password=@Microsoft.KeyVault(SecretUri=https://my_vault.vault.azure.net/secrets/SYNTHETIC_REVOKED)",
        ] {
            assert!(
                !detect(input).is_empty(),
                "expected a finding for {input:?}"
            );
        }
    }

    #[test]
    fn azure_keyvault_reference_is_excluded_across_crlf_and_unicode_prefix() {
        for input in [
            // CRLF line ending after the value.
            "password: @Microsoft.KeyVault(SecretUri=https://myvault.vault.azure.net/secrets/mysecret)\r\n",
            // LF line ending after the value.
            "password: @Microsoft.KeyVault(SecretUri=https://myvault.vault.azure.net/secrets/mysecret)\n",
            // A multi-byte Unicode character preceding the assignment,
            // exercising byte-offset (not char-count) boundary handling.
            // Quoted because the unquoted-value scanner treats `;` as a
            // value boundary (the `VaultName=...;SecretName=...` form's
            // required separator).
            "note: caf\u{e9} \u{2014} password=\"@Microsoft.KeyVault(VaultName=myvault;SecretName=mysecret)\"",
        ] {
            assert!(
                detect(input).is_empty(),
                "expected no findings for {input:?}"
            );
        }
    }

    // --- issue #278: an unquoted value that is a source-code expression
    // (member access, call, subscript, or generic type) names where a value
    // lives, not the value itself -------------------------------------------

    #[test]
    fn a_known_reference_root_member_access_is_excluded() {
        for input in [
            "password=settings.DATABASE_PASSWORD",
            "  apiKey: config.anthropicApiKey,",
            "this.configService.get(user.id)",
            "cfg.RedisPassword",
        ] {
            assert!(
                detect(input).is_empty(),
                "expected no findings for {input:?}"
            );
        }
    }

    #[test]
    fn a_snake_case_attribute_reference_chain_is_excluded() {
        for input in [
            "password = random_password.db.result",
            "password=data.aws_secretsmanager_secret_version.db.secret_string",
        ] {
            assert!(
                detect(input).is_empty(),
                "expected no findings for {input:?}"
            );
        }
    }

    #[test]
    fn a_generic_type_or_subscript_value_is_excluded() {
        for input in ["pub api_key: Option<String>,", "api_key: Optional[str]"] {
            assert!(
                detect(input).is_empty(),
                "expected no findings for {input:?}"
            );
        }
    }

    #[test]
    fn a_call_or_subscript_truncated_at_a_string_literal_is_excluded() {
        let input = "api_key=os.environ[\"OPENAI_API_KEY\"],";
        assert!(
            detect(input).is_empty(),
            "expected no findings for {input:?}"
        );
    }

    #[test]
    fn a_dotted_value_with_no_underscore_and_no_known_root_is_still_detected() {
        let input = "password: SYNTHETIC.REVOKED.CONTEXT_VALUE";
        assert!(
            !detect(input).is_empty(),
            "expected a finding for {input:?}"
        );
    }

    #[test]
    fn an_underscore_separated_value_with_no_dot_is_still_detected_at_high_confidence() {
        let input = "password: SYNTHETIC_REVOKED_CONTEXT_VALUE";
        let candidates = detect(input);
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].confidence(), Confidence::High);
    }

    // --- issue #467: the residual of #278 — a source-code expression whose
    // call parentheses are *closed*, and one cut short inside them ----------

    #[test]
    fn a_closed_call_expression_is_excluded() {
        for input in [
            // A PascalCase client type's member call.
            "secret = SecretManagerServiceClient.access_secret_version(req)",
            // A bare function call.
            "secret = getSecretOrThrow(SECRET_NAME_CONSTANT)",
            // A dotted module chain ending in a keyword-argument call.
            "secret = django.core.signing.get_cookie_signer(salt=SALT)",
            // A call whose argument is a number.
            "api_key = rsa.generate_private_key(public_exponent=65537)",
        ] {
            assert!(
                detect(input).is_empty(),
                "expected no findings for {input:?}"
            );
        }
    }

    #[test]
    fn a_call_expression_cut_short_inside_its_arguments_is_excluded() {
        for input in [
            // Cut at the space inside an object-literal argument: the shape
            // whose redaction used to strand ` key: pem })` on the line.
            "secret = crypto.createPrivateKey({ key: pem })",
            // Cut at the comma between two arguments.
            "secret = helper(FIRST_ARGUMENT, SECOND_ARGUMENT)",
        ] {
            assert!(
                detect(input).is_empty(),
                "expected no findings for {input:?}"
            );
        }
    }

    #[test]
    fn redaction_of_a_truncated_call_expression_strands_nothing() {
        let input = "secret = crypto.createPrivateKey({ key: pem })";
        assert!(
            detect(input).is_empty(),
            "a partially matched call expression would strand the rest of its argument group",
        );
    }

    #[test]
    fn a_value_that_merely_embeds_parentheses_is_still_detected() {
        // A balanced `(...)` that does not end the value leaves trailing
        // characters, so the value is not a call expression end to end.
        let input = "password: SYNTHETIC(REVOKED)_CONTEXT_VALUE";
        let candidates = detect(input);
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].confidence(), Confidence::High);
    }

    #[test]
    fn a_quoted_value_with_an_unbalanced_parenthesis_is_still_detected() {
        // A quoted value carries its own delimiters, so it is never cut
        // mid-group and the truncation check does not apply to it.
        let input = "password: \"SYNTHETIC(REVOKED_CONTEXT_VALUE\"";
        let candidates = detect(input);
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].confidence(), Confidence::High);
    }

    #[test]
    fn a_bracket_group_opened_by_a_non_identifier_is_not_truncated_code() {
        // `$(`, `#{`, and `{{` open on punctuation rather than on an
        // identifier, so #266's and #279's fragment shapes stay detected.
        for input in [
            "password=$(SYNTHETIC_REVOKED_CONTEXT_VALUE",
            "password=SYNTHETIC_REVOKED_{{ x }}_CONTEXT_VALUE",
            "password=SYNTHETIC_REVOKED_#{x}_CONTEXT_VALUE",
        ] {
            assert!(
                !detect(input).is_empty(),
                "expected a finding for {input:?}"
            );
        }
    }

    // --- issue #262: a contextual-assignment operator with no value before
    // end-of-line does not cross into the next physical line ---------------

    #[test]
    fn operator_with_no_value_before_end_of_line_does_not_cross_into_the_next_line() {
        for input in [
            // A Kubernetes-style YAML key opening a nested mapping.
            "secret:\n  secretName: web-tls-cert",
            // An interactive prompt with no value at all.
            "Password:\nPermission denied, please try again.",
            // An ssh transcript: prompt line, then the program's own denial.
            "fixture@db.example.test's password:\nfixture@db.example.test: Permission denied (publickey,password).",
        ] {
            assert!(
                detect(input).is_empty(),
                "expected no findings for {input:?}"
            );
        }
    }

    #[test]
    fn password_value_on_the_same_line_is_still_detected() {
        let input = "password: SYNTHETIC_REVOKED_CONTEXT_VALUE";
        let candidates = detect(input);
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].confidence(), Confidence::High);
        assert_eq!(candidates[0].specificity(), Some(Specificity::Contextual));
    }

    /// The paired recall regression (issue #265): the outer `database:`
    /// key's failed value scan used to advance the cursor past the nested
    /// `password:` key's own boundary character, so it was never matched.
    #[test]
    fn a_nested_credential_under_an_unrelated_parent_key_is_still_detected() {
        let input = "database:\n  password: SYNTHETIC_REVOKED_FIXTURE_VALUE";
        let candidates = detect(input);
        let (start, end) = only_range(&candidates);
        assert_eq!(&input[start..end], "SYNTHETIC_REVOKED_FIXTURE_VALUE");
        assert_eq!(candidates[0].confidence(), Confidence::High);
    }

    // --- issue #266: a YAML flow mapping's opening `{` (or a flow sequence's
    // `[`) is not treated as the start of an unquoted scalar -------------

    #[test]
    fn a_yaml_flow_mapping_key_is_not_captured_as_the_assignment_value() {
        let input = "volumes: [{name: tls, secret: {secretName: web-tls-cert}}]";
        assert!(
            detect(input).is_empty(),
            "expected no findings for {input:?}"
        );
    }

    #[test]
    fn a_block_style_secret_value_is_still_detected() {
        let input = "secret: SYNTHETIC_REVOKED_CONTEXT_VALUE";
        let candidates = detect(input);
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].confidence(), Confidence::High);
        assert_eq!(candidates[0].specificity(), Some(Specificity::Contextual));
    }

    #[test]
    fn open_contextual_assignment_hint_recognizes_a_pending_high_signal_or_ambiguous_name() {
        for open in [
            "api_key",
            "api_key=",
            "api_key: ",
            "\"api_key\"=",
            "'api_key' = ",
            "{api_key=",
            "Client(api_key=",
            "line one\napi_key:",
            "AWS_SECRET_ACCESS_KEY=",
            "auth",
            "credential:",
            // Issue #990: every name form the grammar joins to an operator
            // on a later line.
            "`password\n",
            "x\"password\"\n",
            "x'secret'\n  \n",
            "{\\\"password\\\"\n",
            "{\"kty\":\"oct\",\"k\"\n",
            "{\"kty\":\"RSA\",\"qi\"\r\n",
            "{\"kty\":\"oct\",\"k\":",
        ] {
            assert!(has_open_contextual_assignment(open), "{open:?}");
        }
    }

    #[test]
    fn open_jwk_member_hint_reads_only_the_members_own_line() {
        for closed in [
            // No `"kty"` on the member's line, before or after a break.
            "{\"k\"\n",
            "{\"kty\":\"oct\"}\n{\"k\"\n",
            "{\"kty\":\"oct\"}\r{\"k\"\n",
            // Unquoted, or not a secret member.
            "{\"kty\":\"oct\",k\n",
            "{\"kty\":\"RSA\",\"n\"\n",
        ] {
            assert!(!has_open_contextual_assignment(closed), "{closed:?}");
        }
    }

    #[test]
    fn open_contextual_assignment_hint_rejects_resolved_or_low_signal_text() {
        for closed in [
            "",
            "token=",
            "xapi_key=",
            "api_key=SYNTHETIC_REVOKED_CONTEXT_VALUE",
            "plain text",
        ] {
            assert!(!has_open_contextual_assignment(closed), "{closed:?}");
        }
    }

    // --- issue #484: declarative ruleset names section ---------------------

    #[test]
    fn a_ruleset_supplied_ambiguous_name_is_medium_confidence_at_the_ambiguous_threshold() {
        let input = "corp_passphrase=SYNTHETIC_REVOKED_RULESET_AMBIGUOUS_1234";
        let candidates = detect_with_ruleset_names(input, &["corp_passphrase"]);
        assert_eq!(only_range(&candidates), (16, input.len()));
        assert_eq!(candidates[0].confidence(), Confidence::Medium);
        assert_eq!(candidates[0].specificity(), Some(Specificity::Contextual));
    }

    #[test]
    fn a_ruleset_supplied_name_never_reaches_high_confidence_regardless_of_entropy() {
        // Same value shape that makes a `HIGH_SIGNAL_NAMES` match `High`
        // (issue #484's hazard: a caller-supplied high-signal name would
        // select the lower entropy bar and reach `High` on a `Contextual`
        // candidate). The ruleset path is restricted to the ambiguous
        // bucket, so it must stay `Medium` no matter how high the value's
        // entropy is.
        let input = "corp_passphrase=SYNTHETIC_REVOKED_CONTEXT_VALUE";
        let candidates = detect_with_ruleset_names(input, &["corp_passphrase"]);
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].confidence(), Confidence::Medium);
    }

    #[test]
    fn a_ruleset_supplied_name_below_the_ambiguous_entropy_threshold_is_ignored() {
        let input = "corp_passphrase=aaaaaaaaaaaaaaaaaaaa";
        let candidates = detect_with_ruleset_names(input, &["corp_passphrase"]);
        assert!(candidates.is_empty());
    }

    #[test]
    fn an_unlisted_name_produces_no_ruleset_candidate() {
        let input = "unrelated_field=SYNTHETIC_REVOKED_RULESET_AMBIGUOUS_1234";
        let candidates = detect_with_ruleset_names(input, &["corp_passphrase"]);
        assert!(candidates.is_empty());
    }

    #[test]
    fn the_ruleset_names_detector_never_matches_a_built_in_high_signal_name() {
        // The ruleset path only ever consults its own caller-supplied list,
        // never `HIGH_SIGNAL_NAMES` — a built-in name's presence in the
        // input is irrelevant to this detector even if it were (incorrectly)
        // passed in the extra list, since `crate::ruleset` never does that;
        // this asserts the detector's own restriction as a second layer.
        let input = "api_key=SYNTHETIC_REVOKED_CONTEXT_VALUE";
        let candidates = detect_with_ruleset_names(input, &["corp_passphrase"]);
        assert!(candidates.is_empty());
    }

    #[test]
    fn the_ruleset_names_detector_does_not_match_authorization_schemes() {
        let input = "Authorization: Basic aGVsbG86d29ybGQtc3ludGhldGljLXJldm9rZWQ=";
        let candidates = detect_with_ruleset_names(input, &["corp_passphrase"]);
        assert!(candidates.is_empty());
    }

    #[test]
    fn the_ruleset_names_detector_claims_the_fixed_reserved_id() {
        let detector = generic_token_ruleset_names_detector(vec!["corp_passphrase".to_owned()]);
        assert_eq!(detector.id(), RULESET_NAMES_DETECTOR_ID);
    }

    #[test]
    fn is_reserved_name_covers_both_built_in_buckets() {
        for name in HIGH_SIGNAL_NAMES.iter().chain(AMBIGUOUS_NAMES.iter()) {
            assert!(is_reserved_name(name), "{name}");
        }
        assert!(!is_reserved_name("corp_passphrase"));
    }

    // --- auth_token is a high-signal name (issue #941) -------------------

    #[test]
    fn auth_token_is_a_high_signal_name_and_its_neighbours_are_unchanged() {
        for name in ["auth_token", "authToken", "AUTH_TOKEN", "app_auth_token"] {
            assert!(is_high_signal_name(&normalize_name(name)), "{name}");
            assert!(!is_ambiguous_name(&normalize_name(name)), "{name}");
        }
        assert!(is_high_signal_name("oauth_token"));
        assert!(is_ambiguous_name("auth"));
        assert!(!is_high_signal_name("auth"));
        assert!(!is_high_signal_name("csrf_token"));
    }

    #[test]
    fn an_auth_token_literal_is_high_and_placeholders_stay_silent() {
        let value = "Rk7vQ2mX9pL4tW8nB5cD1fG6hJ3sY0aZ";
        let input = format!("auth_token={value}");
        let candidates = detect(&input);
        assert_eq!(candidates.len(), 1, "{candidates:?}");
        assert_eq!(candidates[0].confidence(), Confidence::High);
        assert_eq!(
            &input[candidates[0].range().start()..candidates[0].range().end()],
            value
        );
        for silent in [
            "auth_token=your_auth_token",
            "auth_token=<AUTH_TOKEN>",
            "auth_token=${AUTH_TOKEN}",
            "auth_token=TWILIO_AUTH_TOKEN",
            "auth_token: {{ auth_token }}",
            "auth_token=xxxxxxxxxxxxxxxxxxxxxxxx",
        ] {
            assert!(detect(silent).is_empty(), "{silent}");
        }
    }

    // --- bare vendor-prefixed policy candidates (issue #552) ------------

    const VENDOR_PREFIX_LEGACY_BODY: &str = "SYNTHETICrevoked0001aaaaBBBBccccDDDD1234wxyzEFGH";
    const VENDOR_PREFIX_PROJ_BODY: &str = "SYNTHETICrevoked0002bbbbCCCCddddEEEE5678uvwxIJKL";

    #[test]
    fn a_bare_sk_legacy_value_is_a_medium_confidence_entropy_specificity_candidate() {
        let input = format!("sk-{VENDOR_PREFIX_LEGACY_BODY}");
        let candidates = detect(&input);
        assert_eq!(only_range(&candidates), (0, input.len()));
        assert_eq!(candidates[0].type_name(), "vendor_prefixed_credential");
        assert_eq!(candidates[0].confidence(), Confidence::Medium);
        assert_eq!(candidates[0].specificity(), Some(Specificity::Entropy));
    }

    #[test]
    fn every_documented_namespace_is_detected_independently() {
        for prefix in ["sk-", "sk-proj-", "sk-svcacct-", "sk-admin-"] {
            let input = format!("{prefix}{VENDOR_PREFIX_LEGACY_BODY}");
            let candidates = detect(&input);
            assert_eq!(only_range(&candidates), (0, input.len()), "{prefix}");
            assert_eq!(
                candidates[0].type_name(),
                "vendor_prefixed_credential",
                "{prefix}"
            );
        }
    }

    #[test]
    fn a_low_entropy_bare_vendor_prefixed_body_is_not_detected() {
        let input = format!("sk-{}", "A".repeat(48));
        assert!(detect(&input).is_empty());
    }

    #[test]
    fn a_bare_vendor_prefixed_body_one_byte_short_is_not_detected() {
        let short_body = &VENDOR_PREFIX_LEGACY_BODY[..47];
        let input = format!("sk-{short_body} end");
        assert!(detect(&input).is_empty());
    }

    #[test]
    fn a_bare_vendor_prefixed_value_embedded_in_a_wider_identifier_is_not_detected() {
        let input = format!("sk-{VENDOR_PREFIX_LEGACY_BODY}9");
        assert!(detect(&input).is_empty());
    }

    /// Anthropic's `sk-ant-` and `OpenRouter`'s `sk-or-` namespaces are never
    /// claimed: their own namespace dash sits well inside the first 48
    /// bytes, so the alphanumeric-only run never reaches the required
    /// length. No reject list is needed.
    #[test]
    fn anthropic_and_openrouter_lookalike_prefixes_are_not_claimed() {
        for prefix in ["sk-ant-", "sk-or-v1-"] {
            let input = format!("{prefix}{}", "A".repeat(60));
            assert!(detect(&input).is_empty(), "{prefix}");
        }
    }

    #[test]
    fn a_bare_vendor_prefixed_value_is_detected_quoted_and_across_unicode_crlf() {
        let value = format!("sk-proj-{VENDOR_PREFIX_PROJ_BODY}");

        let quoted = format!("{{\"value\": \"{value}\"}}");
        let quoted_candidates = detect(&quoted);
        let (start, end) = only_range(&quoted_candidates);
        assert_eq!(&quoted[start..end], value);
        assert_eq!(
            quoted_candidates[0].type_name(),
            "vendor_prefixed_credential"
        );

        let unicode_crlf = format!("# \u{1F511} reviewed format\r\n{value}\n");
        let unicode_candidates = detect(&unicode_crlf);
        let (start, end) = only_range(&unicode_candidates);
        assert_eq!(&unicode_crlf[start..end], value);
        assert_eq!(
            unicode_candidates[0].type_name(),
            "vendor_prefixed_credential"
        );
    }

    /// The ruleset-names variant must not duplicate the built-in's bare
    /// vendor-prefixed candidates, the same way it does not duplicate
    /// `authorization_candidates`.
    #[test]
    fn the_ruleset_names_detector_does_not_match_bare_vendor_prefixed_values() {
        let input = format!("sk-{VENDOR_PREFIX_LEGACY_BODY}");
        let candidates = detect_with_ruleset_names(&input, &["corp_passphrase"]);
        assert!(candidates.is_empty());
    }

    // --- issue #730 (benchmark gap `product-730`): an OS keychain
    // secret-store reference is excluded like the other secret-manager
    // references.

    #[test]
    fn a_keychain_secret_store_reference_is_excluded() {
        for input in [
            "{\n  \"apiKey\": \"{keychain:fireworks-api-key}\"\n}\n",
            "api_key='{keychain:synthetic.item_name}'",
            "apiKey: {keychain:fireworks-api-key}",
        ] {
            assert!(detect(input).is_empty(), "{input:?}");
        }
    }

    #[test]
    fn a_malformed_or_embedded_keychain_reference_is_still_detected() {
        for input in [
            "\"apiKey\": \"{keychain:}SYNTHETIC0REVOKED\"",
            "\"apiKey\": \"{keychain:a b SYNTHETIC0REVOKED}\"",
            "\"apiKey\": \"{keychain:item}SYNTHETIC0REVOKED\"",
            "\"apiKey\": \"{keychain:vault/item#SYNTHETIC0REVOKED}\"",
            "\"apiKey\": \"{keyring:SYNTHETIC0REVOKED}\"",
        ] {
            assert!(!detect(input).is_empty(), "{input:?}");
        }
    }

    // --- issue #264 (benchmark gap `product-264`): a partially masked
    // console display (visible head, a mask run, visible tail) is excluded.

    #[test]
    fn a_partially_masked_console_display_is_excluded() {
        let groq = format!("Secret: gsk_{}Tn4q    Created: 2026-09-01", "*".repeat(48));
        let xai = format!("password: xai-AbCd{}WxYz", "*".repeat(72));
        let bullets = format!("secret: sk-{}Ab12", "\u{2022}".repeat(8));
        for input in [
            groq.as_str(),
            xai.as_str(),
            bullets.as_str(),
            "api_key=ab****cd",
        ] {
            assert!(detect(input).is_empty(), "{input:?}");
        }
    }

    #[test]
    fn values_near_a_partially_masked_display_are_still_detected() {
        for input in [
            // Only one visible side: the #264 near-miss stays in scope.
            "Password: ********x".to_owned(),
            "Password: x********".to_owned(),
            // A mask run shorter than MIN_MASK_RUN.
            "secret: SYNTHETIC***REVOKED".to_owned(),
            // More visible characters than mask.
            "secret: SYNTHETIC0R****EVOKED0VALUE".to_owned(),
            // A visible side longer than MAX_MASK_VISIBLE_SIDE.
            format!("secret: SYNTHETIC0REVOKED0{}Tn4q", "*".repeat(64)),
            // Two mask runs, or a mixed run.
            format!("secret: gsk_{}Tn{}4q", "*".repeat(20), "*".repeat(20)),
            format!(
                "secret: gsk_{}{}Tn4q",
                "*".repeat(20),
                "\u{2022}".repeat(20)
            ),
            // A byte outside the visible alphabet.
            format!("secret: gsk+{}Tn4q", "*".repeat(48)),
        ] {
            assert!(!detect(&input).is_empty(), "{input:?}");
        }
    }

    // --- issue #727 (benchmark gap `product-727`): a colon-namespaced
    // scope identifier glued to a credential-like name is one token.

    #[test]
    fn a_colon_namespaced_acl_scope_is_not_an_assignment() {
        for input in [
            "{\n  \"acls\": [\"api-key:endpoint:chat\", \"api-key:model:*\"]\n}\n",
            "scopes: api_key:models:read-write",
            "secret:rotate:all_regions",
        ] {
            assert!(detect(input).is_empty(), "{input:?}");
        }
    }

    #[test]
    fn a_credential_assignment_near_a_scope_identifier_is_still_detected() {
        for input in [
            // A space after the colon is a real mapping.
            "api_key: endpoint:chatSYNTHETIC",
            "api-key: endpoint:chat",
            // A single-segment value glued to the name (a curl header).
            "Api-Key:SYNTHETIC0REVOKED0VALUE",
            // An `=` operator, a quoted name, or a non-scope segment.
            "api_key=endpoint:chat",
            "\"api_key\":\"endpoint:chat\"",
            "api_key:endpoint:SYNTHETIC0REVOKED",
            "api_key:endpoint:0synthetic",
        ] {
            assert!(!detect(input).is_empty(), "{input:?}");
        }
    }

    fn npmrc_spans(input: &str) -> Vec<(usize, usize)> {
        npmrc_credential_candidates(input)
            .iter()
            .map(|candidate| {
                assert_eq!(candidate.confidence(), Confidence::High);
                (candidate.range().start(), candidate.range().end())
            })
            .collect()
    }

    #[test]
    fn npmrc_credential_keys_report_their_value() {
        let value = "Synthetic0Revoked1Registry2Token3";
        for input in [
            format!("//registry.npmjs.org/:_authToken={value}\n"),
            format!("//npm.example.invalid/repo/npm/:_auth = \"{value}\"\n"),
            format!("//npm.example.invalid/:_password={value}"),
            format!("_authToken={value}\n"),
            format!("  _auth={value}\r\n"),
        ] {
            let start = input.find(value).unwrap();
            assert_eq!(
                npmrc_spans(&input),
                vec![(start, start + value.len())],
                "{input}"
            );
        }
    }

    #[test]
    fn npmrc_references_placeholders_and_other_keys_stay_silent() {
        for input in [
            "//registry.npmjs.org/:_authToken=${NPM_TOKEN}\n",
            "//registry.npmjs.org/:_authToken=<your-token>\n",
            "//registry.npmjs.org/:_authToken=\n",
            "//registry.npmjs.org/:username=synthetic-user\n",
            "//registry.npmjs.org/:email=someone@example.invalid\n",
            "registry=https://registry.npmjs.org/\n",
            "the _authToken=Synthetic0Revoked1Registry2Token3 in prose\n",
            "x:_authToken=Synthetic0Revoked1Registry2Token3\n",
            "//registry.npmjs.org/:_authorization=Synthetic0Revoked1Registry2Token3\n",
            "//registry.npmjs.org/:_authToken=short\n",
        ] {
            assert!(npmrc_spans(input).is_empty(), "{input}");
        }
    }
}
