//! Contextual assignment and structural `Basic`/`Token` authorization
//! detector.
//!
//! Combines explicit credential names or authorization syntax with bounded
//! entropy. A plain `token` name and entropy-only text intentionally produce
//! no candidates. Values above 4 KiB are left to more specific detectors.

use super::text::{
    ascii_run_len, char_at, ends_with_ci, is_horizontal_js_whitespace, is_js_whitespace,
    is_line_start, is_repeated_character_filler, matches_placeholder_vocabulary, prev_char,
    rskip_while_chars, skip_while_chars, starts_with_ci,
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
    "aws_session_token",
    "password",
    "passwd",
    "private_key",
    "client_secret",
    "webhook_secret",
];

const AMBIGUOUS_NAMES: &[&str] = &[
    "auth",
    "auth_token",
    "credential",
    "credentials",
    "signing_key",
];

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
/// bytes only.
fn normalize_name(name: &str) -> String {
    let bytes = name.as_bytes();
    let mut out = String::with_capacity(name.len() + 4);
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
    out
}

fn is_open_assignment_boundary_char(ch: char) -> bool {
    is_js_whitespace(ch) || matches!(ch, '{' | ',' | ';')
}

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
pub(crate) fn has_open_contextual_assignment(input: &str) -> bool {
    let mut end = rskip_while_chars(input, input.len(), is_js_whitespace);

    if let Some(ch) = prev_char(input, end)
        && (ch == '=' || ch == ':')
    {
        end -= ch.len_utf8();
        end = rskip_while_chars(input, end, is_js_whitespace);
    }

    if let Some(ch @ ('"' | '\'')) = prev_char(input, end) {
        end -= ch.len_utf8();
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

    let mut boundary_pos = name_start;
    if let Some(ch @ ('"' | '\'')) = prev_char(input, boundary_pos) {
        boundary_pos -= ch.len_utf8();
    }
    let boundary_ok = boundary_pos == 0
        || prev_char(input, boundary_pos).is_some_and(is_open_assignment_boundary_char);
    if !boundary_ok {
        return false;
    }

    let normalized = normalize_name(&input[name_start..name_end]);
    HIGH_SIGNAL_NAMES.contains(&normalized.as_str())
        || AMBIGUOUS_NAMES.contains(&normalized.as_str())
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
}

fn is_boolean_null_or_digits(lower: &str) -> bool {
    matches!(lower, "true" | "false" | "null" | "undefined")
        || (!lower.is_empty() && lower.bytes().all(|byte| byte.is_ascii_digit()))
}

fn starts_with_env_reference(value: &str) -> bool {
    if value.starts_with("${") {
        return true;
    }
    if value.as_bytes().first() == Some(&b'$')
        && let Some(second) = char_at(value, 1)
        && (second.is_ascii_alphabetic() || second == '_')
    {
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

/// `true` when the whole value is delimited by `{{` and `}}`
/// (`^\{\{.*\}\}$`) — the idiomatic Jinja/Helm/Go-template reference syntax
/// Ansible, Helm, Salt, and Go templates use for a vaulted or injected
/// value (`{{ vault_db_password }}`, `{{ .Values.postgresql.auth.password }}`).
/// A value that only starts with `{{`, or that carries `{{...}}` inside a
/// larger string, does not satisfy this and stays detected: only a value
/// fully bounded by the delimiters is a bare reference rather than
/// suspicious content the delimiters happen to appear in.
fn is_template_reference(value: &str) -> bool {
    value.starts_with("{{") && value.ends_with("}}") && value.len() >= 4
}

// --- interpolation / command-substitution reference exclusions
// (issue #279) -----------------------------------------------------------
//
// Each of these is, like `is_template_reference`, a syntax that is only a
// bare reference when it delimits the *whole* value -- a value that merely
// starts with the opener, or that carries the pair embedded inside a larger
// string, stays detected. `docs/decisions/2026-09-16-exclude-interpolation-command-substitution-references.md`
// records the supported syntaxes and the accompanying span-scanning fix
// (`delimited_reference_value`) that lets the whole-value check see past a
// closing `)`/`]`/backtick that a plain unquoted-value boundary scan would
// otherwise cut short before.

/// `true` when `value` is exactly `open` followed by anything followed by
/// `close` -- the same whole-value shape `is_template_reference` checks for
/// `{{`/`}}`, generalized to an arbitrary delimiter pair.
fn is_fully_delimited(value: &str, open: &str, close: &str) -> bool {
    value.starts_with(open) && value.ends_with(close) && value.len() >= open.len() + close.len()
}

/// `true` for a POSIX/shell, `Makefile`, or Kustomize variable or
/// command-substitution reference (`$(registryPassword)`,
/// `$(pass show db/prod)`): the value names a variable or command to
/// resolve at runtime, not a secret.
fn is_command_substitution_reference(value: &str) -> bool {
    is_fully_delimited(value, "$(", ")")
}

/// `true` for an Azure Pipelines runtime-expression reference
/// (`$[variables.x]`).
fn is_runtime_expression_reference(value: &str) -> bool {
    is_fully_delimited(value, "$[", "]")
}

/// `true` for a Ruby string-interpolation reference
/// (`#{ENV['DB_PASSWORD']}`).
fn is_ruby_interpolation_reference(value: &str) -> bool {
    is_fully_delimited(value, "#{", "}")
}

/// opencode config substitution kinds resolved from the environment or a
/// file at load time rather than containing a secret directly.
const OPENCODE_REFERENCE_KINDS: &[&str] = &["env", "file"];

/// `true` for an opencode `{env:VAR}` or `{file:path}` substitution.
fn is_opencode_reference(value: &str) -> bool {
    OPENCODE_REFERENCE_KINDS.iter().any(|kind| {
        let open = format!("{{{kind}:");
        is_fully_delimited(value, &open, "}")
    })
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
// `docs/decisions/2026-09-16-exclude-secret-manager-references.md` records
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

fn is_env_var_identifier(value: &str) -> bool {
    let mut chars = value.chars();
    match chars.next() {
        Some(first) if first.is_ascii_alphabetic() || first == '_' => {}
        _ => return false,
    }
    chars.all(|ch| ch.is_ascii_alphanumeric() || ch == '_')
}

// --- cmd-style Windows env reference and SQL bind parameter exclusions
// (issue #292) ------------------------------------------------------------
//
// `docs/decisions/2026-09-16-exclude-interpolation-command-substitution-references.md`
// deferred these two syntaxes so each got its own explicit fixture coverage.
// Both share `is_env_var_identifier`'s identifier shape rather than
// `is_template_reference`'s "anything between the delimiters" rule: `%` and
// `:` are common enough punctuation (a percentage-bounded range, a URL port,
// a prose colon) that a bare delimiter-pair check would exclude values that
// merely start and end with one, so the *content* must itself look like an
// identifier.

/// `true` for a cmd.exe/batch-style Windows environment-variable reference
/// (`%DB_PASSWORD%`): the whole value is `%` + an identifier + `%`, expanded
/// by the shell at runtime rather than a secret. A value missing either `%`
/// delimiter, or one that carries the pair embedded inside a larger value,
/// does not satisfy this and stays detected — the same whole-value
/// requirement as `is_template_reference`.
fn is_windows_env_reference(value: &str) -> bool {
    value
        .strip_prefix('%')
        .and_then(|rest| rest.strip_suffix('%'))
        .is_some_and(is_env_var_identifier)
}

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

fn is_secret_manager_reference(value: &str) -> bool {
    is_onepassword_reference(value)
        || is_litellm_env_reference(value)
        || is_gcp_secret_manager_reference(value)
        || is_vals_reference(value)
        || is_bank_vaults_reference(value)
        || is_aws_secretsmanager_arn(value)
        || is_azure_keyvault_reference(value)
}

/// A small, explicit set of source-code roots whose member-access syntax is
/// unambiguous as soon as it opens: a Django/Rails/NestJS `settings`/`config`
/// object, JS/Python/Ruby `self`/`this` instance access, or a Terraform
/// `var`/`local`/`data` lookup. Anchored at the start of the value with a
/// required `.` immediately after the root, so `self` does not also match an
/// unrelated identifier like `selfhosted`.
const CODE_REFERENCE_ROOTS: &[&str] = &[
    "settings", "config", "cfg", "options", "self", "this", "var", "local", "data",
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
fn contains_generic_or_subscript_syntax(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.iter().enumerate().any(|(index, &byte)| {
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
        || is_boolean_null_or_digits(&lower)
        || starts_with_env_reference(value)
        || starts_with_path_like(value)
        || ends_with_key_or_pem(value)
        || is_template_reference(value)
        || is_interpolation_reference(value)
        || is_secret_manager_reference(value)
        || is_repeated_character_filler(value)
        || is_source_code_expression(value, form)
        || is_windows_env_reference(value)
        || is_sql_bind_parameter(value)
}

// --- confidence -----------------------------------------------------------

fn assignment_confidence(name: &str, value: &str, form: ValueForm) -> Option<Confidence> {
    if value.len() < MIN_CONTEXT_VALUE_LENGTH
        || value.len() > MAX_CONTEXT_VALUE_LENGTH
        || is_non_secret_reference(value, form)
    {
        return None;
    }

    let entropy = crate::shannon_entropy(value);
    if HIGH_SIGNAL_NAMES.contains(&name) {
        return Some(
            if value.len() >= MIN_HIGH_ENTROPY_LENGTH && entropy >= HIGH_ENTROPY_THRESHOLD {
                Confidence::High
            } else {
                Confidence::Medium
            },
        );
    }

    if AMBIGUOUS_NAMES.contains(&name)
        && value.len() >= MIN_HIGH_ENTROPY_LENGTH
        && entropy >= AMBIGUOUS_ENTROPY_THRESHOLD
    {
        return Some(Confidence::Medium);
    }

    None
}

// --- assignment value spans ------------------------------------------------

/// A quote character (`"`/`'`) is a valid trailing boundary alongside the
/// existing whitespace/structural set: when a quoted value's own closing
/// quote is immediately followed by another quote rather than whitespace or
/// a structural character, that adjacent quote is closing an *enclosing*
/// quoted context with no separator of its own (`value="api_key="TOKEN""`,
/// issue #294) rather than continuing the same value. `is_unquoted_value_boundary`
/// already treats a bare quote as ending an unquoted value on the same
/// reasoning.
fn is_quoted_value_boundary(ch: Option<char>) -> bool {
    match ch {
        None => true,
        Some(c) => matches!(
            c,
            ' ' | '\t' | '\u{0B}' | '\u{0C}' | '\r' | '\n' | ',' | ';' | '}' | ']' | '"' | '\''
        ),
    }
}

fn is_unquoted_value_boundary(ch: Option<char>) -> bool {
    match ch {
        None => true,
        Some(c) => matches!(
            c,
            ' ' | '\t' | '\u{0B}' | '\u{0C}' | '\r' | '\n' | ',' | ';' | '}' | ']' | '"' | '\''
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
    OPENCODE_REFERENCE_KINDS
        .iter()
        .any(|kind| input[start..].starts_with(&format!("{{{kind}:")))
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
    while let Some(ch) = char_at(input, cursor) {
        if is_unquoted_value_boundary(Some(ch)) {
            break;
        }
        cursor += ch.len_utf8();
        if cursor - start > MAX_CONTEXT_VALUE_LENGTH {
            return None;
        }
    }
    (cursor > start).then_some((start, cursor))
}

fn assignment_value(input: &str, start: usize) -> Option<(usize, usize, ValueForm)> {
    match char_at(input, start) {
        Some('"' | '\'') => quoted_assignment_value(input, start)
            .map(|(value_start, value_end)| (value_start, value_end, ValueForm::Quoted)),
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
fn is_prefix_boundary_char(ch: char) -> bool {
    is_js_whitespace(ch) || matches!(ch, '{' | ',' | ';' | '"' | '\'')
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
/// `docs/decisions/2026-09-15-contextual-assignment-stops-at-the-line.md`.
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
    }
    cursor = skip_while_chars(input, cursor, is_js_whitespace);
    match char_at(input, cursor) {
        Some('=' | ':') => cursor += 1,
        _ => return None,
    }
    cursor = skip_while_chars(input, cursor, is_horizontal_js_whitespace);

    Some((name_start, name_end, cursor))
}

/// Tries the `(?:^|[\s{,;])` prefix alternative at `pos` (line start first,
/// per regex alternation order) followed by the rest of the pattern.
fn try_match_assignment_prefix(input: &str, pos: usize) -> Option<(usize, usize, usize)> {
    if is_line_start(input, pos)
        && let Some(m) = parse_name_and_operator(input, pos)
    {
        return Some(m);
    }
    let ch = char_at(input, pos)?;
    if is_prefix_boundary_char(ch) {
        return parse_name_and_operator(input, pos + ch.len_utf8());
    }
    None
}

fn assignment_candidates(input: &str) -> Vec<Candidate> {
    let mut candidates = Vec::new();
    let mut cursor = 0usize;

    while cursor < input.len() {
        let Some((name_start, name_end, prefix_end)) = try_match_assignment_prefix(input, cursor)
        else {
            cursor += char_at(input, cursor).map_or(1, char::len_utf8);
            continue;
        };

        if let Some((value_start, value_end, form)) = assignment_value(input, prefix_end) {
            let value = &input[value_start..value_end];
            let normalized = normalize_name(&input[name_start..name_end]);
            if let Some(confidence) = assignment_confidence(&normalized, value, form)
                && let Some(range) = ByteRange::new(value_start, value_end)
            {
                let name_signal = if HIGH_SIGNAL_NAMES.contains(&normalized.as_str()) {
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

        cursor = prefix_end;
    }

    candidates
}

// --- `AUTHORIZATION_PATTERN`: (?:^|[\r\n])[ \t]*authorization[ \t]*:[ \t]*(basic|token)[ \t]+([A-Za-z0-9+/=_-]{12,}) ---

fn is_space_or_tab_byte(byte: u8) -> bool {
    byte == b' ' || byte == b'\t'
}

fn is_authorization_value_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/' | b'=' | b'_' | b'-')
}

struct AuthorizationMatch {
    scheme: &'static str,
    value_start: usize,
    value_end: usize,
}

fn parse_authorization_from(input: &str, start: usize) -> Option<AuthorizationMatch> {
    let bytes = input.as_bytes();
    let mut cursor = start + ascii_run_len(bytes, start, is_space_or_tab_byte);
    if !starts_with_ci(input, cursor, "authorization") {
        return None;
    }
    cursor += "authorization".len();
    cursor += ascii_run_len(bytes, cursor, is_space_or_tab_byte);
    if bytes.get(cursor) != Some(&b':') {
        return None;
    }
    cursor += 1;
    cursor += ascii_run_len(bytes, cursor, is_space_or_tab_byte);

    let scheme = if starts_with_ci(input, cursor, "basic") {
        cursor += "basic".len();
        "basic"
    } else if starts_with_ci(input, cursor, "token") {
        cursor += "token".len();
        "token"
    } else {
        return None;
    };

    let ws_len = ascii_run_len(bytes, cursor, is_space_or_tab_byte);
    if ws_len == 0 {
        return None;
    }
    let value_start = cursor + ws_len;
    let value_len = ascii_run_len(bytes, value_start, is_authorization_value_byte);
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

struct GenericTokenDetector;

impl Detector for GenericTokenDetector {
    fn id(&self) -> &'static str {
        "generic-token"
    }

    fn detect(
        &self,
        input: &str,
        _context: &DetectorContext,
    ) -> Result<Vec<Candidate>, DetectorFailure> {
        let mut candidates = assignment_candidates(input);
        candidates.extend(authorization_candidates(input));
        Ok(candidates)
    }
}

/// The contextual assignment and `Basic`/`Token` authorization detector.
#[must_use]
pub fn generic_token_detector() -> Box<dyn Detector> {
    Box::new(GenericTokenDetector)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn detect(input: &str) -> Vec<Candidate> {
        GenericTokenDetector
            .detect(input, &DetectorContext::new(input.len()))
            .unwrap()
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

    #[test]
    fn high_signal_assignment_with_bounded_entropy_is_high_confidence() {
        let input = "api_key=SYNTHETIC_REVOKED_CONTEXT_VALUE";
        let candidates = detect(input);
        assert_eq!(only_range(&candidates), (8, input.len()));
        assert_eq!(candidates[0].confidence(), Confidence::High);
        assert_eq!(candidates[0].specificity(), Some(Specificity::Contextual));
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
    // out of issue #279 (`docs/decisions/2026-09-16-exclude-interpolation-command-substitution-references.md`)
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
            "line one\napi_key:",
            "AWS_SECRET_ACCESS_KEY=",
            "auth",
            "credential:",
        ] {
            assert!(has_open_contextual_assignment(open), "{open:?}");
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
}
