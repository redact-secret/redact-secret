//! Name-scoped contextual readers (issues #1228, #1229 and #1230).
//!
//! The contextual vocabulary (`generic_token.rs`) reads a value by the name it
//! is assigned to. A few documented credential fields are named too plainly to
//! join that vocabulary as a name on their own: the bare `token`, which stays
//! unmatched by the accepted rule of
//! `decision-redact-provider-named-credential-assignments` and #1241, and
//! `encoded`. This module reads such a name **only** where the carrier or the
//! surrounding text carries the context the evidence Case names, and judges the
//! value under an existing high-signal name (the alias), so every other rule
//! (the 8-byte floor, the entropy tiers, the placeholder, reference and mask
//! exclusions) applies unchanged. It adds no name to the vocabulary and widens
//! no bare-name rule.
//!
//! | Name | Carrier | Required context | Alias |
//! | --- | --- | --- | --- |
//! | `token_key` | quoted JSON member | none (the quoted member is the carrier) | `access_token` |

/// What a scoped name is judged as, and the extra guard it carries.
pub(super) struct ScopedRead {
    /// The high-signal name the value is judged under.
    pub(super) alias: &'static str,
    /// A value that is itself the name of a credential (`accessToken`,
    /// `auth_token_key`) is a reference, not a value: the scoped name also
    /// names the storage key an application saves a token under.
    pub(super) name_phrase_is_reference: bool,
}

/// `true` when the name at `name_start..name_end` is a quoted JSON member name
/// (`"tokenKey":`, also inside an escaped JSON string, `\"tokenKey\":`).
pub(super) fn is_quoted_member(input: &str, name_start: usize, name_end: usize) -> bool {
    let before = &input[..name_start];
    let after = &input[name_end..];
    before.ends_with('"') && (after.starts_with('"') || after.starts_with("\\\""))
}

/// How the assignment at `name_start..name_end` is read, when `normalized` (the
/// normalized name) is a scoped name whose context is present.
pub(super) fn scoped_alias(
    input: &str,
    name_start: usize,
    name_end: usize,
    normalized: &str,
) -> Option<ScopedRead> {
    match normalized {
        "token_key" if is_quoted_member(input, name_start, name_end) => Some(ScopedRead {
            alias: "access_token",
            name_phrase_is_reference: true,
        }),
        _ => None,
    }
}
