//! The contextual evidence class of one candidate (issue #770).
//!
//! The benchmark calibration (redact-secret-benchmarks#255) fitted the
//! `contextual` group against five context classes that its candidate-feature
//! dataset derives from the text around a span
//! (`docs/specs/candidate-features.md`, "Contextual evidence class"). The core
//! does not re-parse the surrounding text for this: a detector has already
//! parsed it, and records what it found as internal signal labels on the
//! [`Candidate`]. [`context_class_of`] maps those labels onto the benchmark's
//! classes. `docs/specs/engine.md` ("Shadow evidence aggregation") documents
//! the mapping and where it diverges from the benchmark.
//!
//! The class is a closed enum. It carries no part of the candidate value or
//! of the name, header or URL around it.

use crate::types::{Candidate, Specificity};

/// Where a candidate sits, as far as credential-bearing syntax goes. The
/// variants and their names follow the benchmark's `contextClass`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) enum ContextClass {
    /// The password of a `scheme://user:password@` URL.
    UrlUserinfo,
    /// The credential of an `Authorization` header or a bare `Bearer`/
    /// `Basic` scheme.
    AuthorizationHeader,
    /// The value of an assignment whose name is credential-bearing.
    CredentialName,
    /// The value of an assignment whose name is not credential-bearing. No
    /// built-in detector emits a candidate for such a name today, so the core
    /// never produces this class; it exists so the benchmark's vocabulary is
    /// complete and a later detector can use it.
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "no built-in detector emits a non-credential assignment"
        )
    )]
    OtherName,
    /// None of the above.
    Bare,
}

impl ContextClass {
    /// The benchmark's name for the class.
    #[must_use]
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::UrlUserinfo => "url-userinfo",
            Self::AuthorizationHeader => "authorization-header",
            Self::CredentialName => "credential-name",
            Self::OtherName => "other-name",
            Self::Bare => "bare",
        }
    }
}

/// `generic-token`'s contextual assignment candidates (`contextual_secret`)
/// carry one of these when the assignment name is in its credential-bearing
/// vocabulary (built-in high-signal or ambiguous names, or a ruleset's
/// declared names).
pub(crate) const CREDENTIAL_NAME_SIGNALS: [&str; 2] = ["high-signal-name", "ambiguous-name"];

/// Maps a candidate's detector evidence onto a [`ContextClass`].
///
/// The match is on the pair of the candidate's type and one of its signals,
/// so a signal label alone, from a detector that uses the same word for
/// something else, never selects a credential-bearing class:
///
/// | Type | Signal | Class |
/// | --- | --- | --- |
/// | `connection_string_password` | `credential-bearing-authority` | `url-userinfo` |
/// | `authorization_credential` | `authorization-<scheme>-scheme` | `authorization-header` |
/// | `bearer_token` | `bearer-scheme` | `authorization-header` |
/// | `contextual_secret` (specificity `contextual`) | `high-signal-name` or `ambiguous-name` | `credential-name` |
/// | anything else | | `bare` |
#[must_use]
pub(crate) fn context_class_of(candidate: &Candidate) -> ContextClass {
    let has = |wanted: &dyn Fn(&str) -> bool| candidate.signals().iter().any(|s| wanted(s));
    match candidate.type_name() {
        "connection_string_password" if has(&|s| s == "credential-bearing-authority") => {
            ContextClass::UrlUserinfo
        }
        "authorization_credential"
            if has(&|s| s.starts_with("authorization-") && s.ends_with("-scheme")) =>
        {
            ContextClass::AuthorizationHeader
        }
        "bearer_token" if has(&|s| s == "bearer-scheme") => ContextClass::AuthorizationHeader,
        "contextual_secret"
            if candidate.specificity() == Some(Specificity::Contextual)
                && has(&|s| CREDENTIAL_NAME_SIGNALS.contains(&s)) =>
        {
            ContextClass::CredentialName
        }
        _ => ContextClass::Bare,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detectors::built_in_detectors;
    use crate::types::{ByteRange, Confidence, DetectorContext};

    /// Runs every built-in detector over `input` and returns the context
    /// class of each candidate of `type_name`.
    fn classes_of(input: &str, type_name: &str) -> Vec<ContextClass> {
        let context = DetectorContext::new(input.len());
        built_in_detectors()
            .iter()
            .flat_map(|detector| detector.detect(input, &context).unwrap())
            .filter(|candidate| candidate.type_name() == type_name)
            .map(|candidate| context_class_of(&candidate))
            .collect()
    }

    // The fixtures below are synthetic. They tie the mapping to what the
    // real detectors emit, so renaming a signal breaks this test rather than
    // silently turning a class into `bare`.

    #[test]
    fn credential_bearing_assignments_are_credential_name() {
        for input in [
            "API_KEY=Q7vK2mZp9LxR4tWb8NcY3hJd",
            "password: \"Zp9LxR4tWb8NcY3h\"",
            "auth_token = Wb8NcY3hJd6FsG1eUaQ7vK2m",
        ] {
            assert_eq!(
                classes_of(input, "contextual_secret"),
                [ContextClass::CredentialName],
                "{input}"
            );
        }
    }

    #[test]
    fn authorization_and_bearer_schemes_are_authorization_header() {
        assert_eq!(
            classes_of(
                "Authorization: Basic ZmFrZXVzZXI6ZmFrZXBhc3N3b3Jk",
                "authorization_credential"
            ),
            [ContextClass::AuthorizationHeader]
        );
        assert_eq!(
            classes_of(
                "Authorization: Bearer Q7vK2mZp9LxR4tWb8NcY3hJd6FsG1eUa",
                "bearer_token"
            ),
            [ContextClass::AuthorizationHeader]
        );
    }

    #[test]
    fn connection_url_passwords_are_url_userinfo() {
        assert_eq!(
            classes_of(
                "postgres://fakeuser:Zp9LxR4tWb8NcY3h@db.example.invalid:5432/app",
                "connection_string_password"
            ),
            [ContextClass::UrlUserinfo]
        );
    }

    #[test]
    fn a_signal_without_its_type_or_a_foreign_type_is_bare() {
        let range = ByteRange::new(0, 8).unwrap();
        let foreign = Candidate::new("acme-internal-token", Confidence::Medium, range)
            .with_specificity(Specificity::Contextual)
            .with_signals(["high-signal-name", "credential-bearing-authority"]);
        assert_eq!(context_class_of(&foreign), ContextClass::Bare);
        let unsignalled = Candidate::new("contextual_secret", Confidence::Medium, range)
            .with_specificity(Specificity::Contextual);
        assert_eq!(context_class_of(&unsignalled), ContextClass::Bare);
        let vendor = Candidate::new("vendor_prefixed_credential", Confidence::Medium, range)
            .with_specificity(Specificity::Entropy)
            .with_signals(["vendor-prefix-policy"]);
        assert_eq!(context_class_of(&vendor), ContextClass::Bare);
    }

    #[test]
    fn class_names_follow_the_benchmark_vocabulary() {
        let names = [
            ContextClass::UrlUserinfo,
            ContextClass::AuthorizationHeader,
            ContextClass::CredentialName,
            ContextClass::OtherName,
            ContextClass::Bare,
        ]
        .map(ContextClass::as_str);
        assert_eq!(
            names,
            [
                "url-userinfo",
                "authorization-header",
                "credential-name",
                "other-name",
                "bare"
            ]
        );
    }
}
