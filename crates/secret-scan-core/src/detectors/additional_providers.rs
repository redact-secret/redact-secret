//! Stripe, Slack, `PyPI`, Hugging Face, Docker, Cloudflare, `DigitalOcean`,
//! Linear, Supabase, and Vercel token detection.
//!
//! Mirrors `src/detectors/additional-providers.ts`. Every one of these
//! providers reduces to the same shape as [`super::gitlab`] or
//! [`super::anthropic`] — a documented literal prefix set followed by a
//! minimum-length opaque suffix, with a boundary alphabet of
//! `[A-Za-z0-9_-]` — so they share one generic [`Detector`] implementation
//! instead of one bespoke type each.

use crate::detectors::pattern::{self, Alphabet, RunLength};
use crate::error::DetectorFailure;
use crate::types::{ByteRange, Candidate, Confidence, Detector, DetectorContext, Specificity};

/// A detector defined purely by a literal prefix set, a following
/// character-class run, and the resulting finding's metadata.
pub(super) struct KnownFormatProviderDetector {
    id: &'static str,
    type_name: &'static str,
    signals: &'static [&'static str],
    prefixes: &'static [&'static str],
    run: RunLength,
    alphabet: Alphabet,
    boundary: Alphabet,
}

impl Detector for KnownFormatProviderDetector {
    fn id(&self) -> &str {
        self.id
    }

    fn detect(
        &self,
        input: &str,
        _context: &DetectorContext,
    ) -> Result<Vec<Candidate>, DetectorFailure> {
        let mut candidates = Vec::new();
        for (start, end) in pattern::scan_prefixed_runs(
            input,
            self.prefixes,
            self.run,
            self.alphabet,
            self.boundary,
        ) {
            let Some(range) = ByteRange::new(start, end) else {
                continue;
            };
            candidates.push(
                Candidate::new(self.type_name, Confidence::High, range)
                    .with_specificity(Specificity::Provider)
                    .with_signals(self.signals.iter().copied()),
            );
        }
        Ok(candidates)
    }
}

/// Stripe secret, restricted, organization, and webhook-signing
/// credentials. The suffix alphabet is `[A-Za-z0-9]` — narrower than the
/// `[A-Za-z0-9_-]` boundary — so a trailing `_` or `-` still rejects a
/// truncated candidate. The publishable-key prefix (`pk_live_`,
/// `pk_test_`) is deliberately excluded: it names a public identifier, not
/// a secret, so treating it as a match would be a false positive. Newer or
/// undocumented prefixes are false negatives until added.
pub(super) const STRIPE: KnownFormatProviderDetector = KnownFormatProviderDetector {
    id: "stripe-token",
    type_name: "stripe_credential",
    signals: &["stripe-documented-prefix", "opaque-suffix"],
    prefixes: &[
        "sk_test_", "sk_live_", "rk_test_", "rk_live_", "sk_org_", "whsec_",
    ],
    run: RunLength::AtLeast(20),
    alphabet: pattern::is_alnum,
    boundary: pattern::is_alnum_dash,
};

/// Current Slack bot, user, app, workflow, rotating, and refresh tokens.
/// Every documented prefix requires its trailing `-`; a prefix missing that
/// delimiter, or any undocumented prefix, is an intentional false negative
/// rather than a fuzzy match.
pub(super) const SLACK: KnownFormatProviderDetector = KnownFormatProviderDetector {
    id: "slack-token",
    type_name: "slack_token",
    signals: &["slack-documented-prefix", "opaque-suffix"],
    prefixes: &[
        "xoxb-",
        "xoxp-",
        "xapp-",
        "xwfp-",
        "xoxe-",
        "xoxe.xoxb-",
        "xoxe.xoxp-",
    ],
    run: RunLength::AtLeast(20),
    alphabet: pattern::is_alnum_dash,
    boundary: pattern::is_alnum_dash,
};

/// `PyPI`'s documented Macaroon serialization with its exact minimum
/// suffix. The prefix is matched case-sensitively (lowercase `pypi-`
/// only) and the 85-byte minimum favors precision: a shorter or
/// differently-cased example is an intentional false negative rather than
/// a loosened match.
pub(super) const PYPI: KnownFormatProviderDetector = KnownFormatProviderDetector {
    id: "pypi-token",
    type_name: "pypi_api_token",
    signals: &["pypi-documented-prefix", "macaroon-minimum-length"],
    prefixes: &["pypi-"],
    run: RunLength::AtLeast(85),
    alphabet: pattern::is_alnum_dash,
    boundary: pattern::is_alnum_dash,
};

/// Hugging Face user access tokens in the provider's `hf_` namespace. A
/// dash in place of the documented underscore, or any other undocumented
/// prefix, is an intentional false negative.
pub(super) const HUGGING_FACE: KnownFormatProviderDetector = KnownFormatProviderDetector {
    id: "huggingface-token",
    type_name: "huggingface_token",
    signals: &["huggingface-documented-prefix", "opaque-suffix"],
    prefixes: &["hf_"],
    run: RunLength::AtLeast(20),
    alphabet: pattern::is_alnum_dash,
    boundary: pattern::is_alnum_dash,
};

/// Docker Hub personal and organization access tokens. Only the two
/// documented `_pat_`/`_oat_` segment names are matched; an undocumented
/// segment name is an intentional false negative, and legacy Docker Hub
/// passwords (which carry no distinguishing prefix at all) are out of
/// scope for this detector.
pub(super) const DOCKER: KnownFormatProviderDetector = KnownFormatProviderDetector {
    id: "docker-token",
    type_name: "docker_token",
    signals: &["docker-documented-prefix", "opaque-suffix"],
    prefixes: &["dckr_pat_", "dckr_oat_"],
    run: RunLength::AtLeast(20),
    alphabet: pattern::is_alnum_dash,
    boundary: pattern::is_alnum_dash,
};

/// Cloudflare's current scannable user and account API-token namespace. A
/// truncated or misspelled prefix is deliberately excluded, and the
/// legacy unprefixed Global API Key format is a known false negative this
/// detector does not attempt, since it is indistinguishable from ordinary
/// opaque hex without a prefix to anchor on.
pub(super) const CLOUDFLARE: KnownFormatProviderDetector = KnownFormatProviderDetector {
    id: "cloudflare-token",
    type_name: "cloudflare_api_token",
    signals: &["cloudflare-scannable-prefix", "opaque-suffix"],
    prefixes: &["cfut_"],
    run: RunLength::AtLeast(20),
    alphabet: pattern::is_alnum_dash,
    boundary: pattern::is_alnum_dash,
};

/// `DigitalOcean` personal, `OAuth` access, and `OAuth` refresh token
/// families. Only the documented `v1` namespace is matched; a future
/// version bump (`dop_v2_` and siblings) is an intentional false negative
/// until that shape is confirmed and added.
pub(super) const DIGITALOCEAN: KnownFormatProviderDetector = KnownFormatProviderDetector {
    id: "digitalocean-token",
    type_name: "digitalocean_token",
    signals: &["digitalocean-documented-prefix", "versioned-opaque-suffix"],
    prefixes: &["dop_v1_", "doo_v1_", "dor_v1_"],
    run: RunLength::AtLeast(20),
    alphabet: pattern::is_alnum_dash,
    boundary: pattern::is_alnum_dash,
};

/// Linear API keys and OAuth access tokens with scanner-oriented prefixes.
/// An undocumented segment name in place of `api`/`oauth` is an
/// intentional false negative.
pub(super) const LINEAR: KnownFormatProviderDetector = KnownFormatProviderDetector {
    id: "linear-token",
    type_name: "linear_token",
    signals: &["linear-scannable-prefix", "opaque-suffix"],
    prefixes: &["lin_api_", "lin_oauth_"],
    run: RunLength::AtLeast(20),
    alphabet: pattern::is_alnum_dash,
    boundary: pattern::is_alnum_dash,
};

/// Supabase elevated-access secret keys. The `sb_publishable_` prefix is
/// deliberately excluded — it names a public identifier, not a secret —
/// so classifying it would be a false positive; an undocumented prefix is
/// a false negative.
pub(super) const SUPABASE: KnownFormatProviderDetector = KnownFormatProviderDetector {
    id: "supabase-token",
    type_name: "supabase_secret_key",
    signals: &["supabase-secret-prefix", "elevated-access-key"],
    prefixes: &["sb_secret_"],
    run: RunLength::AtLeast(20),
    alphabet: pattern::is_alnum_dash,
    boundary: pattern::is_alnum_dash,
};

/// Vercel personal, integration, app, refresh, and API-key credentials. An
/// undocumented prefix letter is an intentional false negative.
pub(super) const VERCEL: KnownFormatProviderDetector = KnownFormatProviderDetector {
    id: "vercel-token",
    type_name: "vercel_token",
    signals: &["vercel-documented-prefix", "opaque-suffix"],
    prefixes: &["vcp_", "vci_", "vca_", "vcr_", "vck_"],
    run: RunLength::AtLeast(20),
    alphabet: pattern::is_alnum_dash,
    boundary: pattern::is_alnum_dash,
};

/// npm access tokens. Granular, automation, and legacy read-only tokens all
/// share the same `npm_`-prefixed shape: a fixed 36-byte base62
/// (`[A-Za-z0-9]`) body, the last six bytes of which encode a base62-encoded
/// CRC32 checksum. The suffix is matched as an exact length, not a minimum —
/// a prefix with the token truncated below 36 bytes, or with the `npm_`
/// prefix stripped entirely, is an intentional false negative; the fixed
/// prefix, alphabet, and length keep false-positive risk low.
pub(super) const NPM: KnownFormatProviderDetector = KnownFormatProviderDetector {
    id: "npm-token",
    type_name: "npm_access_token",
    signals: &["npm-documented-prefix", "base62-exact-length"],
    prefixes: &["npm_"],
    run: RunLength::Exact(36),
    alphabet: pattern::is_alnum,
    boundary: pattern::is_alnum_dash,
};

#[cfg(test)]
mod tests {
    use super::*;

    const BODY: &str = "SYNTHETICREVOKEDPROVIDERVALUE";
    /// npm's suffix is matched as an exact 36-byte length, not a minimum, so
    /// it needs its own fixed-length synthetic body rather than [`BODY`].
    const NPM_BODY: &str = "SYNTHETICREVOKEDNPMACCESSTOKENVALUE1";

    fn detect(detector: &KnownFormatProviderDetector, input: &str) -> Vec<Candidate> {
        detector
            .detect(input, &DetectorContext::new(input.len()))
            .unwrap()
    }

    struct Family {
        detector: KnownFormatProviderDetector,
        value: String,
        short: &'static str,
    }

    fn families() -> Vec<Family> {
        vec![
            Family {
                detector: STRIPE,
                value: format!("sk_live_{BODY}"),
                short: "sk_live_SYNTHETICSHORT",
            },
            Family {
                detector: SLACK,
                value: format!("xoxb-{BODY}"),
                short: "xoxb-SYNTHETICSHORT",
            },
            Family {
                detector: PYPI,
                value: format!("pypi-{}", "SYNTHETIC_REVOKED_".repeat(5)),
                short: "pypi-SYNTHETICSHORT",
            },
            Family {
                detector: HUGGING_FACE,
                value: format!("hf_{BODY}"),
                short: "hf_SYNTHETIC_SHORT",
            },
            Family {
                detector: DOCKER,
                value: format!("dckr_pat_{BODY}"),
                short: "dckr_pat_SYNTHETIC_SHORT",
            },
            Family {
                detector: CLOUDFLARE,
                value: format!("cfut_{BODY}"),
                short: "cfut_SYNTHETIC_SHORT",
            },
            Family {
                detector: DIGITALOCEAN,
                value: format!("dop_v1_{BODY}"),
                short: "dop_v1_SYNTHETIC_SHORT",
            },
            Family {
                detector: LINEAR,
                value: format!("lin_api_{BODY}"),
                short: "lin_api_SYNTHETIC_SHORT",
            },
            Family {
                detector: SUPABASE,
                value: format!("sb_secret_{BODY}"),
                short: "sb_secret_SYNTHETIC_SHORT",
            },
            Family {
                detector: VERCEL,
                value: format!("vcp_{BODY}"),
                short: "vcp_SYNTHETIC_SHORT",
            },
            Family {
                detector: NPM,
                value: format!("npm_{NPM_BODY}"),
                short: "npm_SYNTHETICSHORT",
            },
        ]
    }

    #[test]
    fn detects_a_synthetic_credential_with_provider_specificity() {
        for family in families() {
            let candidates = detect(&family.detector, &family.value);
            assert_eq!(candidates.len(), 1, "{}", family.detector.id());
            assert_eq!(candidates[0].confidence(), Confidence::High);
            assert_eq!(candidates[0].effective_specificity(), Specificity::Provider);
            assert_eq!(
                candidates[0].range(),
                ByteRange::new(0, family.value.len()).unwrap()
            );
        }
    }

    #[test]
    fn rejects_short_invalid_alphabet_and_embedded_lookalikes() {
        for family in families() {
            let embedded = format!("X{}Y", family.value);
            let broken = family.value.replacen("REVOKED", "REVO!KED", 1);
            for input in [family.short, broken.as_str(), embedded.as_str()] {
                assert_eq!(
                    detect(&family.detector, input).len(),
                    0,
                    "{} {input}",
                    family.detector.id()
                );
            }
        }
    }

    #[test]
    fn accepts_punctuation_boundaries() {
        for family in families() {
            let input = format!("({}).", family.value);
            let candidates = detect(&family.detector, &input);
            assert_eq!(candidates.len(), 1, "{}", family.detector.id());
            assert_eq!(
                candidates[0].range(),
                ByteRange::new(1, family.value.len() + 1).unwrap(),
                "{}",
                family.detector.id()
            );
        }
    }

    #[test]
    fn detects_every_documented_prefix_variant() {
        let cases: [(&KnownFormatProviderDetector, &str); 25] = [
            (&STRIPE, "sk_test_"),
            (&STRIPE, "sk_live_"),
            (&STRIPE, "rk_test_"),
            (&STRIPE, "rk_live_"),
            (&STRIPE, "sk_org_"),
            (&STRIPE, "whsec_"),
            (&SLACK, "xoxb-"),
            (&SLACK, "xoxp-"),
            (&SLACK, "xapp-"),
            (&SLACK, "xwfp-"),
            (&SLACK, "xoxe-"),
            (&SLACK, "xoxe.xoxb-"),
            (&SLACK, "xoxe.xoxp-"),
            (&DOCKER, "dckr_pat_"),
            (&DOCKER, "dckr_oat_"),
            (&DIGITALOCEAN, "dop_v1_"),
            (&DIGITALOCEAN, "doo_v1_"),
            (&DIGITALOCEAN, "dor_v1_"),
            (&LINEAR, "lin_api_"),
            (&LINEAR, "lin_oauth_"),
            (&VERCEL, "vcp_"),
            (&VERCEL, "vci_"),
            (&VERCEL, "vca_"),
            (&VERCEL, "vcr_"),
            (&VERCEL, "vck_"),
        ];
        for (detector, prefix) in cases {
            let value = format!("{prefix}{BODY}");
            let candidates = detect(detector, &value);
            assert_eq!(candidates.len(), 1, "{prefix}");
            assert_eq!(
                candidates[0].range(),
                ByteRange::new(0, value.len()).unwrap(),
                "{prefix}"
            );
        }
    }

    #[test]
    fn does_not_classify_neighboring_public_or_identifier_only_formats() {
        for input in [
            format!("pk_live_{BODY}"),
            format!("sb_publishable_{BODY}"),
            format!("SK{}", "0".repeat(32)),
            // An undocumented near-miss prefix (not one byte-for-byte equal to
            // any documented prefix) stays a false-negative-by-design, never a
            // fuzzy match.
            format!("sk_liv_{BODY}"),
            format!("sb_secrets_{BODY}"),
        ] {
            assert_eq!(detect(&STRIPE, &input).len(), 0, "{input}");
            assert_eq!(detect(&SUPABASE, &input).len(), 0, "{input}");
        }
    }

    /// A public-prefix identifier surrounded by punctuation or Unicode/CRLF
    /// context, and a documented secret prefix followed by a redaction mask
    /// or a template interpolation reference instead of a real suffix, must
    /// all stay unclassified.
    #[test]
    fn rejects_masked_interpolated_and_contextualized_near_misses() {
        for input in [
            format!("(pk_live_{BODY})."),
            format!("(sb_publishable_{BODY})."),
            format!("# \u{1F511} caf\u{e9}\r\npk_live_{BODY}\r\n"),
            format!("# \u{1F511} caf\u{e9}\r\nsb_publishable_{BODY}\r\n"),
            "sk_live_********************".to_string(),
            "sb_secret_********************".to_string(),
            "sk_live_${STRIPE_SECRET_KEY}".to_string(),
            "sb_secret_${SUPABASE_SERVICE_ROLE_KEY}".to_string(),
        ] {
            assert_eq!(detect(&STRIPE, &input).len(), 0, "{input}");
            assert_eq!(detect(&SUPABASE, &input).len(), 0, "{input}");
        }
    }

    /// A public identifier and a secret credential on adjacent lines: the
    /// public prefix never generates a candidate, while the paired secret is
    /// still classified with the correct range.
    #[test]
    fn classifies_only_the_secret_half_of_a_mixed_public_and_secret_input() {
        let input = format!("pk_live_SYNTHETICREVOKEDSYNT\nsk_live_{BODY}");
        let candidates = detect(&STRIPE, &input);
        assert_eq!(candidates.len(), 1);
        let expected_start = input.find("sk_live_").unwrap();
        assert_eq!(
            candidates[0].range(),
            ByteRange::new(expected_start, input.len()).unwrap()
        );
    }
}
