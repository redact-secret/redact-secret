//! Stripe, `PyPI`, Hugging Face, Docker, `DigitalOcean`, Supabase, Vercel,
//! npm, Google, and Grafana Cloud API key detection.
//!
//! Mirrors the retired `src/detectors/additional-providers.ts` oracle. Every
//! one of these providers reduces to the same shape as [`super::gitlab`] or
//! [`super::anthropic`] — a documented literal prefix set, each prefix
//! followed by a fixed- or minimum-length run of a documented alphabet,
//! with a boundary alphabet of `[A-Za-z0-9_-]` — so they share one generic
//! [`Detector`] implementation instead of one bespoke type each. Prefixes of
//! one provider may carry different lengths (Docker Hub's `dckr_pat_` and
//! `dckr_oat_`), which is why each prefix is a [`PrefixShape`] of its own.
//! Slack moved out to [`super::slack`] (issue #371): its `xoxb-` bot prefix
//! needs a `-`-separated section grammar this generic shape cannot express,
//! while its other prefixes keep this same "prefix plus a minimum-length
//! run" shape as an interim guard, composed directly from the shared
//! `pattern` primitives instead of through this type. Cloudflare moved out
//! to [`super::cloudflare`] (issue #373): its reviewed contract needs a
//! post-hoc check on the matched run's trailing bytes (a checksum-shaped
//! tail) this type cannot express. Linear moved out to [`super::linear`]
//! (issue #374): its reviewed `lin_api_` contract needs a narrower suffix
//! alphabet (`[A-Za-z0-9]`) than the interim-guarded `lin_oauth_` prefix
//! (`[A-Za-z0-9_-]`), and this type's single alphabet field is shared by
//! every shape, not per-prefix.

use crate::detectors::pattern::{self, Alphabet, PrefixShape};
use crate::error::DetectorFailure;
use crate::types::{ByteRange, Candidate, Confidence, Detector, DetectorContext, Specificity};

/// A detector defined purely by a literal prefix set, a following
/// character-class run, and the resulting finding's metadata.
pub(super) struct KnownFormatProviderDetector {
    id: &'static str,
    type_name: &'static str,
    signals: &'static [&'static str],
    shapes: &'static [PrefixShape<'static>],
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
        for (start, end) in
            pattern::scan_prefixed_shapes(input, self.shapes, self.alphabet, self.boundary)
        {
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
    shapes: &[
        PrefixShape::at_least("sk_test_", 20),
        PrefixShape::at_least("sk_live_", 20),
        PrefixShape::at_least("rk_test_", 20),
        PrefixShape::at_least("rk_live_", 20),
        PrefixShape::at_least("sk_org_", 20),
        PrefixShape::at_least("whsec_", 20),
    ],
    alphabet: pattern::is_alnum,
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
    shapes: &[PrefixShape::at_least("pypi-", 85)],
    alphabet: pattern::is_alnum_dash,
    boundary: pattern::is_alnum_dash,
};

/// Hugging Face user access tokens in the provider's `hf_` namespace.
/// Issue #372 (following the frozen precision contract from issue #367,
/// `docs/audits/evidence/367/precision-contracts.json`) narrows the
/// retired `hf_` + 20-byte-minimum shared shape to the reviewed grammar:
/// gitleaks 8.30.1 and trufflehog 3.97.4 independently agree on an exact
/// 34-byte body, so a body one byte short of 34 (the beta.4
/// `huggingface-token-user-plain-twin` regression) is now an intentional
/// false negative instead of a match. The two tools disagree on the body
/// alphabet (gitleaks: letters only; trufflehog: letters and digits); that
/// conflict is resolved as a support-policy choice for the union
/// `[A-Za-z0-9]` rather than guessed into the letters-only intersection, so
/// a digit-bearing body is still accepted even though it stays unscored
/// (T0) in the benchmark corpus pending independent review. Both tools
/// agree the body excludes `_`/`-`, so — unlike the shared "prefix plus a
/// minimum-length run" shape most of this module's providers still use —
/// an underscore or dash inside the body is now evidence-backed exclusion,
/// not merely a length shortfall. A dash in place of the documented
/// underscore prefix, or any other undocumented prefix, remains an
/// intentional false negative.
pub(super) const HUGGING_FACE: KnownFormatProviderDetector = KnownFormatProviderDetector {
    id: "huggingface-token",
    type_name: "huggingface_token",
    signals: &["huggingface-documented-prefix", "base62-exact-length"],
    shapes: &[PrefixShape::exact("hf_", 34)],
    alphabet: pattern::is_alnum,
    boundary: pattern::is_alnum_dash,
};

/// Docker Hub personal (`dckr_pat_`) and organization (`dckr_oat_`) access
/// tokens, validated as two separately-sized exact-length shapes (issue
/// #370, `decision-freeze-docker-pat-oat-exact-length-grammar`):
///
/// ```text
/// dckr_pat_<27 bytes from [A-Za-z0-9_-]>   (36 bytes total)
/// dckr_oat_<32 bytes from [A-Za-z0-9_-]>   (41 bytes total)
/// ```
///
/// Each segment name carries its own length, so a 26- or 28-byte suffix
/// after `dckr_pat_`, a 31- or 33-byte suffix after `dckr_oat_`, or the
/// PAT length under the OAT prefix (and vice versa) is an intentional false
/// negative rather than a fuzzy match, the same exact-length precedent
/// `npm-token` and `google-api-key` below already set. Only the two
/// documented segment names are matched; an undocumented segment name is an
/// intentional false negative, and legacy Docker Hub passwords (which carry
/// no distinguishing prefix at all) are out of scope for this detector.
pub(super) const DOCKER: KnownFormatProviderDetector = KnownFormatProviderDetector {
    id: "docker-token",
    type_name: "docker_token",
    signals: &["docker-documented-prefix", "exact-length-suffix"],
    shapes: &[
        PrefixShape::exact("dckr_pat_", DOCKER_PAT_SUFFIX_LEN),
        PrefixShape::exact("dckr_oat_", DOCKER_OAT_SUFFIX_LEN),
    ],
    alphabet: pattern::is_alnum_dash,
    boundary: pattern::is_alnum_dash,
};

/// The exact suffix length after `dckr_pat_`.
pub(super) const DOCKER_PAT_SUFFIX_LEN: usize = 27;
/// The exact suffix length after `dckr_oat_`.
pub(super) const DOCKER_OAT_SUFFIX_LEN: usize = 32;

/// `DigitalOcean` personal (`dop_v1_`), `OAuth` access (`doo_v1_`), and
/// `OAuth` refresh (`dor_v1_`) token families.
///
/// The reviewed contract (issue #369) is each documented prefix followed by
/// exactly 64 lowercase hexadecimal bytes. `DigitalOcean`'s API release
/// notes (2022-03-29) establish the three prefixes; gitleaks v8.30.1
/// (`digitalocean-pat`, `digitalocean-access-token`,
/// `digitalocean-refresh-token`) and trufflehog v3.97.4 (`digitaloceanv2`)
/// independently pin the body to `[a-f0-9]{64}`, and no reviewed source
/// shows any other length or alphabet. The earlier 20-byte `[A-Za-z0-9_-]`
/// minimum accepted a 63-byte twin of every paired positive; the exact run
/// rejects it, rejects a 65-byte or wider run outright (a token is never
/// carved out of a longer identifier), and rejects uppercase hex. gitleaks
/// alone matches `dor_v1_` case-insensitively; that is a tool convenience
/// with no provider evidence behind it, so all three prefixes stay
/// case-sensitive. Only the documented `v1` namespace is matched; a future
/// version bump (`dop_v2_` and siblings) is an intentional false negative
/// until that shape is confirmed and added.
pub(super) const DIGITALOCEAN: KnownFormatProviderDetector = KnownFormatProviderDetector {
    id: "digitalocean-token",
    type_name: "digitalocean_token",
    signals: &["digitalocean-documented-prefix", "fixed-length-hex-suffix"],
    shapes: &[
        PrefixShape::exact("dop_v1_", 64),
        PrefixShape::exact("doo_v1_", 64),
        PrefixShape::exact("dor_v1_", 64),
    ],
    alphabet: pattern::is_lower_hex,
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
    shapes: &[PrefixShape::at_least("sb_secret_", 20)],
    alphabet: pattern::is_alnum_dash,
    boundary: pattern::is_alnum_dash,
};

/// Vercel personal, integration, app, refresh, and API-key credentials. An
/// undocumented prefix letter is an intentional false negative.
pub(super) const VERCEL: KnownFormatProviderDetector = KnownFormatProviderDetector {
    id: "vercel-token",
    type_name: "vercel_token",
    signals: &["vercel-documented-prefix", "opaque-suffix"],
    shapes: &[
        PrefixShape::at_least("vcp_", 20),
        PrefixShape::at_least("vci_", 20),
        PrefixShape::at_least("vca_", 20),
        PrefixShape::at_least("vcr_", 20),
        PrefixShape::at_least("vck_", 20),
    ],
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
    shapes: &[PrefixShape::exact("npm_", 36)],
    alphabet: pattern::is_alnum,
    boundary: pattern::is_alnum_dash,
};

/// Legacy Google Cloud / Gemini "standard" API keys: the `AIza` prefix
/// documented by Google Cloud's API-key authentication guide, followed by an
/// exact 35-byte suffix from `[A-Za-z0-9_-]`, for 39 bytes total. This is the
/// key *string* used to authenticate requests, not the administrative key
/// *ID* shown in Cloud console URLs — the ID cannot call any API and is out
/// of scope. Google began issuing a differently-shaped "Auth key" (service
/// account-bound, reported with an `AQ.` prefix) as the new default in 2026
/// and is retiring standalone `AIza` keys; that newer shape is an
/// intentional false negative until its grammar is confirmed from
/// authoritative Google documentation, not third-party reports. A suffix
/// shorter or longer than exactly 35 bytes, or an undocumented prefix, is
/// also an intentional false negative rather than a fuzzy match. The same
/// `AIza`-prefixed shape appears in public Firebase/browser configuration
/// (referrer-restricted, not always a privileged secret) as well as in
/// service-scoped Cloud/Gemini use, so this detector reports the shape at
/// `Confidence::High` and leaves the redact/warn action call to policy, the
/// same tradeoff npm and the other known-format providers above make.
pub(super) const GOOGLE: KnownFormatProviderDetector = KnownFormatProviderDetector {
    id: "google-api-key",
    type_name: "google_api_key",
    signals: &["google-documented-prefix", "exact-length-suffix"],
    shapes: &[PrefixShape::exact("AIza", 35)],
    alphabet: pattern::is_alnum_dash,
    boundary: pattern::is_alnum_dash,
};

/// Grafana Cloud access policy tokens (formerly "Grafana Cloud API tokens"
/// in older provider material). Grafana's own documentation describes the
/// `glc_` prefix only through example output, not a published grammar; two
/// independent external tools (gitleaks's `grafana-cloud-api-token` and
/// trufflehog's `grafana` detector, consulted only as behavioral references
/// per `AGENTS.md`) both converge on a `glc_`-prefixed base64 body, with
/// trufflehog additionally observing that the body itself decodes as
/// base64-encoded JSON. This detector matches the `glc_` prefix followed by
/// a run of the standard base64 body alphabet (`[A-Za-z0-9+/]`, no `=`
/// padding -- see [`pattern::is_base64_body`]) with a 32-byte minimum,
/// matching gitleaks's documented floor rather than trufflehog's narrower
/// `eyJ`-anchored variant, since requiring a specific decoded-JSON prefix
/// would encode an implementation detail of a single external tool rather
/// than an independently confirmed provider fact. An undocumented prefix,
/// or a body shorter than the minimum, is an intentional false negative.
pub(super) const GRAFANA_CLOUD: KnownFormatProviderDetector = KnownFormatProviderDetector {
    id: "grafana-cloud-access-policy-token",
    type_name: "grafana_cloud_access_policy_token",
    signals: &["grafana-cloud-documented-prefix", "base64-opaque-suffix"],
    shapes: &[PrefixShape::at_least("glc_", 32)],
    alphabet: pattern::is_base64_body,
    boundary: pattern::is_alnum_dash,
};

#[cfg(test)]
mod tests {
    use super::*;

    const BODY: &str = "SYNTHETICREVOKEDPROVIDERVALUE";
    /// Issue #372: Hugging Face's suffix is matched as an exact 34-byte
    /// length from `[A-Za-z0-9]` (no `_`/`-`), not a minimum, so it needs
    /// its own fixed-length, underscore-free synthetic body rather than
    /// [`BODY`].
    const HUGGING_FACE_BODY: &str = "SYNTHETICREVOKEDHUGGINGFACETOKEN01";
    const _: () = assert!(HUGGING_FACE_BODY.len() == 34);
    /// npm's suffix is matched as an exact 36-byte length, not a minimum, so
    /// it needs its own fixed-length synthetic body rather than [`BODY`].
    const NPM_BODY: &str = "SYNTHETICREVOKEDNPMACCESSTOKENVALUE1";
    /// Google's suffix is matched as an exact 35-byte length, not a minimum,
    /// so it needs its own fixed-length synthetic body rather than [`BODY`].
    const GOOGLE_BODY: &str = "SYNTHETIC_REVOKED_GOOGLE_API_KEY012";
    /// Grafana Cloud's suffix has a 32-byte minimum, longer than [`BODY`]'s
    /// 30 bytes, so it needs its own body.
    const GRAFANA_CLOUD_BODY: &str = "SYNTHETICREVOKEDGRAFANACLOUDACCESSPOLICYTOKEN";
    /// Exactly [`DOCKER_PAT_SUFFIX_LEN`] bytes: the documented `dckr_pat_`
    /// suffix length (issue #370).
    const DOCKER_PAT_BODY: &str = "SYNTHETICREVOKEDDOCKERPAT00";
    /// Exactly [`DOCKER_OAT_SUFFIX_LEN`] bytes: the documented `dckr_oat_`
    /// suffix length (issue #370).
    const DOCKER_OAT_BODY: &str = "SYNTHETICREVOKEDDOCKERORGTOKEN00";
    const _: () = assert!(DOCKER_PAT_BODY.len() == DOCKER_PAT_SUFFIX_LEN);
    const _: () = assert!(DOCKER_OAT_BODY.len() == DOCKER_OAT_SUFFIX_LEN);
    /// `DigitalOcean`'s suffix is exactly 64 lowercase hex bytes (issue
    /// #369), so each documented prefix gets its own fixed-length synthetic
    /// body. These are the locally constructed values from the issue's
    /// self-contained snapshot; none was ever provider-issued.
    const DIGITALOCEAN_BODY: &str =
        "1f24601fd1e661dc9b0a5f6e206888cac4ba0147c46563ccd2d81004e954cad9";
    const DIGITALOCEAN_OAUTH_BODY: &str =
        "025343c0555235768c29735f523ad644fbfe1569b1d88f46b4f506628ae8b08a";
    const DIGITALOCEAN_REFRESH_BODY: &str =
        "686b232b8722f7ab110b24d01fd9a96539cdec166f27e643ae9852b28d2b0da5";

    fn detect(detector: &KnownFormatProviderDetector, input: &str) -> Vec<Candidate> {
        detector
            .detect(input, &DetectorContext::new(input.len()))
            .unwrap()
    }

    struct Family {
        detector: KnownFormatProviderDetector,
        value: String,
        /// `value` with an invalid-alphabet byte inserted four bytes into
        /// the suffix, so the run breaks before any family's minimum or
        /// exact length is reached.
        broken: String,
        short: &'static str,
    }

    fn family(
        detector: KnownFormatProviderDetector,
        prefix: &str,
        body: &str,
        short: &'static str,
    ) -> Family {
        Family {
            detector,
            value: format!("{prefix}{body}"),
            broken: format!("{prefix}{}!{}", &body[..4], &body[4..]),
            short,
        }
    }

    fn families() -> Vec<Family> {
        vec![
            family(STRIPE, "sk_live_", BODY, "sk_live_SYNTHETICSHORT"),
            family(
                PYPI,
                "pypi-",
                &"SYNTHETIC_REVOKED_".repeat(5),
                "pypi-SYNTHETICSHORT",
            ),
            family(HUGGING_FACE, "hf_", HUGGING_FACE_BODY, "hf_SYNTHETIC_SHORT"),
            family(
                DOCKER,
                "dckr_pat_",
                DOCKER_PAT_BODY,
                "dckr_pat_SYNTHETIC_SHORT",
            ),
            family(
                DIGITALOCEAN,
                "dop_v1_",
                DIGITALOCEAN_BODY,
                "dop_v1_SYNTHETIC_SHORT",
            ),
            family(SUPABASE, "sb_secret_", BODY, "sb_secret_SYNTHETIC_SHORT"),
            family(VERCEL, "vcp_", BODY, "vcp_SYNTHETIC_SHORT"),
            family(NPM, "npm_", NPM_BODY, "npm_SYNTHETICSHORT"),
            family(GOOGLE, "AIza", GOOGLE_BODY, "AIzaSYNTHETICSHORT"),
            family(
                GRAFANA_CLOUD,
                "glc_",
                GRAFANA_CLOUD_BODY,
                "glc_SYNTHETICSHORT",
            ),
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
            for input in [family.short, family.broken.as_str(), embedded.as_str()] {
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
        // Docker's two prefixes carry different exact lengths, so they are
        // asserted by `docker_accepts_each_segment_at_exactly_its_own_length`
        // instead of against the shared minimum-length `BODY`. Slack moved
        // out to `super::slack` (issue #371) and Linear to `super::linear`
        // (issue #374); each is covered by its own tests there.
        let cases: [(&KnownFormatProviderDetector, &str); 14] = [
            (&STRIPE, "sk_test_"),
            (&STRIPE, "sk_live_"),
            (&STRIPE, "rk_test_"),
            (&STRIPE, "rk_live_"),
            (&STRIPE, "sk_org_"),
            (&STRIPE, "whsec_"),
            (&DIGITALOCEAN, "dop_v1_"),
            (&DIGITALOCEAN, "doo_v1_"),
            (&DIGITALOCEAN, "dor_v1_"),
            (&VERCEL, "vcp_"),
            (&VERCEL, "vci_"),
            (&VERCEL, "vca_"),
            (&VERCEL, "vcr_"),
            (&VERCEL, "vck_"),
        ];
        for (detector, prefix) in cases {
            // DigitalOcean's contracted body is exactly 64 lowercase hex
            // bytes (issue #369), so it cannot share the generic [`BODY`].
            let body = if detector.id() == DIGITALOCEAN.id() {
                DIGITALOCEAN_BODY
            } else {
                BODY
            };
            let value = format!("{prefix}{body}");
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

    /// Issue #320: the four infrastructure-provider detectors (Docker,
    /// Cloudflare, `DigitalOcean`, Vercel) each get the same false-positive
    /// assurance the earlier prefix-family issues (#316/#317) established
    /// for Stripe/Shopify/Supabase/`OpenAI`/Anthropic, across every
    /// documented prefix variant.
    /// 27 bytes: a valid suffix for every minimum-length infra prefix and,
    /// since issue #370, exactly the documented `dckr_pat_` length too.
    const INFRA_SUFFIX: &str = "SYNTHETIC_REVOKED_KEY_VALUE";
    /// 32 bytes: exactly the documented `dckr_oat_` length (issue #370).
    const DOCKER_OAT_SUFFIX: &str = "SYNTHETIC_REVOKED_OAT_KEY_VALUE3";
    const _: () = assert!(INFRA_SUFFIX.len() == DOCKER_PAT_SUFFIX_LEN);
    const _: () = assert!(DOCKER_OAT_SUFFIX.len() == DOCKER_OAT_SUFFIX_LEN);

    /// One documented prefix of an infrastructure-provider detector, paired
    /// with a synthetic body that satisfies that detector's contracted
    /// shape and a documentation-style placeholder built entirely from the
    /// detector's own suffix alphabet at a length its contract accepts.
    struct InfraVariant {
        detector: &'static KnownFormatProviderDetector,
        prefix: &'static str,
        body: &'static str,
        placeholder: String,
    }

    fn opaque_variant(
        detector: &'static KnownFormatProviderDetector,
        prefix: &'static str,
    ) -> InfraVariant {
        InfraVariant {
            detector,
            prefix,
            body: INFRA_SUFFIX,
            placeholder: "x".repeat(20),
        }
    }

    /// `DigitalOcean`'s contract is exactly 64 lowercase hex bytes (issue
    /// #369), so its variants carry a fixed-length hex body and a hex-only
    /// placeholder.
    fn digitalocean_variant(prefix: &'static str, body: &'static str) -> InfraVariant {
        InfraVariant {
            detector: &DIGITALOCEAN,
            prefix,
            body,
            placeholder: "a".repeat(64),
        }
    }

    /// Docker Hub's two prefixes carry different exact lengths (issue
    /// #370), so each gets a body of its own documented length and a
    /// placeholder of that same length.
    fn docker_variant(prefix: &'static str, body: &'static str) -> InfraVariant {
        InfraVariant {
            detector: &DOCKER,
            prefix,
            body,
            placeholder: "x".repeat(body.len()),
        }
    }

    fn infra_provider_variants() -> Vec<InfraVariant> {
        vec![
            docker_variant("dckr_pat_", INFRA_SUFFIX),
            docker_variant("dckr_oat_", DOCKER_OAT_SUFFIX),
            digitalocean_variant("dop_v1_", DIGITALOCEAN_BODY),
            digitalocean_variant("doo_v1_", DIGITALOCEAN_OAUTH_BODY),
            digitalocean_variant("dor_v1_", DIGITALOCEAN_REFRESH_BODY),
            opaque_variant(&VERCEL, "vcp_"),
            opaque_variant(&VERCEL, "vci_"),
            opaque_variant(&VERCEL, "vca_"),
            opaque_variant(&VERCEL, "vcr_"),
            opaque_variant(&VERCEL, "vck_"),
        ]
    }

    #[test]
    fn infra_providers_accept_a_doc_style_placeholder_built_from_valid_alphabet_characters() {
        for variant in infra_provider_variants() {
            let input = format!("{}{}", variant.prefix, variant.placeholder);
            assert_eq!(
                detect(variant.detector, &input).len(),
                1,
                "{}",
                variant.detector.id()
            );
        }
    }

    #[test]
    fn infra_providers_reject_a_prefix_embedded_in_a_wider_benign_identifier() {
        // A leading alnum/dash byte right before the documented prefix means
        // this is a truncated slice of a longer identifier, not a
        // boundary-delimited credential.
        for variant in infra_provider_variants() {
            let input = format!("legacy{}{}", variant.prefix, variant.body);
            assert_eq!(
                detect(variant.detector, &input).len(),
                0,
                "{}",
                variant.detector.id()
            );
        }
    }

    #[test]
    fn infra_providers_reject_case_changed_wrong_prefixes() {
        for variant in infra_provider_variants() {
            let input = format!("{}{}", variant.prefix.to_ascii_uppercase(), variant.body);
            assert_eq!(
                detect(variant.detector, &input).len(),
                0,
                "{}",
                variant.detector.id()
            );
        }
    }

    #[test]
    fn infra_providers_reject_masked_and_interpolated_near_misses() {
        for variant in infra_provider_variants() {
            for input in [
                format!("{}{}", variant.prefix, "*".repeat(variant.body.len())),
                format!("{}${{ENV_VAR}}", variant.prefix),
            ] {
                assert_eq!(
                    detect(variant.detector, &input).len(),
                    0,
                    "{} {input}",
                    variant.detector.id()
                );
            }
        }
    }

    #[test]
    fn infra_providers_bound_a_match_against_trailing_prose_punctuation() {
        for variant in infra_provider_variants() {
            let token = format!("{}{}", variant.prefix, variant.body);
            let input = format!("Rotate {token}, then redeploy.");
            let candidates = detect(variant.detector, &input);
            assert_eq!(candidates.len(), 1, "{}", variant.detector.id());
            let start = "Rotate ".len();
            let end = start + token.len();
            assert_eq!(
                candidates[0].range(),
                ByteRange::new(start, end).unwrap(),
                "{}",
                variant.detector.id()
            );
        }
    }

    /// A container registry/image reference qualified by a `sha256:` digest
    /// (the well-known hash of the empty string, not a credential) has
    /// neither Docker Hub's documented prefix nor its alphabet shape.
    #[test]
    fn docker_rejects_an_ordinary_registry_image_digest_reference() {
        let input = "docker pull registry.example.com/myorg/app@sha256:\
            e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b85";
        assert_eq!(detect(&DOCKER, input).len(), 0);
    }

    /// Issue #370: `dckr_pat_` and `dckr_oat_` are validated separately, each
    /// at exactly its own documented length (27 and 32 bytes), instead of
    /// sharing one 20-byte minimum.
    #[test]
    fn docker_accepts_each_segment_at_exactly_its_own_length() {
        for (prefix, body) in [
            ("dckr_pat_", DOCKER_PAT_BODY),
            ("dckr_oat_", DOCKER_OAT_BODY),
        ] {
            let value = format!("{prefix}{body}");
            let candidates = detect(&DOCKER, &value);
            assert_eq!(candidates.len(), 1, "{prefix}");
            assert_eq!(candidates[0].confidence(), Confidence::High);
            assert_eq!(candidates[0].effective_specificity(), Specificity::Provider);
            assert_eq!(
                candidates[0].range(),
                ByteRange::new(0, value.len()).unwrap(),
                "{prefix}"
            );
        }
    }

    /// Issue #370: one byte short of, or one byte past, either documented
    /// length is an intentional false negative — the beta.4 benchmark's
    /// `docker-token-pat-plain-twin` (26) and `docker-token-oat-plain-twin`
    /// (31) mutations, plus their one-byte-long counterparts. A longer run is
    /// not misread as the exact shape followed by trailing bytes.
    #[test]
    fn docker_rejects_a_suffix_one_byte_off_either_documented_length() {
        for (prefix, body) in [
            ("dckr_pat_", DOCKER_PAT_BODY),
            ("dckr_oat_", DOCKER_OAT_BODY),
        ] {
            let one_short = format!("{prefix}{}", &body[..body.len() - 1]);
            let one_long = format!("{prefix}{body}0");
            for input in [one_short, one_long] {
                assert_eq!(detect(&DOCKER, &input).len(), 0, "{input}");
            }
        }
    }

    /// Issue #370: the two segment names do not share a length — the PAT
    /// length under the OAT prefix and the OAT length under the PAT prefix
    /// are both rejected.
    #[test]
    fn docker_does_not_share_a_length_between_segment_names() {
        for input in [
            format!("dckr_oat_{DOCKER_PAT_BODY}"),
            format!("dckr_pat_{DOCKER_OAT_BODY}"),
        ] {
            assert_eq!(detect(&DOCKER, &input).len(), 0, "{input}");
        }
    }

    /// Issue #370: the benchmark's Unicode/CRLF twins
    /// (`docker-token-pat-unicode-crlf-twin`,
    /// `docker-token-oat-unicode-crlf-twin`) stay silent while their paired
    /// positives are reported at exact UTF-8 byte offsets — the 24-byte
    /// comment line before each token is the same prefix the benchmark uses.
    #[test]
    fn docker_distinguishes_unicode_crlf_twins_from_their_paired_positives() {
        const COMMENT: &str = "# \u{1F511} reviewed format\r\n";
        assert_eq!(COMMENT.len(), 24);
        for (prefix, body) in [
            ("dckr_pat_", DOCKER_PAT_BODY),
            ("dckr_oat_", DOCKER_OAT_BODY),
        ] {
            let positive = format!("{COMMENT}{prefix}{body}\n\r\n");
            let candidates = detect(&DOCKER, &positive);
            assert_eq!(candidates.len(), 1, "{prefix}");
            assert_eq!(
                candidates[0].range(),
                ByteRange::new(COMMENT.len(), COMMENT.len() + prefix.len() + body.len()).unwrap(),
                "{prefix}"
            );

            let twin = format!("{COMMENT}{prefix}{}\n\r\n", &body[..body.len() - 1]);
            assert_eq!(detect(&DOCKER, &twin).len(), 0, "{prefix}");
        }
    }

    /// Issue #370: a valid PAT, its 26-byte twin, a valid OAT, and its
    /// 31-byte twin on adjacent lines are discriminated independently, and a
    /// quoted, backticked, or `key=` value is still bounded exactly.
    #[test]
    fn docker_discriminates_adjacent_twins_and_bounds_delimited_values() {
        let pat = format!("dckr_pat_{DOCKER_PAT_BODY}");
        let oat = format!("dckr_oat_{DOCKER_OAT_BODY}");
        let pat_twin = &pat[..pat.len() - 1];
        let oat_twin = &oat[..oat.len() - 1];
        let input = format!("{pat}\n{pat_twin}\n{oat}\n{oat_twin}\n");
        let candidates = detect(&DOCKER, &input);
        let ranges: Vec<(usize, usize)> = candidates
            .iter()
            .map(|candidate| (candidate.range().start(), candidate.range().end()))
            .collect();
        let oat_start = pat.len() + 1 + pat_twin.len() + 1;
        assert_eq!(
            ranges,
            vec![(0, pat.len()), (oat_start, oat_start + oat.len())]
        );

        for (input, start, len) in [
            (format!("\"{pat}\""), 1, pat.len()),
            (format!("`{oat}`"), 1, oat.len()),
            (
                format!("DOCKER_TOKEN={pat}"),
                "DOCKER_TOKEN=".len(),
                pat.len(),
            ),
        ] {
            let candidates = detect(&DOCKER, &input);
            assert_eq!(candidates.len(), 1, "{input}");
            assert_eq!(
                candidates[0].range(),
                ByteRange::new(start, start + len).unwrap(),
                "{input}"
            );
        }
    }

    /// A `DigitalOcean` App Platform deployment/resource identifier is an
    /// ordinary UUID with no `v1` token prefix.
    #[test]
    fn digitalocean_rejects_an_ordinary_deployment_resource_id() {
        let input = "resource: do:app:3f900b88-8eb1-4de4-b7a3-93c1fb2f8b1d";
        assert_eq!(detect(&DIGITALOCEAN, input).len(), 0);
    }

    /// A Vercel deployment identifier uses its own `dpl_` namespace,
    /// distinct from every documented Vercel token prefix.
    #[test]
    fn vercel_rejects_an_ordinary_deployment_id() {
        let input = "deployment: dpl_8sFjq2K3nQeR7xYtLmWzAbCdEfGh";
        assert_eq!(detect(&VERCEL, input).len(), 0);
    }

    /// Issue #320 follow-up: an identical value repeated in the same input
    /// is reported once per independent occurrence, not deduplicated, the
    /// same dimension #321 established for `HuggingFace`/Linear/Slack but
    /// not yet exercised for the four infra-provider families.
    #[test]
    fn infra_providers_report_a_repeated_identical_value_once_per_occurrence() {
        for variant in infra_provider_variants() {
            let value = format!("{}{}", variant.prefix, variant.body);
            let input = format!("{value} {value}");
            let candidates = detect(variant.detector, &input);
            assert_eq!(candidates.len(), 2, "{}", variant.detector.id());
        }
    }

    /// Issue #321: this dimension is scoped to `HUGGING_FACE`, without
    /// widening the shared [`families`] list. Slack moved out to
    /// `super::slack` (issue #371) and Linear to `super::linear` (issue
    /// #374); each repeats this dimension there for its own prefixes.
    #[test]
    fn application_providers_accept_an_all_valid_alphabet_documentation_placeholder() {
        let value = format!("hf_{}", "x".repeat(34));
        let candidates = detect(&HUGGING_FACE, &value);
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].confidence(), Confidence::High);
    }

    #[test]
    fn application_providers_reject_the_prefix_embedded_in_a_wider_identifier() {
        let value = format!("legacyhf_{HUGGING_FACE_BODY}");
        assert_eq!(detect(&HUGGING_FACE, &value).len(), 0);
    }

    #[test]
    fn application_providers_reject_a_percent_encoded_delimiter_lookalike() {
        assert_eq!(
            detect(&HUGGING_FACE, "hf%5FSYNTHETIC_REVOKED_CONFORMANCE_KEY").len(),
            0
        );
    }

    #[test]
    fn application_providers_report_a_repeated_identical_value_once_per_occurrence() {
        let value = format!("hf_{HUGGING_FACE_BODY}");
        let input = format!("{value} {value}");
        assert_eq!(detect(&HUGGING_FACE, &input).len(), 2);
    }

    /// Issue #372: the frozen precision contract
    /// (`docs/audits/evidence/367/precision-contracts.json`, `families.
    /// huggingface-token`) narrows the body to exactly 34 bytes. A 33-byte
    /// body — one byte short, the beta.4
    /// `huggingface-token-user-plain-twin` regression fixture — is an
    /// intentional false negative, and a 35-byte body (one byte past the
    /// documented length) is not misread as the exact shape followed by a
    /// trailing byte.
    #[test]
    fn huggingface_rejects_a_body_one_byte_off_the_documented_length() {
        for body in [
            &HUGGING_FACE_BODY[..HUGGING_FACE_BODY.len() - 1],
            &format!("{HUGGING_FACE_BODY}A"),
        ] {
            let value = format!("hf_{body}");
            assert_eq!(detect(&HUGGING_FACE, &value).len(), 0, "{value}");
        }
    }

    /// Issue #372: both gitleaks 8.30.1 and trufflehog 3.97.4 agree the body
    /// excludes `_`/`-`; the beta.4 shared minimum-length shape's acceptance
    /// of them was a shared-rule artifact, not evidence. An otherwise
    /// documented-length body containing either byte is rejected rather
    /// than truncated to its longest valid-alphabet prefix.
    #[test]
    fn huggingface_rejects_a_documented_length_body_containing_underscore_or_dash() {
        for byte in ['_', '-'] {
            let mut body = HUGGING_FACE_BODY.to_string();
            body.replace_range(4..5, &byte.to_string());
            let value = format!("hf_{body}");
            assert_eq!(detect(&HUGGING_FACE, &value).len(), 0, "{value}");
        }
    }

    /// Issue #372: the two tools disagree on the body alphabet (gitleaks:
    /// letters only; trufflehog: letters and digits). That conflict is
    /// resolved as a support-policy choice for the union rather than
    /// guessed into the letters-only intersection, so a digit-bearing body
    /// is still accepted.
    #[test]
    fn huggingface_accepts_a_digit_bearing_documented_length_body() {
        let mut body = HUGGING_FACE_BODY.to_string();
        body.replace_range(0..2, "42");
        let value = format!("hf_{body}");
        assert_eq!(detect(&HUGGING_FACE, &value).len(), 1, "{value}");
    }

    // Issue #369: the DigitalOcean v1 token contract. DigitalOcean's API
    // release notes (2022-03-29) document the `dop_v1_` / `doo_v1_` /
    // `dor_v1_` prefixes; gitleaks v8.30.1 and trufflehog v3.97.4
    // independently pin the body to `[a-f0-9]{64}`. Every body below is a
    // locally constructed synthetic value from the issue's self-contained
    // snapshot; none was ever provider-issued.

    /// The three documented prefixes, each with its synthetic 64-byte body.
    fn digitalocean_tokens() -> [String; 3] {
        [
            format!("dop_v1_{DIGITALOCEAN_BODY}"),
            format!("doo_v1_{DIGITALOCEAN_OAUTH_BODY}"),
            format!("dor_v1_{DIGITALOCEAN_REFRESH_BODY}"),
        ]
    }

    #[test]
    fn digitalocean_accepts_exactly_sixty_four_lowercase_hex_bytes_for_every_prefix() {
        for token in digitalocean_tokens() {
            assert_eq!(token.len(), 71);
            let candidates = detect(&DIGITALOCEAN, &token);
            assert_eq!(candidates.len(), 1, "{token}");
            assert_eq!(candidates[0].type_name(), "digitalocean_token");
            assert_eq!(candidates[0].confidence(), Confidence::High);
            assert_eq!(candidates[0].effective_specificity(), Specificity::Provider);
            assert_eq!(candidates[0].range(), ByteRange::new(0, 71).unwrap());
        }
    }

    /// The reproduced beta.4 failure: a 63-byte body -- the paired positive
    /// with its final byte dropped -- was accepted under the old 20-byte
    /// minimum and is now rejected, both bare and in the Unicode/CRLF
    /// framing the benchmark used, while the paired positive keeps its exact
    /// UTF-8 byte range.
    #[test]
    fn digitalocean_rejects_a_sixty_three_byte_twin_of_every_prefix() {
        for token in digitalocean_tokens() {
            let twin = &token[..token.len() - 1];
            for input in [
                format!("{twin}\n\n"),
                format!("# \u{1F511} reviewed format\r\n{twin}\n\r\n"),
            ] {
                assert!(detect(&DIGITALOCEAN, &input).is_empty(), "{input}");
            }
            let framed = format!("# \u{1F511} reviewed format\r\n{token}\n\r\n");
            let candidates = detect(&DIGITALOCEAN, &framed);
            assert_eq!(candidates.len(), 1, "{framed}");
            assert_eq!(candidates[0].range(), ByteRange::new(24, 95).unwrap());
        }
    }

    /// A longer run of the boundary alphabet is a wider identifier, not a
    /// token with a valid-looking 64-byte substring: nothing is carved out
    /// of it on either side.
    #[test]
    fn digitalocean_never_extracts_a_token_from_a_wider_identifier() {
        for token in digitalocean_tokens() {
            for input in [
                // One extra hex byte: a 65-byte run.
                format!("{token}0"),
                // A trailing underscore- or dash-joined segment.
                format!("{token}_backup"),
                format!("{token}-1"),
                // A leading alphabet byte or identifier fragment.
                format!("x{token}"),
                format!("legacy{token}"),
            ] {
                assert!(detect(&DIGITALOCEAN, &input).is_empty(), "{input}");
            }
        }
    }

    #[test]
    fn digitalocean_rejects_uppercase_hex_and_non_hex_bytes_inside_the_body() {
        let token = format!("dop_v1_{DIGITALOCEAN_BODY}");
        let body_at = |index: usize, replacement: &str| {
            let at = "dop_v1_".len() + index;
            format!("{}{replacement}{}", &token[..at], &token[at + 1..])
        };
        for input in [
            // One uppercase hex digit inside the body.
            body_at(8, "D"),
            // One byte outside `[0-9a-f]`.
            body_at(8, "g"),
            // Whitespace splits the run.
            body_at(8, " "),
            // An uppercase final byte: 63 valid bytes then a boundary byte.
            body_at(63, "A"),
        ] {
            assert!(detect(&DIGITALOCEAN, &input).is_empty(), "{input}");
        }
    }

    /// Quotes, Markdown code spans, prose punctuation, and URL query
    /// delimiters all bound the token without joining it.
    #[test]
    fn digitalocean_bounds_the_token_against_quotes_code_spans_and_urls() {
        let token = format!("dop_v1_{DIGITALOCEAN_BODY}");
        for (input, start) in [
            (format!("\"{token}\""), 1),
            (format!("`{token}`"), 1),
            (format!("token: '{token}',"), 8),
            (format!("https://example.test/?token={token}&x=1"), 28),
        ] {
            let candidates = detect(&DIGITALOCEAN, &input);
            assert_eq!(candidates.len(), 1, "{input}");
            assert_eq!(
                candidates[0].range(),
                ByteRange::new(start, start + 71).unwrap(),
                "{input}"
            );
        }
    }

    #[test]
    fn digitalocean_rejects_wrong_and_encoded_prefixes_with_a_contracted_body() {
        for input in [
            format!("dov_v1_{DIGITALOCEAN_BODY}"),
            format!("dop_v2_{DIGITALOCEAN_BODY}"),
            format!("DOP_V1_{DIGITALOCEAN_BODY}"),
            format!("dop%5Fv1%5F{DIGITALOCEAN_BODY}"),
        ] {
            assert!(detect(&DIGITALOCEAN, &input).is_empty(), "{input}");
        }
    }
}
