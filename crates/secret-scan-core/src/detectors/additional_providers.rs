//! Stripe, `PyPI`, Hugging Face, Docker, `DigitalOcean`, Supabase, Vercel,
//! npm, Google, Grafana Cloud, and Pulumi access token detection.
//!
//! Mirrors the retired `src/detectors/additional-providers.ts` oracle. Every
//! one of these providers reduces to the same shape as [`super::gitlab`] or
//! [`super::anthropic`] — a documented literal prefix set, each prefix
//! followed by a fixed- or minimum-length run of a documented alphabet, an
//! optional post-hoc check, and the finding signals a match carries — so
//! they share one generic, table-driven [`Detector`] implementation instead
//! of one bespoke type each. [`super::cloudflare`] and [`super::linear`] are
//! this same detector: a [`PrefixShape`]'s alphabet, signals, and
//! [`pattern::PostCheck`] are each carried per shape, not per detector, so
//! Cloudflare's checksum-shaped tail and Linear's two differently-alphabet'd
//! prefixes are both expressible as data, matched in one left-to-right,
//! longest-prefix-wins pass. [`super::slack`] is the one exception: its
//! `xoxb-` bot prefix needs a `-`-separated section grammar no
//! [`PrefixShape`] can express, so it stays a bespoke `Detector`; its other
//! prefixes keep this same "prefix plus a minimum-length run" shape as an
//! interim guard, merged with the bot scan's results by position.

use crate::detectors::pattern::{self, Alphabet, PrefixShape};
use crate::error::DetectorFailure;
use crate::types::{ByteRange, Candidate, Confidence, Detector, DetectorContext, Specificity};

/// A detector defined purely by a table of [`PrefixShape`]s (each carrying
/// its own alphabet and finding signals) and a shared boundary alphabet.
pub(super) struct KnownFormatProviderDetector {
    id: &'static str,
    type_name: &'static str,
    shapes: &'static [PrefixShape<'static>],
    boundary: Alphabet,
}

impl KnownFormatProviderDetector {
    /// Constructs a detector from its table, for use by sibling detector
    /// modules ([`super::cloudflare`], [`super::linear`]) whose own reviewed
    /// contract is this same shape.
    pub(super) const fn new(
        id: &'static str,
        type_name: &'static str,
        shapes: &'static [PrefixShape<'static>],
        boundary: Alphabet,
    ) -> Self {
        Self {
            id,
            type_name,
            shapes,
            boundary,
        }
    }
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
        for (start, end, signals) in
            pattern::scan_prefixed_shapes(input, self.shapes, self.boundary)
        {
            let Some(range) = ByteRange::new(start, end) else {
                continue;
            };
            candidates.push(
                Candidate::new(self.type_name, Confidence::High, range)
                    .with_specificity(Specificity::Provider)
                    .with_signals(signals.iter().copied()),
            );
        }
        Ok(candidates)
    }
}

/// Stripe secret, restricted, organization, and webhook-signing
/// credentials. The suffix alphabet is `[A-Za-z0-9]` — narrower than the
/// `[A-Za-z0-9_-]` boundary — so a trailing `_` or `-` still rejects a
/// truncated candidate. The publishable-key prefix (`pk_live_`,
/// `pk_test_`) is deliberately excluded: Stripe's own key-types table
/// (<https://docs.stripe.com/keys>, observed 2026-09-20) marks `pk_...` as
/// "Safe to expose" — the only key type it does — so treating it as a match
/// would be a false positive by the provider's own classification, not
/// merely a naming convention this project inferred.
///
/// Issue #513 completes the family with `sk_org_` and `whsec_`, each on a
/// narrower evidence bar than `sk_`/`rk_`'s: gitleaks' `stripe-access-token`
/// rule (`(?:sk|rk)_(?:test|live|prod)_[a-zA-Z0-9]{10,99}`) and trufflehog's
/// `stripe` detector (`[rs]k_live_[a-zA-Z0-9]{20,247}`) corroborate `sk_`
/// and `rk_`'s `live`/`test` segments, but neither tool has a rule for
/// `sk_org_` or `whsec_` — both are adopted on provider documentation alone
/// (T1, prefix only; the 20-byte floor below is this family's existing
/// support-policy choice, not independently evidenced for these two
/// prefixes):
///
/// - `sk_org_` — the same key-types table documents an "Organization API
///   key `sk_org_...`", "Safe to expose: No", same secret handling as an
///   account-level secret or restricted key
///   (<https://docs.stripe.com/keys>, observed 2026-09-20).
///   `docs.stripe.com/keys/organization-api-keys` (observed 2026-09-20)
///   states the prefix precisely — "Organization API keys are prefixed
///   `sk_org`" — and, as a direct evidenced negative, that there is **no**
///   `rk_org_` counterpart: "All organization API keys have the same
///   `sk_org` prefix, regardless of their permission levels. (There's no
///   `rk_org` prefix.)" That page also states organization keys "support
///   sandboxes and live mode", but shows no literal example distinguishing
///   the two the way `sk_live_`/`sk_test_` are shown elsewhere on
///   `docs.stripe.com/keys`; without a documented literal for that segment,
///   this shape stays flat (`sk_org_` plus one opaque run), the same
///   evidence-bar reasoning `docs/decisions/2026-09-17-freeze-precision-contracts-for-seven-provider-families.md`
///   applies elsewhere in this crate ("select the reviewed source ordering,
///   never guess a literal"). A value with a `_`-delimited environment
///   segment embedded after `sk_org_` (for example a hypothetical
///   `sk_org_live_...`) is therefore an intentional false negative today:
///   the embedded `_` ends the alnum run before this shape's 20-byte floor,
///   the same way any other undocumented internal separator would.
///   gitleaks' own environment enumeration additionally includes `prod`
///   (`sk_prod_`/`rk_prod_`), which no Stripe page documents for any key
///   type; adopting it is out of this issue's scope and is left unadded.
/// - `whsec_` — `docs.stripe.com/webhooks` (observed 2026-09-20) states
///   webhook signing secrets are "per-webhook secrets", separate from API
///   keys, and shows the literal prefix directly: "a signing secret
///   beginning with `whsec_` appears", "a `webhook_endpoint.signing_secret`
///   value that starts with `whsec_`", and the verification-handler
///   placeholder `endpoint_secret = 'whsec_...'`. No page states a length or
///   alphabet for the value that follows, so this shape's 20-byte
///   alnum-run floor is the same support-policy choice already applied to
///   `sk_`/`rk_`, not an independent contract for `whsec_`.
const STRIPE_SIGNALS: [&str; 2] = ["stripe-documented-prefix", "opaque-suffix"];

pub(super) const STRIPE: KnownFormatProviderDetector = KnownFormatProviderDetector {
    id: "stripe-token",
    type_name: "stripe_credential",
    shapes: &[
        PrefixShape::at_least("sk_test_", 20, pattern::is_alnum, &STRIPE_SIGNALS),
        PrefixShape::at_least("sk_live_", 20, pattern::is_alnum, &STRIPE_SIGNALS),
        PrefixShape::at_least("rk_test_", 20, pattern::is_alnum, &STRIPE_SIGNALS),
        PrefixShape::at_least("rk_live_", 20, pattern::is_alnum, &STRIPE_SIGNALS),
        PrefixShape::at_least("sk_org_", 20, pattern::is_alnum, &STRIPE_SIGNALS),
        PrefixShape::at_least("whsec_", 20, pattern::is_alnum, &STRIPE_SIGNALS),
    ],
    boundary: pattern::is_alnum_dash,
};

/// `PyPI`'s documented Macaroon serialization with its exact minimum
/// suffix. The prefix is matched case-sensitively (lowercase `pypi-`
/// only) and the 85-byte minimum favors precision: a shorter or
/// differently-cased example is an intentional false negative rather than
/// a loosened match.
const PYPI_SIGNALS: [&str; 2] = ["pypi-documented-prefix", "macaroon-minimum-length"];

pub(super) const PYPI: KnownFormatProviderDetector = KnownFormatProviderDetector {
    id: "pypi-token",
    type_name: "pypi_api_token",
    shapes: &[PrefixShape::at_least(
        "pypi-",
        85,
        pattern::is_alnum_dash,
        &PYPI_SIGNALS,
    )],
    boundary: pattern::is_alnum_dash,
};

/// Hugging Face user access tokens in the provider's `hf_` namespace: the
/// reviewed grammar (issue #372, following the frozen precision contract
/// from issue #367, `docs/contracts/precision/precision-contracts.json`) is
/// `hf_` plus an exact 34-byte body, matched to the union alphabet
/// `[A-Za-z0-9]`. gitleaks 8.30.1 and trufflehog 3.97.4 independently agree
/// on the 34-byte exact length, so a body one byte short is an intentional
/// false negative; they disagree on the body alphabet (gitleaks: letters
/// only; trufflehog: letters and digits), resolved as a support-policy
/// choice for the union rather than the letters-only intersection, so a
/// digit-bearing body is accepted even though it stays unscored (T0) in the
/// benchmark corpus pending independent review. Both tools agree the body
/// excludes `_`/`-`, an evidence-backed exclusion rather than merely a
/// length shortfall. A dash in place of the documented underscore prefix, or
/// any other undocumented prefix, is an intentional false negative.
///
/// Hugging Face organization API tokens in the `api_org_` namespace (issue
/// #485, re-tiering `docs/contracts/precision/precision-contracts.json`,
/// `families.huggingface-token.pending.organization-token` from T0 to T2):
/// the #367 audit deferred `api_org_` not for an evidence gap but as a scope
/// boundary ("adding a variant is a coverage change, not a precision fix"),
/// while the evidence itself already matched the `hf_` variant's own T2
/// bar. gitleaks 8.30.1 registers `api_org_` as its own
/// `huggingface-organization-api-token` rule (34-byte letters-only body) and
/// trufflehog 3.97.4 matches both `hf_` and `api_org_` under one
/// `(?:hf_|api_org_)[a-zA-Z0-9]{34}` rule — the identical dual-tool,
/// 34-byte-exact-length agreement, and the identical gitleaks/trufflehog
/// letters-only-vs-union alphabet conflict, that already ties `hf_`'s own
/// length and alphabet to "tool-agreement" and "support-policy" rather than
/// provider documentation. No Hugging Face page documents `api_org_`'s
/// grammar, but none documents `hf_`'s length or alphabet either — only its
/// bare prefix, as a placeholder. `api_org_` is therefore adopted as a
/// second [`PrefixShape`] over `hf_`'s identical body grammar, not new
/// matching logic, and the alphabet conflict is resolved identically (union
/// `[A-Za-z0-9]`, support-policy).
const HUGGING_FACE_SIGNALS: [&str; 2] = ["huggingface-documented-prefix", "base62-exact-length"];
const HUGGING_FACE_ORGANIZATION_SIGNALS: [&str; 2] = [
    "huggingface-organization-documented-prefix",
    "base62-exact-length",
];

pub(super) const HUGGING_FACE: KnownFormatProviderDetector = KnownFormatProviderDetector {
    id: "huggingface-token",
    type_name: "huggingface_token",
    shapes: &[
        PrefixShape::exact("hf_", 34, pattern::is_alnum, &HUGGING_FACE_SIGNALS),
        PrefixShape::exact(
            "api_org_",
            34,
            pattern::is_alnum,
            &HUGGING_FACE_ORGANIZATION_SIGNALS,
        ),
    ],
    boundary: pattern::is_alnum_dash,
};

/// Docker Hub personal (`dckr_pat_`) and organization (`dckr_oat_`) access
/// tokens, validated as separately-sized exact-length shapes (issue #370,
/// `decision-freeze-precision-contracts-seven-provider-families`, Docker row;
/// the second OAT width is issue #708):
///
/// ```text
/// dckr_pat_<27 bytes from [A-Za-z0-9_-]>        (36 bytes total)
/// dckr_oat_<27 or 32 bytes from [A-Za-z0-9_-]>  (36 or 41 bytes total)
/// ```
///
/// Docker's own Hub API reference shows an organization access token with a
/// 27-byte body. The 32-byte width comes from trufflehog only, so both
/// widths are accepted under `dckr_oat_` (#708). Every other length is an
/// intentional false negative rather than a fuzzy match: a 26- or 28-byte
/// suffix after `dckr_pat_`, anything other than 27 or 32 bytes after
/// `dckr_oat_`, or the 32-byte OAT width under the PAT prefix. This follows
/// the same exact-length precedent `npm-token` and `google-api-key` below
/// already set. Only the two
/// documented segment names are matched; an undocumented segment name is an
/// intentional false negative, and legacy Docker Hub passwords (which carry
/// no distinguishing prefix at all) are out of scope for this detector.
const DOCKER_SIGNALS: [&str; 2] = ["docker-documented-prefix", "exact-length-suffix"];

pub(super) const DOCKER: KnownFormatProviderDetector = KnownFormatProviderDetector {
    id: "docker-token",
    type_name: "docker_token",
    shapes: &[
        PrefixShape::exact(
            "dckr_pat_",
            DOCKER_PAT_SUFFIX_LEN,
            pattern::is_alnum_dash,
            &DOCKER_SIGNALS,
        ),
        PrefixShape::one_of(
            "dckr_oat_",
            &DOCKER_OAT_SUFFIX_LENS,
            pattern::is_alnum_dash,
            &DOCKER_SIGNALS,
        ),
    ],
    boundary: pattern::is_alnum_dash,
};

/// The exact suffix length after `dckr_pat_`.
pub(super) const DOCKER_PAT_SUFFIX_LEN: usize = 27;
/// The longer exact suffix length after `dckr_oat_` (trufflehog-corroborated).
pub(super) const DOCKER_OAT_SUFFIX_LEN: usize = 32;
/// Every exact suffix length accepted after `dckr_oat_`: the provider's own
/// 27-byte example width (issue #708) and the 32-byte width.
pub(super) const DOCKER_OAT_SUFFIX_LENS: [usize; 2] =
    [DOCKER_PAT_SUFFIX_LEN, DOCKER_OAT_SUFFIX_LEN];

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
const DIGITALOCEAN_SIGNALS: [&str; 2] =
    ["digitalocean-documented-prefix", "fixed-length-hex-suffix"];

pub(super) const DIGITALOCEAN: KnownFormatProviderDetector = KnownFormatProviderDetector {
    id: "digitalocean-token",
    type_name: "digitalocean_token",
    shapes: &[
        PrefixShape::exact("dop_v1_", 64, pattern::is_lower_hex, &DIGITALOCEAN_SIGNALS),
        PrefixShape::exact("doo_v1_", 64, pattern::is_lower_hex, &DIGITALOCEAN_SIGNALS),
        PrefixShape::exact("dor_v1_", 64, pattern::is_lower_hex, &DIGITALOCEAN_SIGNALS),
    ],
    boundary: pattern::is_alnum_dash,
};

/// Supabase elevated-access secret keys. The `sb_publishable_` prefix is
/// deliberately excluded — it names a public identifier, not a secret —
/// so classifying it would be a false positive; an undocumented prefix is
/// a false negative.
const SUPABASE_SIGNALS: [&str; 2] = ["supabase-secret-prefix", "elevated-access-key"];

pub(super) const SUPABASE: KnownFormatProviderDetector = KnownFormatProviderDetector {
    id: "supabase-token",
    type_name: "supabase_secret_key",
    shapes: &[PrefixShape::at_least(
        "sb_secret_",
        20,
        pattern::is_alnum_dash,
        &SUPABASE_SIGNALS,
    )],
    boundary: pattern::is_alnum_dash,
};

/// Supabase personal access tokens (PATs): a credential class that
/// authenticates the Management API and the tools built on it (the
/// Supabase CLI and MCP server), issued from a project's account settings
/// rather than from a project's own API-keys page.
/// `docs.supabase.com/guides/platform/personal-access-tokens` documents the
/// `sbp_` prefix (by example only, e.g. `sbp_fc...`) and the classic-vs-
/// scoped distinction, but not an exact body grammar.
///
/// `decision-freeze-precision-contracts-seven-provider-families` (Supabase
/// management-token row, issue #515) is explicit that this class must never borrow or lend
/// evidence to `SUPABASE` (`sb_secret_`/`sb_publishable_`, above) or to the
/// legacy JWT anon/service-role carve-out in [`super::jwt`]: a PAT
/// authenticates a Supabase *account*, a secret key authenticates one
/// *project's* data API, and a legacy JWT is a third, structurally
/// unrelated shape. The two-shape body grammar here (`sbp_`/`sbp_v0_`, each
/// followed by exactly 40 [`pattern::is_lower_alnum`] bytes) is instead
/// externally corroborated: it is the shape `TruffleHog`'s own shipped
/// detector (the `supabase` reference this project's benchmark evidence has
/// historically pinned, per issue #515) already matches for the classic
/// `sbp_` prefix. That reference detector's regex is anchored to
/// `[a-z0-9]{40}` and carries no `_` in its character class, so it cannot
/// match the versioned `sbp_v0_` prefix the same docs page's scoped-token
/// walkthrough names — an admitted gap this detector closes as a second
/// [`PrefixShape`] over the identical body grammar, not new matching logic,
/// the same "adopt the sibling prefix, keep the body shape" move
/// `HUGGING_FACE`'s `api_org_` shape already makes above. No `TruffleHog`
/// implementation code is used; only its published match shape is
/// consulted, per `AGENTS.md`.
const SUPABASE_PAT_SIGNALS: [&str; 2] =
    ["supabase-pat-documented-prefix", "tool-corroborated-length"];

pub(super) const SUPABASE_PAT: KnownFormatProviderDetector = KnownFormatProviderDetector {
    id: "supabase-management-token",
    type_name: "supabase_personal_access_token",
    shapes: &[
        PrefixShape::exact(
            "sbp_v0_",
            40,
            pattern::is_lower_alnum,
            &SUPABASE_PAT_SIGNALS,
        ),
        PrefixShape::exact("sbp_", 40, pattern::is_lower_alnum, &SUPABASE_PAT_SIGNALS),
    ],
    boundary: pattern::is_alnum_dash,
};

/// Vercel personal, integration, app, refresh, and API-key credentials. An
/// undocumented prefix letter is an intentional false negative.
const VERCEL_SIGNALS: [&str; 2] = ["vercel-documented-prefix", "opaque-suffix"];

pub(super) const VERCEL: KnownFormatProviderDetector = KnownFormatProviderDetector {
    id: "vercel-token",
    type_name: "vercel_token",
    shapes: &[
        PrefixShape::at_least("vcp_", 20, pattern::is_alnum_dash, &VERCEL_SIGNALS),
        PrefixShape::at_least("vci_", 20, pattern::is_alnum_dash, &VERCEL_SIGNALS),
        PrefixShape::at_least("vca_", 20, pattern::is_alnum_dash, &VERCEL_SIGNALS),
        PrefixShape::at_least("vcr_", 20, pattern::is_alnum_dash, &VERCEL_SIGNALS),
        PrefixShape::at_least("vck_", 20, pattern::is_alnum_dash, &VERCEL_SIGNALS),
    ],
    boundary: pattern::is_alnum_dash,
};

/// npm access tokens. Granular, automation, and legacy read-only tokens all
/// share the same `npm_`-prefixed shape: a fixed 36-byte base62
/// (`[A-Za-z0-9]`) body, the last six bytes of which encode a base62-encoded
/// CRC32 checksum. The suffix is matched as an exact length, not a minimum —
/// a prefix with the token truncated below 36 bytes, or with the `npm_`
/// prefix stripped entirely, is an intentional false negative; the fixed
/// prefix, alphabet, and length keep false-positive risk low.
const NPM_SIGNALS: [&str; 2] = ["npm-documented-prefix", "base62-exact-length"];

pub(super) const NPM: KnownFormatProviderDetector = KnownFormatProviderDetector {
    id: "npm-token",
    type_name: "npm_access_token",
    shapes: &[PrefixShape::exact(
        "npm_",
        36,
        pattern::is_alnum,
        &NPM_SIGNALS,
    )],
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
/// as well as in service-scoped Cloud/Gemini use, and the shape carries no
/// API scope: an unrestricted key on a project with the Generative Language
/// API enabled can call Gemini whatever config object surrounds it. So this
/// detector always reports the shape at `Confidence::High`, and nothing
/// downstream exempts it by context. Issue #520 (B3a) once dropped a match
/// inside a recognized Firebase Web SDK client-config object at the
/// pipeline level; #749 reversed that, so a `firebaseConfig` `apiKey` is
/// reported like any other. The redact/warn action call is left to policy,
/// the same tradeoff npm and the other known-format providers above make.
const GOOGLE_SIGNALS: [&str; 2] = ["google-documented-prefix", "exact-length-suffix"];

pub(super) const GOOGLE: KnownFormatProviderDetector = KnownFormatProviderDetector {
    id: "google-api-key",
    type_name: "google_api_key",
    shapes: &[PrefixShape::exact(
        "AIza",
        35,
        pattern::is_alnum_dash,
        &GOOGLE_SIGNALS,
    )],
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
const GRAFANA_CLOUD_SIGNALS: [&str; 2] =
    ["grafana-cloud-documented-prefix", "base64-opaque-suffix"];

pub(super) const GRAFANA_CLOUD: KnownFormatProviderDetector = KnownFormatProviderDetector {
    id: "grafana-cloud-access-policy-token",
    type_name: "grafana_cloud_access_policy_token",
    shapes: &[PrefixShape::at_least(
        "glc_",
        32,
        pattern::is_base64_body,
        &GRAFANA_CLOUD_SIGNALS,
    )],
    boundary: pattern::is_alnum_dash,
};

/// Pulumi Cloud access tokens (issue #522, B3c): personal, organization, and
/// team credentials, all three sharing one literal prefix and body shape --
/// Pulumi's own REST API reference documents no kind-specific prefix, so
/// (the same "one documented shape, several issuance contexts" reading
/// [`NPM`] above already applies) this is one [`PrefixShape`], not one per
/// token kind.
///
/// **Prefix: provider-documented.** Pulumi's Cloud REST API reference
/// (`pulumi.com/docs/reference/cloud-rest-api/access-tokens/`, observed
/// 2026-09-21) states, of the token-creation response: "The response
/// includes the token ID and the tokenValue (prefixed with 'pul-')." That
/// page, and its `personal-access-tokens` sibling (identical prose, observed
/// the same day), state no length or alphabet for the value that follows.
///
/// **Body: tool-corroborated, not provider-documented.** Two independently
/// maintained tools, consulted only as external behavioral references per
/// `AGENTS.md`, converge on the same shape:
///
/// ```text
/// gitleaks 8.30.1's pulumi-api-token rule:
///   \b(pul-[a-f0-9]{40})(?:[`'"\s;]|\\[nr]|$)
/// pleno-dlp's Pulumi detector (github.com/plenoai/pleno-dlp):
///   "pul- prefix + 40-hex"
/// ```
///
/// Both pin exactly 40 lowercase hexadecimal bytes after the prefix; neither
/// registers any other length or alphabet. A worked, explicitly
/// non-working example (Nelson Figueroa, "How to Tell What Kind of Pulumi
/// Access Token You Have", dev.to, observed 2026-09-21, itself citing
/// gitleaks/trufflehog) shows one 40-lowercase-hex-byte example each for the
/// personal, organization, and team kinds -- consistent with, but not
/// treated as independent of, that tool agreement. A body shorter or longer
/// than 40 bytes, in uppercase hex, or using any other undocumented
/// character is an intentional false negative rather than a fuzzy match,
/// the same exact-length precedent [`DIGITALOCEAN`] and [`NPM`] above
/// already set.
const PULUMI_SIGNALS: [&str; 2] = ["pulumi-documented-prefix", "tool-corroborated-length"];

pub(super) const PULUMI: KnownFormatProviderDetector = KnownFormatProviderDetector {
    id: "pulumi-access-token",
    type_name: "pulumi_access_token",
    shapes: &[PrefixShape::exact(
        "pul-",
        40,
        pattern::is_lower_hex,
        &PULUMI_SIGNALS,
    )],
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
    /// body. The hex-only alphabet admits no `SYNTHETIC…` marker, so each
    /// body is instead an unmistakably patterned hex run — the same
    /// counting idiom [`super::datadog`] and [`super::new_relic`] already use
    /// for their own hex-only bodies — rather than the look-alike random
    /// bytes issue #419 replaced. None was ever provider-issued.
    const DIGITALOCEAN_BODY: &str =
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const DIGITALOCEAN_OAUTH_BODY: &str =
        "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";
    /// Exactly 40 bytes from `[a-z0-9]` (no uppercase, no `_`/`-`): the
    /// tool-corroborated `sbp_`/`sbp_v0_` personal-access-token body length
    /// (issue #515). The lowercase-only alphabet admits no `SYNTHETIC…`
    /// marker, so this is a lowercase, unmistakably patterned synthetic run
    /// instead, the same style [`DIGITALOCEAN_BODY`] uses for its own
    /// narrowed alphabet.
    const SUPABASE_PAT_BODY: &str = "synthetic0revoked1provider2value3padding";
    const _: () = assert!(SUPABASE_PAT_BODY.len() == 40);
    const DIGITALOCEAN_REFRESH_BODY: &str =
        "123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0";
    /// Exactly 40 lowercase hex bytes: the tool-corroborated Pulumi access
    /// token body length (issue #522). The hex-only alphabet admits no
    /// `SYNTHETIC…` marker, so this is the same unmistakably patterned hex
    /// run style [`DIGITALOCEAN_BODY`] uses for its own narrowed alphabet.
    /// None was ever provider-issued.
    const PULUMI_BODY: &str = "0123456789abcdef0123456789abcdef01234567";
    const _: () = assert!(PULUMI_BODY.len() == 40);

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
            family(
                SUPABASE_PAT,
                "sbp_",
                SUPABASE_PAT_BODY,
                "sbp_synthetic0short",
            ),
            family(VERCEL, "vcp_", BODY, "vcp_SYNTHETIC_SHORT"),
            family(NPM, "npm_", NPM_BODY, "npm_SYNTHETICSHORT"),
            family(GOOGLE, "AIza", GOOGLE_BODY, "AIzaSYNTHETICSHORT"),
            family(
                GRAFANA_CLOUD,
                "glc_",
                GRAFANA_CLOUD_BODY,
                "glc_SYNTHETICSHORT",
            ),
            family(PULUMI, "pul-", PULUMI_BODY, "pul-0123456789abcdef"),
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
            // Issue #513: Stripe's sandbox-mode publishable key is
            // documented exactly as safe to expose as its live-mode
            // counterpart (docs.stripe.com/keys, observed 2026-09-20).
            format!("pk_test_{BODY}"),
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

    /// Issue #513: `sk_org_`'s and `whsec_`'s own documented-absence and
    /// separator near misses. `rk_org_` is a direct evidenced negative
    /// (`docs.stripe.com/keys/organization-api-keys`, observed 2026-09-20:
    /// "There's no `rk_org` prefix"), not merely an untested guess; the
    /// remaining cases are missing- or wrong-separator variants of
    /// `sk_org_`/`whsec_`, undocumented near-misses by the same
    /// false-negative-by-design rule as `sk_liv_` above.
    #[test]
    fn rejects_organization_and_webhook_documented_absence_and_separator_near_misses() {
        for input in [
            format!("rk_org_{BODY}"),
            format!("sk_org{BODY}"),
            format!("sk_org-{BODY}"),
            format!("whsec{BODY}"),
            format!("whsec-{BODY}"),
            format!("wh_sec_{BODY}"),
        ] {
            assert_eq!(detect(&STRIPE, &input).len(), 0, "{input}");
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

    /// Issue #513: the same public/secret pairing in sandbox mode. Stripe
    /// documents `pk_test_` as equally safe to expose as `pk_live_`
    /// (docs.stripe.com/keys, observed 2026-09-20), so pairing it with a
    /// real-shaped `sk_test_` secret in the same file must classify only
    /// the secret half, the same as the live-mode pairing above.
    #[test]
    fn classifies_only_the_secret_half_of_a_mixed_public_and_secret_input_in_sandbox_mode() {
        let input = format!("pk_test_SYNTHETICREVOKEDSYNT\nsk_test_{BODY}");
        let candidates = detect(&STRIPE, &input);
        assert_eq!(candidates.len(), 1);
        let expected_start = input.find("sk_test_").unwrap();
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

    /// Issue #551: the shared boundary/delimiter regression set, mirrored
    /// from `digitalocean-token`'s existing leading/trailing/dash
    /// identifier-embedding fixtures, for every `docker-token` and
    /// `digitalocean-token` shape here. `vercel-token` is deliberately
    /// excluded: it is not one of the seven families this issue covers, and
    /// unlike these two it is still an open-floor `RunLength::AtLeast` shape
    /// (opaque suffix, no documented maximum) matched against its own
    /// boundary alphabet, so it carries the same live defect `lin_oauth_`
    /// and Slack's remaining interim guards had (see `super::linear` and
    /// `super::slack`) -- out of scope for a family this issue does not
    /// name.
    #[test]
    fn infra_providers_reject_every_shape_embedded_in_a_wider_identifier_leading_trailing_or_dash_joined()
     {
        for variant in infra_provider_variants()
            .into_iter()
            .filter(|variant| variant.detector.id() != "vercel-token")
        {
            let value = format!("{}{}", variant.prefix, variant.body);
            assert!(
                detect(variant.detector, &format!("legacy{value}")).is_empty(),
                "{} leading",
                variant.detector.id()
            );
            assert!(
                detect(variant.detector, &format!("{value}_backup")).is_empty(),
                "{} trailing",
                variant.detector.id()
            );
            assert!(
                detect(variant.detector, &format!("{value}-1")).is_empty(),
                "{} dash",
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
    fn docker_does_not_accept_the_oat_width_under_the_pat_prefix() {
        let input = format!("dckr_pat_{DOCKER_OAT_BODY}");
        assert_eq!(detect(&DOCKER, &input).len(), 0, "{input}");
    }

    /// Issue #708: Docker's Hub API reference shows an organization access
    /// token with a 27-byte body, so `dckr_oat_` accepts exactly 27 or
    /// exactly 32 bytes. Each width is matched over the full span, and every
    /// width in between, or just outside, is rejected rather than truncated.
    #[test]
    fn docker_oat_accepts_exactly_the_27_and_32_byte_widths() {
        for body in [DOCKER_PAT_BODY, DOCKER_OAT_BODY] {
            let input = format!("DOCKER_TOKEN=dckr_oat_{body}");
            let candidates = detect(&DOCKER, &input);
            assert_eq!(candidates.len(), 1, "len={}", body.len());
            assert_eq!(
                candidates[0].range(),
                ByteRange::new("DOCKER_TOKEN=".len(), input.len()).unwrap(),
                "len={}",
                body.len()
            );
        }
        let padding = "SYNTHETICREVOKEDDOCKERORGTOKEN0000";
        for len in [26usize, 28, 29, 30, 31, 33] {
            let input = format!("dckr_oat_{}", &padding[..len]);
            assert_eq!(detect(&DOCKER, &input).len(), 0, "len={len}");
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

    /// Issue #551: the shared boundary/delimiter regression set, mirrored
    /// from `digitalocean-token`'s existing leading/trailing/dash
    /// identifier-embedding fixtures, for `huggingface-token`'s `hf_` shape.
    #[test]
    fn hf_rejects_every_embedding_shape_leading_trailing_or_dash_joined() {
        let value = format!("hf_{HUGGING_FACE_BODY}");
        assert!(detect(&HUGGING_FACE, &format!("legacy{value}")).is_empty());
        assert!(detect(&HUGGING_FACE, &format!("{value}_backup")).is_empty());
        assert!(detect(&HUGGING_FACE, &format!("{value}-1")).is_empty());
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
    /// (`docs/contracts/precision/precision-contracts.json`, `families.
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

    /// Issue #485: `api_org_` is adopted over the identical `hf_` body
    /// grammar (34-byte `[A-Za-z0-9]`). Detected at exactly the documented
    /// range, and `hf_` stays unaffected by the added shape.
    #[test]
    fn huggingface_organization_token_detects_the_api_org_prefix_at_the_documented_shape() {
        let value = format!("api_org_{HUGGING_FACE_BODY}");
        let candidates = detect(&HUGGING_FACE, &value);
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].type_name(), "huggingface_token");
        assert_eq!(candidates[0].confidence(), Confidence::High);
        assert_eq!(candidates[0].effective_specificity(), Specificity::Provider);
        assert_eq!(
            candidates[0].range(),
            ByteRange::new(0, value.len()).unwrap()
        );

        let user_value = format!("hf_{HUGGING_FACE_BODY}");
        assert_eq!(detect(&HUGGING_FACE, &user_value).len(), 1);
    }

    /// Issue #485: an `api_org_` value and an `hf_` value in the same input
    /// are both reported, at their own ranges, without either shape
    /// swallowing the other.
    #[test]
    fn huggingface_organization_token_and_user_token_are_both_reported_independently() {
        let user_value = format!("hf_{HUGGING_FACE_BODY}");
        let org_value = format!("api_org_{HUGGING_FACE_BODY}");
        let input = format!("{user_value} {org_value}");
        let candidates = detect(&HUGGING_FACE, &input);
        assert_eq!(candidates.len(), 2);
        assert_eq!(
            candidates[0].range(),
            ByteRange::new(0, user_value.len()).unwrap()
        );
        let org_start = input.find(&org_value).unwrap();
        assert_eq!(
            candidates[1].range(),
            ByteRange::new(org_start, org_start + org_value.len()).unwrap()
        );
    }

    /// Issue #485: the frozen contract's exact 34-byte body applies
    /// identically to `api_org_`. A 33-byte body — the `api_org_` twin of
    /// the beta.4 `huggingface-token-user-plain-twin` regression — is an
    /// intentional false negative, and a 35-byte body is not misread as the
    /// exact shape followed by a trailing byte.
    #[test]
    fn huggingface_organization_token_rejects_a_body_one_byte_off_the_documented_length() {
        for body in [
            &HUGGING_FACE_BODY[..HUGGING_FACE_BODY.len() - 1],
            &format!("{HUGGING_FACE_BODY}A"),
        ] {
            let value = format!("api_org_{body}");
            assert_eq!(detect(&HUGGING_FACE, &value).len(), 0, "{value}");
        }
    }

    /// Issue #485: an ordinary identifier that begins `api_org_` but does
    /// not carry the documented 34-byte body (for example, a variable or
    /// key name) does not match.
    #[test]
    fn huggingface_organization_token_rejects_an_ordinary_non_conforming_identifier() {
        for value in ["api_org_name", "api_org_id", "api_org_12345"] {
            assert_eq!(detect(&HUGGING_FACE, value).len(), 0, "{value}");
        }
    }

    /// Issue #485: the prefix embedded in a wider identifier, or the
    /// documented-length body containing `_`/`-`, is rejected for
    /// `api_org_` exactly as it already is for `hf_` (issue #372) — the
    /// same tool-agreed exclusion, not a length shortfall.
    #[test]
    fn huggingface_organization_token_rejects_embedded_prefix_and_underscore_or_dash_in_body() {
        let embedded = format!("legacyapi_org_{HUGGING_FACE_BODY}");
        assert_eq!(detect(&HUGGING_FACE, &embedded).len(), 0);

        for byte in ['_', '-'] {
            let mut body = HUGGING_FACE_BODY.to_string();
            body.replace_range(4..5, &byte.to_string());
            let value = format!("api_org_{body}");
            assert_eq!(detect(&HUGGING_FACE, &value).len(), 0, "{value}");
        }
    }

    /// Issue #551: the shared boundary/delimiter regression set, mirrored
    /// from `digitalocean-token`'s existing leading/trailing/dash
    /// identifier-embedding fixtures, for `huggingface-token`'s `api_org_`
    /// shape.
    #[test]
    fn huggingface_organization_token_rejects_every_embedding_shape_leading_trailing_or_dash_joined()
     {
        let value = format!("api_org_{HUGGING_FACE_BODY}");
        assert!(detect(&HUGGING_FACE, &format!("legacy{value}")).is_empty());
        assert!(detect(&HUGGING_FACE, &format!("{value}_backup")).is_empty());
        assert!(detect(&HUGGING_FACE, &format!("{value}-1")).is_empty());
    }

    /// Issue #485: the `hf_`/`api_org_` alphabet conflict (gitleaks:
    /// letters only; trufflehog: letters and digits) is resolved identically
    /// to `hf_` (issue #372) — the union, as a support-policy choice — so a
    /// digit-bearing `api_org_` body is still accepted.
    #[test]
    fn huggingface_organization_token_accepts_a_digit_bearing_documented_length_body() {
        let mut body = HUGGING_FACE_BODY.to_string();
        body.replace_range(0..2, "42");
        let value = format!("api_org_{body}");
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

    // The reproduced beta.4 failure -- a 63-byte body (the paired positive
    // with its final byte dropped) accepted under the old 20-byte minimum,
    // both bare and in the Unicode/CRLF framing the benchmark used -- is the
    // exact scenario `tests/digitalocean_precision.rs` exists to pin, at
    // both the whole-input and isolated-detector level; not repeated here.

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

    // Issue #522: the Pulumi access token contract. The `pul-` prefix is
    // provider-documented (Pulumi's own Cloud REST API reference); the
    // exact 40-lowercase-hex body is tool-corroborated (gitleaks and
    // pleno-dlp independently agree). Every body below is a locally
    // constructed synthetic value; none was ever provider-issued.

    /// The documented shape, matched at `Confidence::High`,
    /// `Specificity::Provider`, at exactly the token's own range. Personal,
    /// organization, and team tokens share this one literal prefix and body
    /// grammar, so one synthetic body stands in for all three kinds.
    #[test]
    fn pulumi_accepts_exactly_forty_lowercase_hex_bytes() {
        let token = format!("pul-{PULUMI_BODY}");
        assert_eq!(token.len(), 44);
        let candidates = detect(&PULUMI, &token);
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].type_name(), "pulumi_access_token");
        assert_eq!(candidates[0].confidence(), Confidence::High);
        assert_eq!(candidates[0].effective_specificity(), Specificity::Provider);
        assert_eq!(candidates[0].range(), ByteRange::new(0, 44).unwrap());
    }

    /// Length negative twin: gitleaks and pleno-dlp both pin the body to
    /// exactly 40 bytes, so a 39-byte or 41-byte body is an intentional
    /// false negative, not a fuzzy match against a minimum or a truncation
    /// to the documented width.
    #[test]
    fn pulumi_rejects_a_body_one_hex_byte_short_or_long_of_the_documented_length() {
        for body in [
            &PULUMI_BODY[..PULUMI_BODY.len() - 1],
            &format!("{PULUMI_BODY}0"),
        ] {
            let value = format!("pul-{body}");
            assert_eq!(detect(&PULUMI, &value).len(), 0, "{value}");
        }
    }

    /// Alphabet negative twin: both corroborating tools pin the body to
    /// lowercase hex only. An uppercase hex digit, a non-hex letter, or
    /// whitespace inside an otherwise documented-length body is rejected
    /// rather than truncated to its longest valid-alphabet prefix.
    #[test]
    fn pulumi_rejects_uppercase_hex_and_non_hex_bytes_inside_the_body() {
        let token = format!("pul-{PULUMI_BODY}");
        let body_at = |index: usize, replacement: &str| {
            let at = "pul-".len() + index;
            format!("{}{replacement}{}", &token[..at], &token[at + 1..])
        };
        for input in [
            body_at(8, "D"),
            body_at(8, "g"),
            body_at(8, " "),
            body_at(39, "A"),
        ] {
            assert!(detect(&PULUMI, &input).is_empty(), "{input}");
        }
    }

    /// Prefix negative twin: an undocumented near-miss prefix (missing or
    /// wrong separator, wrong case, one letter off, or the documented
    /// prefix embedded in a wider identifier) is a false negative by
    /// design, never a fuzzy match, the same rule this registry's other
    /// documented-prefix families already apply.
    #[test]
    fn pulumi_rejects_undocumented_near_miss_prefixes() {
        for input in [
            format!("pu-{PULUMI_BODY}"),
            format!("pull-{PULUMI_BODY}"),
            format!("pul_{PULUMI_BODY}"),
            format!("pul{PULUMI_BODY}"),
            format!("PUL-{PULUMI_BODY}"),
            format!("legacypul-{PULUMI_BODY}"),
            format!("pul%2D{PULUMI_BODY}"),
        ] {
            assert!(detect(&PULUMI, &input).is_empty(), "{input}");
        }
    }

    /// Benign controls (issue #522): a fully qualified Pulumi stack
    /// reference, a bare project name, `pulumi up`/`pulumi version`-style
    /// CLI output, and a documentation-style `x`-filled placeholder all
    /// carry no `pul-`-prefixed hex run and must stay unclassified.
    #[test]
    fn pulumi_rejects_stack_project_and_version_identifiers_as_benign_controls() {
        for input in [
            "stack: myorg/my-infra-project/production",
            "Updating (dev):\n    pulumi:pulumi:Stack my-infra-project-dev running\nResources: 3 unchanged\nUpdate succeeded in 8s",
            "Previewing update (staging)\n    Type                 Name\n +   pulumi:providers:aws default",
            "pulumi version\nv3.142.0",
            "PULUMI_ACCESS_TOKEN=pul-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
        ] {
            assert!(detect(&PULUMI, input).is_empty(), "{input}");
        }
    }

    /// Quotes, Markdown code spans, and a `KEY=` assignment all bound the
    /// token without joining it, the same boundary behavior `DIGITALOCEAN`
    /// already exercises.
    #[test]
    fn pulumi_bounds_the_token_against_quotes_code_spans_and_assignments() {
        let token = format!("pul-{PULUMI_BODY}");
        for (input, start) in [
            (format!("\"{token}\""), 1),
            (format!("`{token}`"), 1),
            (
                format!("PULUMI_ACCESS_TOKEN={token}"),
                "PULUMI_ACCESS_TOKEN=".len(),
            ),
        ] {
            let candidates = detect(&PULUMI, &input);
            assert_eq!(candidates.len(), 1, "{input}");
            assert_eq!(
                candidates[0].range(),
                ByteRange::new(start, start + token.len()).unwrap(),
                "{input}"
            );
        }
    }
}
