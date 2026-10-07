//! Ordered detector registry.
//!
//! Registration order is a pipeline input: it is the fourth overlap tie
//! breaker and it fixes the order in which detectors run. Built-in detectors
//! are always registered before custom ones.

use std::borrow::Cow;
use std::sync::{Arc, OnceLock};

use crate::detectors::{
    BuiltIn, BuiltInDetector, LiteralMatcher, RequiredLiterals, built_in_entries, built_in_ids,
    common_built_in_entries,
};
use crate::error::{SecretScanError, SecretScanErrorCode};
use crate::limits::WholeInputLimits;
use crate::pii::{PiiSelection, adapter, is_reserved_detector_id};
use crate::pipeline::{scan_and_redact_in, scan_in};
use crate::selection::{DetectionConfigError, DetectionSelection, PlanEntry, plan_selection};
use crate::types::{Detector, Finding, PlaceholderFormatter, Policy, ScanResult, is_identifier};

/// A named, reviewed built-in detector composition
/// (`decision-define-detector-profile-and-pack-contract`).
///
/// A profile is the only unit a caller selects: which detectors exist in
/// each one, and how they are constructed, stays private. `full` is the
/// default and compatibility baseline everywhere; `common` is a strict,
/// order-preserving subset meant for size- or latency-sensitive preventive
/// consumers. A registry built through [`DetectorRegistry::new`] plus
/// [`DetectorRegistry::register`] carries no profile identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Profile {
    /// Every officially supported built-in detector. The default and
    /// compatibility baseline on every surface.
    Full,
    /// Only the format-agnostic `common` pack: detectors that recognize a
    /// published structure or a credential-bearing context rather than one
    /// issuer's token format.
    Common,
}

impl Profile {
    /// The wire name (`"full"`, `"common"`).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Full => "full",
            Self::Common => "common",
        }
    }

    /// Parses a wire name.
    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "full" => Some(Self::Full),
            "common" => Some(Self::Common),
            _ => None,
        }
    }
}

/// The compiled prefilter of a registry: the shared one of a whole profile,
/// or one compiled for the detectors a selection left enabled.
#[derive(Clone, Debug)]
enum Prefilter {
    Shared(&'static LiteralMatcher),
    Owned(Arc<LiteralMatcher>),
}

impl Prefilter {
    fn matcher(&self) -> &LiteralMatcher {
        match self {
            Self::Shared(matcher) => matcher,
            Self::Owned(matcher) => matcher,
        }
    }
}

/// Compiles the matcher over `declared`, one call shape for every registry so
/// the generic `LiteralMatcher::compile` is instantiated once rather than per
/// registry type (it is the same code in every WebAssembly artifact).
fn compile_matcher(declared: Vec<Option<&RequiredLiterals>>) -> Option<LiteralMatcher> {
    LiteralMatcher::compile(declared)
}

/// Drops the entries `keep` rejects and compiles a prefilter over exactly the
/// survivors, so a disabled detector is neither constructed nor prefiltered
/// and the matcher's slots stay aligned with registration order.
fn retain_and_recompile<T>(
    entries: &mut Vec<T>,
    keep: &[bool],
    required: impl Fn(&T) -> Option<&RequiredLiterals>,
) -> Option<Prefilter> {
    let mut flags = keep.iter();
    entries.retain(|_| flags.next().copied().unwrap_or(true));
    compile_matcher(entries.iter().map(required).collect())
        .map(|matcher| Prefilter::Owned(Arc::new(matcher)))
}

/// A detector together with the id captured at registration time.
///
/// The id is read exactly once so a detector whose `id()` is not stable
/// cannot change the public `detector` field of findings after validation.
pub struct RegisteredDetector {
    id: Cow<'static, str>,
    detector: Held,
    /// The literals a built-in detector declared for the shared prefilter
    /// (issue #983). `None` for every custom detector and for built-ins
    /// that run on every call. Private: the declaration is not part of the
    /// public `Detector` contract.
    required: Option<RequiredLiterals>,
}

impl RegisteredDetector {
    /// The validated id.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// The id as stored; borrowed for a built-in.
    pub(crate) const fn id_cow(&self) -> &Cow<'static, str> {
        &self.id
    }

    /// The registered detector.
    #[must_use]
    pub fn detector(&self) -> &dyn Detector {
        match &self.detector {
            Held::BuiltIn(detector) => *detector,
            Held::Pii(detector) => detector.as_ref(),
            Held::Custom(detector) => detector.as_ref(),
        }
    }

    /// The literals this detector declared for the shared prefilter, if any.
    pub(crate) const fn required_literals(&self) -> Option<&RequiredLiterals> {
        self.required.as_ref()
    }
}

/// How a [`RegisteredDetector`] holds its detector: a built-in is a
/// reference into the crate's static table of built-ins, so building a
/// built-in registry constructs and allocates nothing per detector
/// (issue #1043); the PII-domain adapter and a custom detector are owned. The
/// adapter is its own variant because, unlike a custom detector, it is
/// `Send + Sync`: that is what lets [`BuiltInRegistry`] move a built-in-only
/// registry's detectors into a thread-shareable value (issue #1178).
enum Held {
    BuiltIn(BuiltInDetector),
    Pii(Box<dyn Detector + Send + Sync>),
    Custom(Box<dyn Detector>),
}

impl std::fmt::Debug for RegisteredDetector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RegisteredDetector")
            .field("id", &self.id)
            .finish_non_exhaustive()
    }
}

/// An ordered, duplicate-free set of detectors.
///
/// A registry may hold a custom [`Detector`], and that trait carries no
/// `Send` or `Sync` bound, so a `DetectorRegistry` is neither `Send` nor
/// `Sync`: build one per thread. To share one registry across threads, use
/// [`BuiltInRegistry`], which holds only built-in detectors (issue #1178).
/// Both properties below are pinned, so a change to either fails a doctest:
///
/// ```compile_fail,E0277
/// fn assert_send<T: Send>() {}
/// assert_send::<redact_secret::DetectorRegistry>();
/// ```
///
/// ```compile_fail,E0277
/// fn assert_sync<T: Sync>() {}
/// assert_sync::<redact_secret::DetectorRegistry>();
/// ```
///
/// ```
/// fn assert_send_sync<T: Send + Sync>() {}
/// assert_send_sync::<redact_secret::BuiltInRegistry>();
/// ```
#[derive(Debug, Default)]
pub struct DetectorRegistry {
    detectors: Vec<RegisteredDetector>,
    profile: Option<Profile>,
    activation_identity: String,
    /// The detector selection applied when this registry was composed
    /// (issue #1251); [`DetectionSelection::all`] unless
    /// [`Self::with_detection`] ran.
    detection: DetectionSelection,
    /// The PII selection the registry's adapter was built from.
    pii: PiiSelection,
    /// Every built-in's prefilter declaration compiled into one matcher
    /// (issue #1057), indexed by registry position. Set by the profile
    /// constructors, which register the built-ins first; detectors
    /// appended later declare nothing, so it never goes stale. `None` for a
    /// registry with no built-ins, where nothing is declared. A detector
    /// selection recompiles it over the detectors that stay.
    prefilter: Option<Prefilter>,
}

impl DetectorRegistry {
    #[cfg(test)]
    pub(crate) fn with_internal_test_detector(detector: Box<dyn Detector>) -> Self {
        Self {
            detectors: vec![RegisteredDetector {
                id: Cow::Owned(detector.id().to_owned()),
                detector: Held::Custom(detector),
                required: None,
            }],
            profile: None,
            activation_identity: String::new(),
            detection: DetectionSelection::all(),
            pii: PiiSelection::empty(),
            prefilter: None,
        }
    }

    /// Creates an empty registry.
    ///
    /// The low-level path: registering built-ins and custom detectors this
    /// way carries no [`Profile`] identity and no profile guarantee.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            detectors: Vec::new(),
            profile: None,
            activation_identity: String::new(),
            detection: DetectionSelection::all(),
            pii: PiiSelection::empty(),
            prefilter: None,
        }
    }

    /// Creates a registry holding every built-in detector in canonical
    /// order, followed by `custom` in the given order.
    ///
    /// This is the only way to reach the built-in detectors: which ones
    /// exist and how they are constructed is private, so it can change
    /// without breaking a caller. Their order is not: it is the fourth
    /// overlap tie breaker.
    ///
    /// # Examples
    ///
    /// ```
    /// use redact_secret::{DefaultPolicy, DetectorRegistry, scan};
    ///
    /// let registry = DetectorRegistry::with_built_in([])?;
    /// assert!(registry.contains("github-token"));
    ///
    /// let input = "API_KEY=ghp_SYNTHETICREVOKED00000000000000000000";
    /// assert_eq!(scan(input, &registry, &DefaultPolicy)?.len(), 1);
    ///
    /// // An empty registry detects nothing; it is not the built-in set.
    /// assert_eq!(scan(input, &DetectorRegistry::new(), &DefaultPolicy)?.len(), 0);
    /// # Ok::<(), redact_secret::SecretScanError>(())
    /// ```
    ///
    /// # Errors
    ///
    /// Returns [`SecretScanErrorCode::InvalidDetector`] when a custom
    /// detector has a malformed id or repeats an id that is already
    /// registered.
    pub fn with_built_in<I>(custom: I) -> Result<Self, SecretScanError>
    where
        I: IntoIterator<Item = Box<dyn Detector>>,
    {
        static FULL_PREFILTER: OnceLock<Option<LiteralMatcher>> = OnceLock::new();
        let mut registry = Self::new();
        for BuiltIn {
            id,
            detector,
            required,
        } in built_in_entries()
        {
            registry.push_validated_built_in(id, detector, required)?;
        }
        registry.prefilter = registry
            .compile_prefilter(&FULL_PREFILTER)
            .map(Prefilter::Shared);
        for detector in custom {
            registry.push_validated_custom(detector, false)?;
        }
        registry.profile = Some(Profile::Full);
        registry.activation_identity = PiiSelection::default().activation_identity(Profile::Full);
        Ok(registry)
    }

    /// Creates a registry holding the `common` profile's built-in detectors
    /// in canonical order, followed by `custom` in the given order
    /// (`decision-define-detector-profile-and-pack-contract`).
    ///
    /// `common` is a strict, order-preserving subset of `full`: every
    /// `common` detector's candidates, over any input, are exactly its
    /// candidates in [`Self::with_built_in`]. Overlap resolution is global,
    /// so a `common` registry's *findings* can still differ from `full`'s —
    /// removing a `provider` competitor changes which candidate wins.
    ///
    /// # Errors
    ///
    /// Returns [`SecretScanErrorCode::InvalidDetector`] when a custom
    /// detector has a malformed id, repeats an id already registered, or
    /// reuses any `full` built-in id — including a `provider` id this
    /// profile does not itself register. A custom `github-token` inside
    /// `common` would otherwise emit findings under a built-in id with
    /// different behavior.
    pub fn with_common_built_in<I>(custom: I) -> Result<Self, SecretScanError>
    where
        I: IntoIterator<Item = Box<dyn Detector>>,
    {
        static COMMON_PREFILTER: OnceLock<Option<LiteralMatcher>> = OnceLock::new();
        let mut registry = Self::new();
        for BuiltIn {
            id,
            detector,
            required,
        } in common_built_in_entries()
        {
            registry.push_validated_built_in(id, detector, required)?;
        }
        registry.prefilter = registry
            .compile_prefilter(&COMMON_PREFILTER)
            .map(Prefilter::Shared);
        for detector in custom {
            registry.push_validated_custom(detector, true)?;
        }
        registry.profile = Some(Profile::Common);
        registry.activation_identity = PiiSelection::default().activation_identity(Profile::Common);
        Ok(registry)
    }

    /// Creates the `full` credential profile plus the selected PII-domain
    /// adapter in its fixed slot after credentials.
    ///
    /// # Errors
    ///
    /// Returns [`SecretScanErrorCode::InvalidDetector`] if registration fails.
    pub fn with_built_in_and_pii(selection: &PiiSelection) -> Result<Self, SecretScanError> {
        Self::with_built_in([])?.with_pii_and_custom(Profile::Full, selection, std::iter::empty())
    }

    /// Creates the `common` credential profile plus the selected PII-domain
    /// adapter in its fixed slot after credentials.
    ///
    /// # Errors
    ///
    /// Returns [`SecretScanErrorCode::InvalidDetector`] if registration fails.
    pub fn with_common_built_in_and_pii(selection: &PiiSelection) -> Result<Self, SecretScanError> {
        Self::with_common_built_in([])?.with_pii_and_custom(
            Profile::Common,
            selection,
            std::iter::empty(),
        )
    }

    /// Creates `full` + PII + custom detectors, preserving profile identity.
    ///
    /// # Errors
    ///
    /// Returns [`SecretScanErrorCode::InvalidDetector`] for a malformed,
    /// duplicate, built-in, adapter, or internal family id.
    pub fn with_built_in_and_pii_custom<I>(
        selection: &PiiSelection,
        custom: I,
    ) -> Result<Self, SecretScanError>
    where
        I: IntoIterator<Item = Box<dyn Detector>>,
    {
        Self::with_built_in([])?.with_pii_and_custom(Profile::Full, selection, custom)
    }

    /// Creates `common` + PII + custom detectors, preserving profile identity.
    ///
    /// # Errors
    ///
    /// Returns [`SecretScanErrorCode::InvalidDetector`] for a malformed,
    /// duplicate, built-in, adapter, or internal family id.
    pub fn with_common_built_in_and_pii_custom<I>(
        selection: &PiiSelection,
        custom: I,
    ) -> Result<Self, SecretScanError>
    where
        I: IntoIterator<Item = Box<dyn Detector>>,
    {
        Self::with_common_built_in([])?.with_pii_and_custom(Profile::Common, selection, custom)
    }

    /// Adds the PII-domain adapter and `custom` detectors to `self`, a
    /// registry the caller built from exactly one credential profile.
    ///
    /// The caller names the profile's constructor directly rather than
    /// passing a runtime [`Profile`] to dispatch on: a `common` build must
    /// not make the `full` constructor, and with it every `provider`
    /// detector, reachable (#929, the reachability rule of
    /// `decision-define-detector-profile-and-pack-contract`).
    fn with_pii_and_custom<I>(
        self,
        profile: Profile,
        selection: &PiiSelection,
        custom: I,
    ) -> Result<Self, SecretScanError>
    where
        I: IntoIterator<Item = Box<dyn Detector>>,
    {
        debug_assert_eq!(self.profile, Some(profile));
        let mut registry = self;
        if !selection.is_off() {
            registry.detectors.push(RegisteredDetector {
                id: Cow::Borrowed("pii-domain"),
                detector: Held::Pii(adapter(selection)),
                required: None,
            });
        }
        for detector in custom {
            registry.push_validated_custom(detector, true)?;
        }
        registry.profile = Some(profile);
        registry.activation_identity = selection.activation_identity(profile);
        registry.pii = selection.clone();
        Ok(registry)
    }

    /// The matcher compiled from the declarations of the built-ins just
    /// registered, cached in `cache` (issue #1057). A profile constructor
    /// registers the same built-ins in the same order on every call, so the
    /// first registry of each profile compiles it and every later one
    /// reuses it.
    fn compile_prefilter(
        &self,
        cache: &'static OnceLock<Option<LiteralMatcher>>,
    ) -> Option<&'static LiteralMatcher> {
        cache
            .get_or_init(|| {
                compile_matcher(
                    self.detectors
                        .iter()
                        .map(RegisteredDetector::required_literals)
                        .collect(),
                )
            })
            .as_ref()
    }

    /// The compiled prefilter declarations of this registry's built-ins,
    /// indexed by registry position; `None` when it has none.
    pub(crate) fn prefilter(&self) -> Option<&LiteralMatcher> {
        self.prefilter.as_ref().map(Prefilter::matcher)
    }

    /// Which profile this registry was built from, when it carries one.
    ///
    /// `Some` only for a registry built through [`Self::with_built_in`] or
    /// [`Self::with_common_built_in`] and not extended since. A registry
    /// assembled or extended through [`Self::register`] carries no profile
    /// guarantee and reports `None`.
    #[must_use]
    pub const fn profile(&self) -> Option<Profile> {
        self.profile
    }

    /// Canonical credentials/PII activation identity.
    #[must_use]
    pub fn activation_identity(&self) -> &str {
        &self.activation_identity
    }

    /// The detector selection this registry was composed with:
    /// [`DetectionSelection::all`] for every constructor except
    /// [`Self::with_detection`].
    #[must_use]
    pub const fn detection(&self) -> &DetectionSelection {
        &self.detection
    }

    /// The PII selection the registry's adapter was built from.
    pub(crate) const fn pii_selection(&self) -> &PiiSelection {
        &self.pii
    }

    /// The registered built-in ids, in registration order.
    pub(crate) fn built_in_ids(&self) -> impl Iterator<Item = &str> {
        self.detectors
            .iter()
            .filter(|registered| matches!(registered.detector, Held::BuiltIn(_)))
            .map(RegisteredDetector::id)
    }

    /// Applies a detector-id selection to this registry's built-in detectors
    /// (issue #1251, `decision-define-detector-id-selection-and-configuration-replacement-precedence`).
    ///
    /// The selection acts here, when the registry is composed, before the
    /// shared prefilter, candidate collection and overlap resolution: a
    /// disabled detector is not prefiltered, produces no candidate, is no
    /// overlap competitor and adds no retention behavior. The enabled set is
    /// the registry's built-ins in registration order filtered to the
    /// enabled ids, so request order never matters and an enabled detector's
    /// candidates equal its candidates in `full`. The PII adapter and custom
    /// or ruleset detectors are not built-ins: a selection neither names nor
    /// removes them. The activation identity does not change, and the
    /// profile identity is kept as the compatibility baseline.
    ///
    /// Call it on a registry built from one profile constructor, so a
    /// `common` build never makes the `full` constructor reachable; every
    /// id a registry does not hold is judged against the full built-in
    /// table, which is pure data.
    ///
    /// [`DetectionSelection::all`] is a no-op. Applying a selection to a
    /// registry that already carries one narrows it further only through the
    /// ids it still holds; ids removed earlier are `DETECTOR_NOT_INCLUDED`.
    ///
    /// # Errors
    ///
    /// A [`DetectionConfigError`] when an id is repeated, unknown, a `full`
    /// built-in this registry does not hold, or names a PII or custom
    /// detector; or `EMPTY_DETECTION_SET` when the selection leaves the
    /// registry with no detector at all. The registry is consumed either way,
    /// so no half-applied registry exists.
    ///
    /// # Examples
    ///
    /// ```
    /// use redact_secret::{DefaultPolicy, DetectionSelection, DetectorRegistry, scan};
    ///
    /// let registry = DetectorRegistry::with_built_in([])?
    ///     .with_detection(&DetectionSelection::include(["jwt"]))?;
    /// assert_eq!(registry.ids().collect::<Vec<_>>(), ["jwt"]);
    ///
    /// // A provider token is no longer detected: its detector is not enabled.
    /// let input = "API_KEY=ghp_SYNTHETICREVOKED00000000000000000000";
    /// let findings = scan(input, &registry, &DefaultPolicy)?;
    /// assert!(findings.iter().all(|finding| finding.detector() != "github-token"));
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn with_detection(
        mut self,
        selection: &DetectionSelection,
    ) -> Result<Self, DetectionConfigError> {
        if selection.is_all() {
            return Ok(self);
        }
        let plan: Vec<PlanEntry<'_>> = self
            .detectors
            .iter()
            .map(|registered| PlanEntry {
                id: registered.id(),
                built_in: matches!(registered.detector, Held::BuiltIn(_)),
            })
            .collect();
        let keep = plan_selection(selection, &plan)?;
        drop(plan);
        self.prefilter = retain_and_recompile(
            &mut self.detectors,
            &keep,
            RegisteredDetector::required_literals,
        );
        self.detection = selection.clone();
        Ok(self)
    }

    /// Appends `detector`. This path applies no profile's reserved-id rule,
    /// so a successful call clears [`Self::profile`].
    ///
    /// # Errors
    ///
    /// Returns [`SecretScanErrorCode::InvalidDetector`] when the id does
    /// not satisfy [`is_identifier`] or is already registered. The registry
    /// is unchanged on error.
    pub fn register(&mut self, detector: Box<dyn Detector>) -> Result<&mut Self, SecretScanError> {
        self.push_validated_custom(detector, false)?;
        self.profile = None;
        Ok(self)
    }

    /// Reads a custom detector's id once, validates it, and appends.
    /// `reject_built_in_ids` additionally refuses any `full` built-in id.
    fn push_validated_custom(
        &mut self,
        detector: Box<dyn Detector>,
        reject_built_in_ids: bool,
    ) -> Result<(), SecretScanError> {
        let id = detector.id();
        self.validate_id(id, reject_built_in_ids)?;
        self.detectors.push(RegisteredDetector {
            id: Cow::Owned(id.to_owned()),
            detector: Held::Custom(detector),
            required: None,
        });
        Ok(())
    }

    /// Validates a built-in table row's `id` (pinned to the detector's own
    /// `id()` by the detector tests) and appends `detector` under it with
    /// its prefilter declaration `required`. The row supplies the id, so
    /// building a built-in registry calls no detector's `id()` (issue
    /// #1043).
    fn push_validated_built_in(
        &mut self,
        id: &'static str,
        detector: BuiltInDetector,
        required: Option<RequiredLiterals>,
    ) -> Result<(), SecretScanError> {
        self.validate_id(id, false)?;
        self.detectors.push(RegisteredDetector {
            id: Cow::Borrowed(id),
            detector: Held::BuiltIn(detector),
            required,
        });
        Ok(())
    }

    /// Refuses a malformed, reserved, or already registered id, and with
    /// `reject_built_in_ids` any `full` built-in id.
    fn validate_id(&self, id: &str, reject_built_in_ids: bool) -> Result<(), SecretScanError> {
        if !is_identifier(id)
            || is_reserved_detector_id(id)
            || self.contains(id)
            || (reject_built_in_ids && built_in_ids().any(|reserved| reserved == id))
        {
            return Err(SecretScanErrorCode::InvalidDetector.into());
        }
        Ok(())
    }

    /// Detectors in registration order.
    #[must_use]
    pub fn detectors(&self) -> &[RegisteredDetector] {
        &self.detectors
    }

    /// Registered ids in registration order.
    pub fn ids(&self) -> impl Iterator<Item = &str> {
        self.detectors.iter().map(RegisteredDetector::id)
    }

    /// Number of registered detectors.
    #[must_use]
    pub fn len(&self) -> usize {
        self.detectors.len()
    }

    /// `true` when no detector is registered.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.detectors.is_empty()
    }

    /// `true` when a detector with `id` is registered.
    #[must_use]
    pub fn contains(&self, id: &str) -> bool {
        self.detectors.iter().any(|registered| registered.id == id)
    }
}

/// One detector of a [`DetectorSet`], as the pipeline reads it.
#[derive(Clone, Copy)]
pub(crate) struct DetectorEntry<'a> {
    pub(crate) id: &'a Cow<'static, str>,
    pub(crate) detector: &'a dyn Detector,
    /// Whether the detector declared literals for the shared prefilter.
    pub(crate) declares_literals: bool,
}

/// What the pipeline needs from a registry, so one pipeline serves both
/// [`DetectorRegistry`] and [`BuiltInRegistry`] and neither is a copy of the
/// other (issue #1178). Crate-private: it is not an extension point.
pub(crate) trait DetectorSet {
    /// Number of detectors.
    fn detector_count(&self) -> usize;
    /// Detectors in registration order.
    fn detector_entries(&self) -> impl Iterator<Item = DetectorEntry<'_>>;
    /// The compiled prefilter indexed by registration position, if any.
    fn compiled_prefilter(&self) -> Option<&LiteralMatcher>;
}

impl DetectorSet for DetectorRegistry {
    fn detector_count(&self) -> usize {
        self.len()
    }

    fn detector_entries(&self) -> impl Iterator<Item = DetectorEntry<'_>> {
        self.detectors.iter().map(|registered| DetectorEntry {
            id: registered.id_cow(),
            detector: registered.detector(),
            declares_literals: registered.required_literals().is_some(),
        })
    }

    fn compiled_prefilter(&self) -> Option<&LiteralMatcher> {
        Self::prefilter(self)
    }
}

/// How a [`BuiltInRegistry`] holds one detector. Both variants are
/// `Send + Sync` by type, which is what makes the registry shareable.
enum SharedHeld {
    BuiltIn(BuiltInDetector),
    Pii(Box<dyn Detector + Send + Sync>),
}

struct SharedDetector {
    id: Cow<'static, str>,
    detector: SharedHeld,
    required: Option<RequiredLiterals>,
}

impl SharedDetector {
    fn detector(&self) -> &dyn Detector {
        match &self.detector {
            SharedHeld::BuiltIn(detector) => *detector,
            SharedHeld::Pii(detector) => detector.as_ref(),
        }
    }
}

/// A built-in-only detector registry that is `Send + Sync`, so one value can
/// be shared by reference or through an [`Arc`](std::sync::Arc) across
/// threads (issue #1178).
///
/// [`DetectorRegistry`] is `!Send + !Sync` because it may hold a custom
/// [`Detector`], and that trait promises no thread safety; adding a bound to
/// it would break existing custom detectors. This type holds only what the
/// crate itself constructs: the `full` or `common` built-in detectors, and the
/// PII-domain adapter when PII is activated. It accepts no custom detector,
/// so it needs no bound on one. It is immutable after construction: there is
/// no `register`, and nothing a scan reads is written, so concurrent scans
/// need no lock. The shared prefilter is a process-wide `OnceLock` that is
/// compiled once and then only read.
///
/// For the same profile and PII selection, every method returns exactly what
/// the corresponding [`DetectorRegistry`] function returns: findings, ids,
/// order, ranges, output bytes and error codes are the same, because both run
/// one pipeline over the same detector table. Use [`DetectorRegistry`] for
/// custom detectors or rulesets, and for [`IncrementalSanitizer`], which owns
/// its own registry per session.
///
/// A `Policy` or `PlaceholderFormatter` you pass to a method is used on the
/// calling thread and needs no thread-safety bound.
///
/// [`IncrementalSanitizer`]: crate::IncrementalSanitizer
///
/// # Examples
///
/// ```
/// use std::sync::Arc;
///
/// use redact_secret::{BuiltInRegistry, DefaultPolicy, default_placeholder_formatter};
///
/// // Build once; clone the `Arc` into every worker.
/// let registry = Arc::new(BuiltInRegistry::with_built_in()?);
/// fn assert_send_sync<T: Send + Sync>(_: &T) {}
/// assert_send_sync(&registry);
///
/// let result = registry.scan_and_redact(
///     "API_KEY=ghp_SYNTHETICREVOKED00000000000000000000",
///     &DefaultPolicy,
///     &default_placeholder_formatter,
/// )?;
/// assert_eq!(result.text(), "API_KEY=<SECRET_1>");
/// # Ok::<(), redact_secret::SecretScanError>(())
/// ```
pub struct BuiltInRegistry {
    detectors: Vec<SharedDetector>,
    profile: Profile,
    activation_identity: String,
    detection: DetectionSelection,
    prefilter: Option<Prefilter>,
}

impl BuiltInRegistry {
    /// Moves the detectors of a registry that was built from a profile
    /// constructor with no custom detector into a shareable value. A custom
    /// detector or a registry without a profile cannot be shared and yields
    /// [`SecretScanErrorCode::InvalidDetector`]; the public constructors
    /// below never pass one.
    fn from_built_in_only(registry: DetectorRegistry) -> Result<Self, SecretScanError> {
        let invalid = || SecretScanError::from(SecretScanErrorCode::InvalidDetector);
        let profile = registry.profile.ok_or_else(invalid)?;
        let mut detectors = Vec::with_capacity(registry.detectors.len());
        for registered in registry.detectors {
            let held = match registered.detector {
                Held::BuiltIn(detector) => SharedHeld::BuiltIn(detector),
                Held::Pii(detector) => SharedHeld::Pii(detector),
                Held::Custom(_) => return Err(invalid()),
            };
            detectors.push(SharedDetector {
                id: registered.id,
                detector: held,
                required: registered.required,
            });
        }
        Ok(Self {
            detectors,
            profile,
            activation_identity: registry.activation_identity,
            detection: registry.detection,
            prefilter: registry.prefilter,
        })
    }

    /// The `full` built-in detectors with PII off: the shareable form of
    /// [`DetectorRegistry::with_built_in`] with no custom detectors.
    ///
    /// # Errors
    ///
    /// Returns [`SecretScanErrorCode::InvalidDetector`] only if the built-in
    /// table itself is malformed, which cannot happen in a released build.
    pub fn with_built_in() -> Result<Self, SecretScanError> {
        Self::from_built_in_only(DetectorRegistry::with_built_in([])?)
    }

    /// The `common` built-in detectors with PII off: the shareable form of
    /// [`DetectorRegistry::with_common_built_in`] with no custom detectors.
    /// A `common` handle never makes the `full` constructor reachable from
    /// this call.
    ///
    /// # Errors
    ///
    /// See [`Self::with_built_in`].
    pub fn with_common_built_in() -> Result<Self, SecretScanError> {
        Self::from_built_in_only(DetectorRegistry::with_common_built_in([])?)
    }

    /// The `full` built-in detectors plus the PII-domain adapter selected by
    /// `selection`: the shareable form of
    /// [`DetectorRegistry::with_built_in_and_pii`].
    ///
    /// # Errors
    ///
    /// See [`Self::with_built_in`].
    pub fn with_built_in_and_pii(selection: &PiiSelection) -> Result<Self, SecretScanError> {
        Self::from_built_in_only(DetectorRegistry::with_built_in_and_pii(selection)?)
    }

    /// The `common` built-in detectors plus the PII-domain adapter selected
    /// by `selection`: the shareable form of
    /// [`DetectorRegistry::with_common_built_in_and_pii`].
    ///
    /// # Errors
    ///
    /// See [`Self::with_built_in`].
    pub fn with_common_built_in_and_pii(selection: &PiiSelection) -> Result<Self, SecretScanError> {
        Self::from_built_in_only(DetectorRegistry::with_common_built_in_and_pii(selection)?)
    }

    /// The profile this registry was built from. Always present, unlike
    /// [`DetectorRegistry::profile`]: nothing can be registered afterwards.
    #[must_use]
    pub const fn profile(&self) -> Profile {
        self.profile
    }

    /// Canonical credentials/PII activation identity, the same string
    /// [`DetectorRegistry::activation_identity`] reports for the same
    /// profile and selection.
    #[must_use]
    pub fn activation_identity(&self) -> &str {
        &self.activation_identity
    }

    /// The detector selection this registry was composed with;
    /// [`DetectionSelection::all`] unless [`Self::with_detection`] ran.
    #[must_use]
    pub const fn detection(&self) -> &DetectionSelection {
        &self.detection
    }

    /// Applies a detector-id selection, exactly as
    /// [`DetectorRegistry::with_detection`] does: before the prefilter and
    /// overlap, in canonical order, rejecting an unknown, not-included or
    /// repeated id and an empty result. The shareable value stays immutable
    /// afterwards.
    ///
    /// # Errors
    ///
    /// See [`DetectorRegistry::with_detection`].
    pub fn with_detection(
        mut self,
        selection: &DetectionSelection,
    ) -> Result<Self, DetectionConfigError> {
        if selection.is_all() {
            return Ok(self);
        }
        let plan: Vec<PlanEntry<'_>> = self
            .detectors
            .iter()
            .map(|registered| PlanEntry {
                id: registered.id.as_ref(),
                built_in: matches!(registered.detector, SharedHeld::BuiltIn(_)),
            })
            .collect();
        let keep = plan_selection(selection, &plan)?;
        drop(plan);
        self.prefilter = retain_and_recompile(&mut self.detectors, &keep, |registered| {
            registered.required.as_ref()
        });
        self.detection = selection.clone();
        Ok(self)
    }

    /// Registered ids in registration order.
    pub fn ids(&self) -> impl Iterator<Item = &str> {
        self.detectors
            .iter()
            .map(|registered| registered.id.as_ref())
    }

    /// Number of registered detectors.
    #[must_use]
    pub fn len(&self) -> usize {
        self.detectors.len()
    }

    /// `true` when no detector is registered. Never the case for a value
    /// built by this type's constructors.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.detectors.is_empty()
    }

    /// `true` when a detector with `id` is registered.
    #[must_use]
    pub fn contains(&self, id: &str) -> bool {
        self.detectors.iter().any(|registered| registered.id == id)
    }

    /// [`scan`](crate::scan) over this registry.
    ///
    /// # Errors
    ///
    /// The errors [`scan`](crate::scan) reports.
    pub fn scan(&self, input: &str, policy: &dyn Policy) -> Result<Vec<Finding>, SecretScanError> {
        self.scan_with_limits(input, policy, &WholeInputLimits::default())
    }

    /// [`scan_with_limits`](crate::scan_with_limits) over this registry.
    ///
    /// # Errors
    ///
    /// The errors [`scan_with_limits`](crate::scan_with_limits) reports.
    pub fn scan_with_limits(
        &self,
        input: &str,
        policy: &dyn Policy,
        limits: &WholeInputLimits,
    ) -> Result<Vec<Finding>, SecretScanError> {
        scan_in(input, self, policy, limits)
    }

    /// [`scan_and_redact`](crate::scan_and_redact) over this registry.
    ///
    /// # Errors
    ///
    /// The errors [`scan_and_redact`](crate::scan_and_redact) reports.
    pub fn scan_and_redact(
        &self,
        input: &str,
        policy: &dyn Policy,
        formatter: &dyn PlaceholderFormatter,
    ) -> Result<ScanResult, SecretScanError> {
        self.scan_and_redact_with_limits(input, policy, formatter, &WholeInputLimits::default())
    }

    /// [`scan_and_redact_with_limits`](crate::scan_and_redact_with_limits)
    /// over this registry.
    ///
    /// # Errors
    ///
    /// The errors
    /// [`scan_and_redact_with_limits`](crate::scan_and_redact_with_limits)
    /// reports.
    pub fn scan_and_redact_with_limits(
        &self,
        input: &str,
        policy: &dyn Policy,
        formatter: &dyn PlaceholderFormatter,
        limits: &WholeInputLimits,
    ) -> Result<ScanResult, SecretScanError> {
        scan_and_redact_in(input, self, policy, formatter, limits)
    }
}

impl DetectorSet for BuiltInRegistry {
    fn detector_count(&self) -> usize {
        self.detectors.len()
    }

    fn detector_entries(&self) -> impl Iterator<Item = DetectorEntry<'_>> {
        self.detectors.iter().map(|registered| DetectorEntry {
            id: &registered.id,
            detector: registered.detector(),
            declares_literals: registered.required.is_some(),
        })
    }

    fn compiled_prefilter(&self) -> Option<&LiteralMatcher> {
        self.prefilter.as_ref().map(Prefilter::matcher)
    }
}

impl std::fmt::Debug for BuiltInRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BuiltInRegistry")
            .field("profile", &self.profile)
            .field("detectors", &self.detectors.len())
            .finish_non_exhaustive()
    }
}

// The point of the type, checked at compile time: a change that makes a held
// detector, the prefilter or any field non-shareable fails the build instead
// of silently dropping the guarantee. `DetectorRegistry` stays
// `!Send + !Sync` (the compile-fail doctest on `DetectorRegistry`).
const _: () = {
    const fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<BuiltInRegistry>();
};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detectors::{built_in_detectors, common_built_in_detectors};
    use crate::error::DetectorFailure;
    use crate::types::{Candidate, DetectorContext};

    struct Named(&'static str);

    impl Detector for Named {
        fn id(&self) -> &str {
            self.0
        }

        fn detect(&self, _: &str, _: &DetectorContext) -> Result<Vec<Candidate>, DetectorFailure> {
            Ok(Vec::new())
        }
    }

    /// Only a built-in constructed by this crate carries a prefilter
    /// declaration (issue #983). A custom detector never does, even one
    /// that reuses a built-in id on the low-level path, so it always runs.
    #[test]
    fn only_crate_built_ins_carry_prefilter_declarations() {
        let full =
            DetectorRegistry::with_built_in([Box::new(Named("custom")) as Box<dyn Detector>])
                .unwrap();
        let declared = |registry: &DetectorRegistry, id: &str| {
            registry
                .detectors()
                .iter()
                .find(|registered| registered.id() == id)
                .unwrap()
                .required_literals()
                .is_some()
        };
        assert!(declared(&full, "github-token"));
        assert!(!declared(&full, "generic-token"));
        assert!(!declared(&full, "custom"));

        let mut low_level = DetectorRegistry::new();
        low_level.register(Box::new(Named("github-token"))).unwrap();
        assert!(!declared(&low_level, "github-token"));

        let pii = DetectorRegistry::with_built_in_and_pii(&PiiSelection::default()).unwrap();
        assert!(pii.detectors().iter().all(|registered| {
            registered.id() != "pii-domain" || registered.required_literals().is_none()
        }));
    }

    #[test]
    fn preserves_registration_order() {
        let mut registry = DetectorRegistry::new();
        registry
            .register(Box::new(Named("zeta")))
            .unwrap()
            .register(Box::new(Named("alpha")))
            .unwrap()
            .register(Box::new(Named("mid.point-1_a")))
            .unwrap();
        assert_eq!(
            registry.ids().collect::<Vec<_>>(),
            ["zeta", "alpha", "mid.point-1_a"]
        );
        assert_eq!(registry.len(), 3);
        assert!(!registry.is_empty());
        assert!(registry.contains("alpha"));
        assert!(!registry.contains("beta"));
        assert_eq!(registry.detectors()[1].detector().id(), "alpha");
    }

    #[test]
    fn rejects_malformed_and_duplicate_ids() {
        let mut registry = DetectorRegistry::new();
        registry.register(Box::new(Named("dup"))).unwrap();
        for id in ["", "Dup", "dup", "1x", "a--b", "a-", " a"] {
            let error = registry.register(Box::new(Named(id))).unwrap_err();
            assert_eq!(error.code(), SecretScanErrorCode::InvalidDetector);
            assert_eq!(error.to_string(), "Invalid detector registration.");
        }
        assert_eq!(registry.len(), 1);
    }

    #[test]
    fn rejects_ids_over_the_length_limit() {
        let long = "a".repeat(crate::MAX_IDENTIFIER_LENGTH + 1).leak();
        let mut registry = DetectorRegistry::new();
        let error = registry.register(Box::new(Named(long))).unwrap_err();
        assert_eq!(error.code(), SecretScanErrorCode::InvalidDetector);
    }

    #[test]
    fn built_in_come_first() {
        let registry =
            DetectorRegistry::with_built_in([Box::new(Named("custom")) as Box<dyn Detector>])
                .unwrap();
        let built_in: Vec<String> = built_in_detectors()
            .iter()
            .map(|d| d.id().to_owned())
            .collect();
        let ids: Vec<&str> = registry.ids().collect();
        assert_eq!(ids.len(), built_in.len() + 1);
        assert_eq!(ids[..built_in.len()], built_in);
        assert_eq!(ids[built_in.len()], "custom");
    }

    #[test]
    fn common_built_in_come_first() {
        // Whether `common_built_in_detectors()`'s ids are themselves an
        // order-preserving subsequence of `built_in_detectors()`'s is
        // `detectors::mod`'s own invariant
        // (`common_built_in_detectors_are_exactly_the_common_pack_in_canonical_order`);
        // this test owns only what `with_common_built_in` itself does with
        // whatever that list is: register it first, then `custom`.
        let registry =
            DetectorRegistry::with_common_built_in(
                [Box::new(Named("custom")) as Box<dyn Detector>],
            )
            .unwrap();
        let common: Vec<String> = common_built_in_detectors()
            .iter()
            .map(|d| d.id().to_owned())
            .collect();
        let ids: Vec<&str> = registry.ids().collect();
        assert_eq!(ids.len(), common.len() + 1);
        assert_eq!(ids[..common.len()], common);
        assert_eq!(ids[common.len()], "custom");
    }

    // `with_common_built_in`'s rejection of a custom detector that reuses a
    // reserved id — either a `provider`-only id or an already-registered
    // `common` id — is a public-API-level contract, covered by
    // `tests/public_api.rs`'s
    // `common_registry_rejects_a_custom_detector_that_reuses_a_full_built_in_id`,
    // not repeated here.

    #[test]
    fn profile_identity_matches_how_the_registry_was_built() {
        assert_eq!(DetectorRegistry::new().profile(), None);
        assert_eq!(
            DetectorRegistry::with_built_in([]).unwrap().profile(),
            Some(Profile::Full)
        );
        assert_eq!(
            DetectorRegistry::with_common_built_in([])
                .unwrap()
                .profile(),
            Some(Profile::Common)
        );
    }

    #[test]
    fn extending_a_profile_registry_clears_its_profile_identity() {
        let mut registry = DetectorRegistry::with_common_built_in([]).unwrap();
        registry.register(Box::new(Named("github-token"))).unwrap();
        assert_eq!(registry.profile(), None);

        let mut rejected = DetectorRegistry::with_common_built_in([]).unwrap();
        rejected.register(Box::new(Named("Bad"))).unwrap_err();
        assert_eq!(rejected.profile(), Some(Profile::Common));
    }

    #[test]
    fn a_profile_constructor_reads_a_custom_id_once() {
        struct Flipping(std::sync::atomic::AtomicUsize);

        impl Detector for Flipping {
            fn id(&self) -> &str {
                if self.0.fetch_add(1, std::sync::atomic::Ordering::Relaxed) == 0 {
                    "github-token"
                } else {
                    "custom-token"
                }
            }

            fn detect(
                &self,
                _: &str,
                _: &DetectorContext,
            ) -> Result<Vec<Candidate>, DetectorFailure> {
                Ok(Vec::new())
            }
        }

        let error = DetectorRegistry::with_common_built_in([Box::new(Flipping(
            std::sync::atomic::AtomicUsize::new(0),
        )) as Box<dyn Detector>])
        .unwrap_err();
        assert_eq!(error.code(), SecretScanErrorCode::InvalidDetector);
    }

    #[test]
    fn profile_wire_names_round_trip() {
        for (profile, name) in [(Profile::Full, "full"), (Profile::Common, "common")] {
            assert_eq!(profile.as_str(), name);
            assert_eq!(Profile::from_name(name), Some(profile));
        }
        assert_eq!(Profile::from_name("tiny"), None);
    }

    #[test]
    fn common_detectors_produce_the_same_candidates_as_in_full() {
        let full = DetectorRegistry::with_built_in([]).unwrap();
        let common = DetectorRegistry::with_common_built_in([]).unwrap();
        let inputs = [
            "-----BEGIN PRIVATE KEY-----\nU1lOVEhFVElDX1JFVk9LRUQ=\n-----END PRIVATE KEY-----",
            "eyJhbGciOiJIUzI1NiJ9.SYNTHETIC_REVOKED_PAYLOAD.SYNTHETIC_REVOKED_SIGNATURE",
            "Authorization: Bearer SYNTHETIC_REVOKED_BEARER_TOKEN_VALUE_0001",
            "postgres://user:SYNTHETIC_REVOKED_PASSWORD@example.test:5432/db",
            "otpauth://totp/Example:alice@example.test?secret=SYNTHETICREVOKEDSECRET&issuer=Example",
            "API_KEY=SYNTHETIC_REVOKED_GENERIC_TOKEN_VALUE_0001234567890",
        ];
        for input in inputs {
            let context = DetectorContext::new(input.len());
            for id in common.ids() {
                let full_detector = full
                    .detectors()
                    .iter()
                    .find(|registered| registered.id() == id)
                    .unwrap();
                let common_detector = common
                    .detectors()
                    .iter()
                    .find(|registered| registered.id() == id)
                    .unwrap();
                assert_eq!(
                    full_detector.detector().detect(input, &context).unwrap(),
                    common_detector.detector().detect(input, &context).unwrap(),
                    "{id}: {input}",
                );
            }
        }
    }

    #[test]
    fn debug_output_shows_only_ids() {
        let mut registry = DetectorRegistry::new();
        registry.register(Box::new(Named("only"))).unwrap();
        let rendered = format!("{registry:?}");
        assert!(rendered.contains("only"));
        assert!(rendered.contains(".."));
    }

    #[test]
    fn pii_adapter_has_one_fixed_slot_and_reserved_identity() {
        let selection = PiiSelection::parse(&["pii"]).unwrap();
        let mut full = DetectorRegistry::with_built_in_and_pii(&selection).unwrap();
        assert_eq!(full.ids().collect::<Vec<_>>().last(), Some(&"pii-domain"));
        assert_eq!(full.profile(), Some(Profile::Full));
        assert_eq!(
            full.activation_identity(),
            "credentials=full;selectors=pii:global;families=pii:global:email,pii:global:iban,pii:global:network-address,pii:global:payment-card,pii:global:phone;vocabulary=pii-context/v2"
        );
        assert_eq!(
            full.register(Box::new(Named("pii-domain")))
                .unwrap_err()
                .code(),
            SecretScanErrorCode::InvalidDetector
        );
        assert_eq!(full.profile(), Some(Profile::Full));
    }

    #[test]
    fn legacy_profile_constructors_remain_pii_off() {
        let full = DetectorRegistry::with_built_in([]).unwrap();
        assert!(!full.contains("pii-domain"));
        assert_eq!(
            full.activation_identity(),
            "credentials=full;selectors=off;families=;vocabulary=pii-context/v2"
        );
    }
}
