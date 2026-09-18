//! Ordered detector registry.
//!
//! Registration order is a pipeline input: it is the fourth overlap tie
//! breaker and it fixes the order in which detectors run. Built-in detectors
//! are always registered before custom ones.

use crate::detectors::{built_in_detectors, built_in_ids, common_built_in_detectors};
use crate::error::{SecretScanError, SecretScanErrorCode};
use crate::types::{Detector, is_identifier};

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

/// A detector together with the id captured at registration time.
///
/// The id is read exactly once so a detector whose `id()` is not stable
/// cannot change the public `detector` field of findings after validation.
pub struct RegisteredDetector {
    id: String,
    detector: Box<dyn Detector>,
}

impl RegisteredDetector {
    /// The validated id.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// The registered detector.
    #[must_use]
    pub fn detector(&self) -> &dyn Detector {
        self.detector.as_ref()
    }
}

impl std::fmt::Debug for RegisteredDetector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RegisteredDetector")
            .field("id", &self.id)
            .finish_non_exhaustive()
    }
}

/// An ordered, duplicate-free set of detectors.
#[derive(Debug, Default)]
pub struct DetectorRegistry {
    detectors: Vec<RegisteredDetector>,
    profile: Option<Profile>,
}

impl DetectorRegistry {
    /// Creates an empty registry.
    ///
    /// The low-level path: registering built-ins and custom detectors this
    /// way carries no [`Profile`] identity and no profile guarantee.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            detectors: Vec::new(),
            profile: None,
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
        let mut registry = Self::new();
        for detector in built_in_detectors() {
            registry.push_validated(detector, false)?;
        }
        for detector in custom {
            registry.push_validated(detector, false)?;
        }
        registry.profile = Some(Profile::Full);
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
        let mut registry = Self::new();
        for detector in common_built_in_detectors() {
            registry.push_validated(detector, false)?;
        }
        for detector in custom {
            registry.push_validated(detector, true)?;
        }
        registry.profile = Some(Profile::Common);
        Ok(registry)
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

    /// Appends `detector`. This path applies no profile's reserved-id rule,
    /// so a successful call clears [`Self::profile`].
    ///
    /// # Errors
    ///
    /// Returns [`SecretScanErrorCode::InvalidDetector`] when the id does
    /// not satisfy [`is_identifier`] or is already registered. The registry
    /// is unchanged on error.
    pub fn register(&mut self, detector: Box<dyn Detector>) -> Result<&mut Self, SecretScanError> {
        self.push_validated(detector, false)?;
        self.profile = None;
        Ok(self)
    }

    /// Reads the id once, validates it, and appends. `reject_built_in_ids`
    /// additionally refuses any `full` built-in id.
    fn push_validated(
        &mut self,
        detector: Box<dyn Detector>,
        reject_built_in_ids: bool,
    ) -> Result<(), SecretScanError> {
        let id = detector.id();
        if !is_identifier(id)
            || self.contains(id)
            || (reject_built_in_ids && built_in_ids().any(|reserved| reserved == id))
        {
            return Err(SecretScanErrorCode::InvalidDetector.into());
        }
        self.detectors.push(RegisteredDetector {
            id: id.to_owned(),
            detector,
        });
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

#[cfg(test)]
mod tests {
    use super::*;
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
    fn common_built_in_come_first_and_are_an_ordered_subset_of_full() {
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

        let full: Vec<String> = built_in_detectors()
            .iter()
            .map(|d| d.id().to_owned())
            .collect();
        let mut cursor = 0;
        for id in &common {
            let found = full[cursor..].iter().position(|f| f == id).unwrap();
            cursor += found + 1;
        }
    }

    #[test]
    fn common_rejects_a_custom_detector_that_reuses_any_full_built_in_id() {
        // "github-token" is a `provider` id, never registered by `common`
        // itself, but still reserved.
        let error = DetectorRegistry::with_common_built_in([
            Box::new(Named("github-token")) as Box<dyn Detector>
        ])
        .unwrap_err();
        assert_eq!(error.code(), SecretScanErrorCode::InvalidDetector);

        // "private-key" is a `common` id the profile already registers.
        let error = DetectorRegistry::with_common_built_in([
            Box::new(Named("private-key")) as Box<dyn Detector>
        ])
        .unwrap_err();
        assert_eq!(error.code(), SecretScanErrorCode::InvalidDetector);
    }

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
}
