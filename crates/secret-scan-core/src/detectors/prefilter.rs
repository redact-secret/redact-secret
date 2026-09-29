//! A shared literal prefilter for built-in detectors (issue #983).
//!
//! Most built-in detectors can only propose a candidate when the scan copy
//! contains one of a few case-sensitive literals: a provider prefix
//! (`ghp_`), a marker (`.atlasv1.`) or a separator pair. Each such detector
//! declares those literals when it is registered ([`RequiredLiterals`]),
//! and the pipeline builds one [`PairSet`] of the scan copy's byte pairs per
//! call. A detector none of whose literals can occur is skipped: it would
//! have searched the whole input and returned nothing.
//!
//! The test is conservative. A literal counts as possibly present when every
//! one of its consecutive byte pairs is in the set, and the set is a small
//! hashed bitset, so a collision or pairs from different places only make a
//! detector run when it did not need to. A detector is skipped only when
//! some pair of each of its literals occurs nowhere in the input, and then
//! no literal can occur either.
//!
//! The declaration is private to the registry. It is never read from the
//! public `Detector` trait, so custom detectors, and the built-ins that
//! cannot name such a literal (`generic-token`, keyword-gated detectors,
//! bare-shape detectors such as `discord`), always run.

/// Bits in a [`PairSet`]. A power of two, so the hash keeps its top bits.
const PAIR_SET_BITS: usize = 1024;

/// How far [`pair_slot`] shifts its product to keep `log2(PAIR_SET_BITS)`
/// bits.
const PAIR_SLOT_SHIFT: u32 = u32::BITS - PAIR_SET_BITS.trailing_zeros();

/// The bitset slot of the byte pair `(first, second)`: a multiplicative
/// hash of the pair's 16-bit value.
fn pair_slot(first: u8, second: u8) -> usize {
    let pair = u32::from(u16::from_le_bytes([first, second]));
    // The top bits of a product by an odd constant (Fibonacci hashing).
    (pair.wrapping_mul(0x9E37_79B1) >> PAIR_SLOT_SHIFT) as usize
}

/// Which adjacent byte pairs occur in one scan copy, as a hashed bitset.
///
/// A 1024-bit set costs 128 bytes to clear, which matters because an
/// incremental session builds one per closed line; a full 65,536-bit pair
/// table would cost 8 KiB per line.
pub(crate) struct PairSet {
    bits: [u64; PAIR_SET_BITS / 64],
}

impl PairSet {
    /// The pairs of `text`.
    pub(crate) fn of(text: &[u8]) -> Self {
        let mut bits = [0u64; PAIR_SET_BITS / 64];
        for pair in text.windows(2) {
            let slot = pair_slot(pair[0], pair[1]);
            bits[slot / 64] |= 1 << (slot % 64);
        }
        Self { bits }
    }

    /// `false` only when the pair `(first, second)` occurs nowhere in the
    /// text.
    fn may_contain(&self, first: u8, second: u8) -> bool {
        let slot = pair_slot(first, second);
        self.bits[slot / 64] & (1 << (slot % 64)) != 0
    }

    /// `false` only when `literal` cannot occur in the text: one of its
    /// consecutive pairs occurs nowhere.
    fn may_contain_literal(&self, literal: &[u8]) -> bool {
        literal
            .windows(2)
            .all(|pair| self.may_contain(pair[0], pair[1]))
    }
}

/// The case-sensitive literals at least one of which occurs in the scan
/// copy whenever a detector proposes any candidate.
///
/// Every literal has at least two bytes: a one-byte literal has no pair to
/// test. [`Self::any_of`] refuses such a list, and the detector then always
/// runs.
#[derive(Debug, Clone)]
pub(crate) struct RequiredLiterals {
    literals: Box<[&'static [u8]]>,
}

impl RequiredLiterals {
    /// A declaration from `literals`, or `None` (always run the detector)
    /// when the list is empty or holds a literal shorter than two bytes.
    pub(crate) fn any_of<I>(literals: I) -> Option<Self>
    where
        I: IntoIterator<Item = &'static [u8]>,
    {
        let literals: Box<[&'static [u8]]> = literals.into_iter().collect();
        if literals.is_empty() || literals.iter().any(|literal| literal.len() < 2) {
            return None;
        }
        Some(Self { literals })
    }

    /// `false` only when no declared literal can occur in the text `pairs`
    /// was built from.
    pub(crate) fn may_match(&self, pairs: &PairSet) -> bool {
        self.literals
            .iter()
            .any(|literal| pairs.may_contain_literal(literal))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_literal_is_possible_exactly_when_all_its_pairs_occur() {
        let pairs = PairSet::of(b"xx re_ yy");
        assert!(pairs.may_contain_literal(b"re_"));
        // `re` alone occurs, `e_` alone occurs, but `ab` does not.
        assert!(!pairs.may_contain_literal(b"ab"));
        let split = PairSet::of(b"re e_");
        // Both pairs occur, apart: a false positive the prefilter allows.
        assert!(split.may_contain_literal(b"re_"));
        let neither = PairSet::of(b"r e _");
        assert!(!neither.may_contain_literal(b"re_"));
    }

    #[test]
    fn every_occurring_literal_is_reported_possible() {
        let text = b"prefix ghp_ AKIA sk-proj- xoxb- .atlasv1. 0: \xff\x00 end";
        let pairs = PairSet::of(text);
        for start in 0..text.len() {
            for end in start + 2..=text.len() {
                assert!(pairs.may_contain_literal(&text[start..end]));
            }
        }
    }

    #[test]
    fn declarations_refuse_short_or_empty_literal_lists() {
        assert!(RequiredLiterals::any_of([]).is_none());
        assert!(RequiredLiterals::any_of([b"ghp_".as_slice(), b"x"]).is_none());
        assert!(RequiredLiterals::any_of([b"ghp_".as_slice(), b"gho_"]).is_some());
    }

    #[test]
    fn a_declaration_matches_when_any_literal_may_occur() {
        let required = RequiredLiterals::any_of([b"ghp_".as_slice(), b"glpat-"]).unwrap();
        assert!(required.may_match(&PairSet::of(b"token glpat-abc")));
        assert!(!required.may_match(&PairSet::of(b"plain prose only")));
        assert!(!required.may_match(&PairSet::of(b"")));
    }

    use crate::detectors::{built_in_entries, common_built_in_entries};

    #[test]
    fn full_declares_75_detectors_and_common_4() {
        let declared = |entries: Vec<super::super::BuiltIn>| {
            entries
                .iter()
                .filter(|entry| entry.required.is_some())
                .count()
        };
        assert_eq!(declared(built_in_entries()), 75);
        assert_eq!(declared(common_built_in_entries()), 4);
    }

    /// The set of built-ins that declare nothing is exactly the reviewed
    /// list of detectors that cannot name a required case-sensitive literal
    /// (issue #983 research), so a new detector is a deliberate choice.
    #[test]
    fn only_the_reviewed_built_ins_run_on_every_call() {
        let always: Vec<String> = built_in_entries()
            .into_iter()
            .filter(|entry| entry.required.is_none())
            .map(|entry| entry.detector.id().to_owned())
            .collect();
        assert_eq!(
            always,
            [
                "twilio-auth-token",
                "twilio-api-key-secret",
                "discord-bot-token",
                "datadog-api-key",
                "datadog-application-key-legacy",
                "new-relic-license-key",
                "pinecone-api-key",
                "confluent-cloud-api-secret-legacy",
                "heroku-api-key-legacy",
                "travisci-api-token",
                "mistral-api-key",
                "cohere-api-key",
                "ai21-api-key",
                "deepgram-api-key",
                "convex-deployment-key",
                "bearer-token",
                "generic-token",
            ]
        );
    }
}
