//! Crate-internal building blocks of the beta.9 shadow evidence scorer
//! (`decision-freeze-the-shadow-evidence-score-and-confidence-contract`).
//!
//! Everything here is `pub(crate)` or narrower: no item is part of the public
//! API, and nothing here changes detection, confidence, overlap resolution or
//! policy. [`features`] extracts the integer statistical features (#769);
//! [`aggregate`] groups, caps and combines them with contextual and negative
//! evidence into a shadow band and its explanation (#770), using
//! [`context`] and [`exclusion`]. [`shadow`] compares that band with the
//! legacy decision of each candidate the pipeline selects, only when a
//! maintainer-local caller asks for it, and renders the comparison (#771).

pub(crate) mod aggregate;
pub(crate) mod context;
pub(crate) mod exclusion;
pub(crate) mod features;
pub(crate) mod fixed_point;
// `ShadowComparison::shifted` serves only the incremental session's
// test-only recording (#772), so a non-test build sees no caller.
#[cfg_attr(
    not(test),
    allow(
        dead_code,
        reason = "the incremental session records shadow comparisons only under cfg(test) (#772)"
    )
)]
pub(crate) mod shadow;

#[cfg(test)]
mod qualification_tests;
