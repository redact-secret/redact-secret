//! Crate-internal building blocks of the beta.9 shadow evidence scorer
//! (`decision-freeze-the-shadow-evidence-score-and-confidence-contract`).
//!
//! Everything here is `pub(crate)` or narrower: no item is part of the public
//! API, and nothing here changes detection, confidence, overlap resolution or
//! policy. [`features`] extracts the integer statistical features (#769).

pub(crate) mod features;
pub(crate) mod fixed_point;
