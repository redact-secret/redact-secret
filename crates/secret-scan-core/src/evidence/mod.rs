//! Crate-internal building blocks of the beta.9 shadow evidence scorer
//! (`decision-freeze-the-shadow-evidence-score-and-confidence-contract`).
//!
//! Everything here is `pub(crate)` or narrower: no item is part of the public
//! API, and nothing here changes detection, confidence, overlap resolution or
//! policy. [`features`] extracts the integer statistical features (#769);
//! [`aggregate`] groups, caps and combines them with contextual and negative
//! evidence into a shadow band and its explanation (#770), using
//! [`context`] and [`exclusion`].

pub(crate) mod aggregate;
pub(crate) mod context;
pub(crate) mod exclusion;
pub(crate) mod features;
pub(crate) mod fixed_point;
