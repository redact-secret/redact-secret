//! Integer fixed-point helpers for the shadow evidence features.
//!
//! `decision-freeze-the-shadow-evidence-score-and-confidence-contract`
//! section 7 forbids `f32`/`f64` and `libm` calls between feature extraction
//! and the shadow band, because a host's `libm` may round `log2` differently
//! in the last place. Every logarithm the features need therefore comes from
//! [`log2_q16`], an exact integer algorithm whose output is a pure function
//! of its `u32` argument on every host.

/// Number of fractional bits in a Q16 fixed-point value.
pub(crate) const Q16_FRACTION_BITS: u32 = 16;

/// `1.0` in Q16 fixed point.
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "only the fixed-point and feature tests convert to Q16"
    )
)]
pub(crate) const Q16_ONE: u32 = 1 << Q16_FRACTION_BITS;

/// Base-2 logarithm of `x` in Q16 fixed point (`log2(x) * 65536`, rounded
/// toward zero by the algorithm below). `log2_q16(0)` is defined as `0`;
/// callers never ask for it.
///
/// Algorithm (bit-by-bit binary logarithm by repeated squaring):
///
/// 1. `k = floor(log2(x)) = 31 - leading_zeros(x)` is the integer part.
/// 2. `m = x << (32 - k)` is `x / 2^k` in Q32, so `2^32 <= m < 2^33`.
/// 3. Sixteen times: `m = (m * m) >> 32` (truncating); shift the fraction
///    left one bit; if `m >= 2^33`, set the new low fraction bit and
///    `m >>= 1`.
/// 4. The result is `(k << 16) | fraction`.
///
/// Every step is integer arithmetic on at most 66-bit intermediates, held in
/// `u128`, so no step can overflow or depend on the host. The result is
/// never above `log2(x) * 65536` and less than two units (`2^-16`) below
/// it, and it is non-decreasing in `x` (both pinned by tests).
#[must_use]
pub(crate) const fn log2_q16(x: u32) -> u32 {
    if x == 0 {
        return 0;
    }
    let integer = x.ilog2();
    // `x < 2^(integer + 1)`, so after the shift `2^32 <= m < 2^33`.
    let mut mantissa: u128 = (x as u128) << (32 - integer);
    let mut fraction: u32 = 0;
    let mut bit = 0;
    while bit < Q16_FRACTION_BITS {
        mantissa = (mantissa * mantissa) >> 32;
        fraction <<= 1;
        if mantissa >= 1 << 33 {
            mantissa >>= 1;
            fraction |= 1;
        }
        bit += 1;
    }
    (integer << Q16_FRACTION_BITS) | fraction
}

/// `floor(numerator * 1000 / denominator)`, or `0` when `denominator` is
/// `0`. Computed in `u64`, so it cannot overflow for `u32` arguments.
#[must_use]
pub(crate) fn permille(numerator: u32, denominator: u32) -> u32 {
    if denominator == 0 {
        return 0;
    }
    let value = u64::from(numerator) * 1000 / u64::from(denominator);
    u32::try_from(value).unwrap_or(u32::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_powers_of_two_are_exact() {
        assert_eq!(log2_q16(0), 0);
        for power in 0..32 {
            assert_eq!(log2_q16(1 << power), power << Q16_FRACTION_BITS);
        }
    }

    #[test]
    fn known_fractional_values_are_pinned() {
        // Golden vectors shared with the benchmark-side reimplementation.
        assert_eq!(log2_q16(3), 103_872);
        assert_eq!(log2_q16(5), 152_169);
        assert_eq!(log2_q16(10), 217_705);
        assert_eq!(log2_q16(62), 390_214);
        assert_eq!(log2_q16(255), 523_917);
        assert_eq!(log2_q16(u32::MAX), 2_097_151);
    }

    #[test]
    fn is_non_decreasing_and_less_than_two_units_below_exact() {
        let mut previous = 0;
        for x in 1..=70_000_u32 {
            let value = log2_q16(x);
            assert!(value >= previous, "not monotone at {x}");
            previous = value;
            let exact = f64::from(x).log2() * f64::from(Q16_ONE);
            let difference = exact - f64::from(value);
            assert!(
                (0.0..2.0).contains(&difference),
                "x={x} value={value} exact={exact}"
            );
        }
    }

    #[test]
    fn permille_rounds_toward_zero_and_guards_zero() {
        assert_eq!(permille(1, 3), 333);
        assert_eq!(permille(2, 3), 666);
        assert_eq!(permille(5, 0), 0);
        assert_eq!(permille(u32::MAX, 1), u32::MAX);
    }
}
