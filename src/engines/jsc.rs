//! JavaScriptCore `Math.random()` — Safari and iOS WebViews.
//!
//! State transition: xorshift128+ (identical to V8). JSC's `WeakRandom` folds
//! the post-step **sum** down using its **low** 53 bits (contrast SpiderMonkey,
//! which uses the high 53):
//!
//! ```text
//! double = (s0 + s1) & (2^53 - 1)) as f64 * 2^-53
//! ```
//!
//! Values are served one-per-step in generation order.
//!
//! NOTE: confirm the low-vs-high choice against a real Safari capture before
//! trusting recovery — that is exactly what the `samples/` fixtures are for.

use crate::prng::XorShift128Plus;

const TWO_POW_53: f64 = 9_007_199_254_740_992.0; // 2^53
const MASK_53: u64 = (1 << 53) - 1;

/// Convert a post-step sum (`s0 + s1`) to the double JSC returns.
#[inline]
pub fn to_double(sum: u64) -> f64 {
    ((sum & MASK_53) as f64) / TWO_POW_53
}

/// Recover the low 53 bits of the sum from an observed double.
#[inline]
pub fn sum_low_bits(value: f64) -> u64 {
    (value * TWO_POW_53) as u64
}

/// Generate `n` doubles in observed order, starting from `state`.
pub fn generate(mut state: XorShift128Plus, n: usize) -> Vec<f64> {
    let mut out = Vec::with_capacity(n);
    for _ in 0..n {
        state.next_state();
        out.push(to_double(state.sum()));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn to_double_in_unit_interval() {
        for bits in [0u64, u64::MAX, 0x1234_5678_9abc_def0] {
            let d = to_double(bits);
            assert!((0.0..1.0).contains(&d), "{d} out of range");
        }
    }

    #[test]
    fn low_bits_round_trip() {
        let sum = 0x0000_0000_0000_0FFFu64 | (0x1A << 53);
        let d = to_double(sum);
        assert_eq!(sum_low_bits(d), sum & MASK_53);
    }
}
