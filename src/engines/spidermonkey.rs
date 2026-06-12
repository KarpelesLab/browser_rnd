//! SpiderMonkey `Math.random()` — Firefox and other Gecko browsers.
//!
//! State transition: xorshift128+ (identical to V8). Output conversion uses the
//! **sum** of both lanes after the step, taking its top 53 bits:
//!
//! ```text
//! double = ((s0 + s1) >> 11) as f64 * 2^-53
//! ```
//!
//! Unlike V8, SpiderMonkey serves values one-per-step in generation order — no
//! reversed cache.
//!
//! VERSION SPLIT — this module models *modern* SpiderMonkey only. Gecko switched
//! `Math.random()` to xorshift128+ around Firefox 49 (2016). Earlier Firefox
//! (e.g. the 1.0 / rv:1.7 captures in `samples/`) used a legacy drand48-style
//! 48-bit LCG instead:
//!   state = (state * 0x5DEECE66D + 0xB) mod 2^48
//!   double = ((next(26) << 27) + next(27)) * 2^-53
//! Both produce 53-bit doubles, so the structural fingerprint cannot tell them
//! apart — only reproduction can. The legacy LCG path is not implemented yet;
//! see the `samples/` Firefox-1.0 fixture, which is the target for it.

use crate::prng::XorShift128Plus;

const TWO_POW_53: f64 = 9_007_199_254_740_992.0; // 2^53

/// Convert a post-step sum (`s0 + s1`) to the double SpiderMonkey returns.
#[inline]
pub fn to_double(sum: u64) -> f64 {
    ((sum >> 11) as f64) / TWO_POW_53
}

/// Recover the top 53 bits of the sum from an observed double. Returns the value
/// of `sum >> 11`; the low 11 bits of the sum are unrecoverable from one output.
#[inline]
pub fn sum_high_bits(value: f64) -> u64 {
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
    fn high_bits_round_trip() {
        let sum = 0xFEDC_BA98_7654_3000u64;
        let d = to_double(sum);
        assert_eq!(sum_high_bits(d), sum >> 11);
    }
}
