//! V8 `Math.random()` — Chrome, Edge, Opera, Brave, Node.js.
//!
//! State transition: xorshift128+. Output conversion reads `s0` *after* the
//! step and reinterprets its top 52 bits as the mantissa of a double in
//! `[1, 2)`, then subtracts 1:
//!
//! ```text
//! double = bitcast((s0 >> 12) | 0x3FF0000000000000) - 1.0
//! ```
//!
//! VERSION SPLIT — this module models *modern* V8 only. Before Chrome 49 / V8
//! 4.9.41 (late 2015), `Math.random()` was MWC1616: two multiply-with-carry
//! 16-bit generators combined into a ~32-bit result, then scaled. It is far
//! weaker and its outputs only populate ~32 mantissa bits — so the structural
//! fingerprint reads ~32 bits, not 52 (see `samples/opera16.txt`, Chromium-era
//! Opera). The MWC1616 path is not implemented yet; that fixture is its target.
//!
//! THE GOTCHA: V8 does not serve values one-per-step. It refills a cache of
//! [`CACHE_SIZE`] doubles and hands them out **in reverse**. So the JS-observed
//! order within a batch is the reverse of generation order, and batch boundaries
//! appear every [`CACHE_SIZE`] draws. Any state-recovery must account for this.

use crate::prng::XorShift128Plus;

/// V8's `kCacheSize` for the Math.random cache (`v8/src/numbers/math-random.cc`).
pub const CACHE_SIZE: usize = 64;

const EXPONENT_BITS: u64 = 0x3FF0_0000_0000_0000;
const MANTISSA_MASK: u64 = 0x000F_FFFF_FFFF_FFFF;

/// Convert a post-step `s0` to the double V8 would return.
#[inline]
pub fn to_double(s0: u64) -> f64 {
    f64::from_bits((s0 >> 12) | EXPONENT_BITS) - 1.0
}

/// Recover the top 52 bits of `s0` from an observed double. The low 12 bits of
/// `s0` are discarded by the conversion and cannot be recovered from one output;
/// the returned value has them zeroed. Bit positions: result == `s0 & !0xFFF`.
#[inline]
pub fn s0_high_bits(value: f64) -> u64 {
    let mantissa = (value + 1.0).to_bits() & MANTISSA_MASK;
    mantissa << 12
}

/// Generate `n` doubles in the order JS observes them (i.e. reverse-served in
/// batches of [`CACHE_SIZE`]), starting from `state`.
pub fn generate(mut state: XorShift128Plus, n: usize) -> Vec<f64> {
    let mut out = Vec::with_capacity(n);
    while out.len() < n {
        // Fill one cache: step CACHE_SIZE times, recording s0 each time.
        let mut cache = [0u64; CACHE_SIZE];
        for slot in cache.iter_mut() {
            state.next_state();
            *slot = state.s0;
        }
        // Served in reverse.
        for &s0 in cache.iter().rev() {
            if out.len() == n {
                break;
            }
            out.push(to_double(s0));
        }
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
        // The top 52 bits survive the double conversion.
        let s0 = 0xABCD_EF12_3456_7000u64; // low 12 bits zero
        let d = to_double(s0);
        assert_eq!(s0_high_bits(d), s0 & !0xFFF);
    }
}
