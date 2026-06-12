//! Linear congruential generators — the family used by legacy JScript
//! (`Math.random()` in MSIE 6/7/8) and assorted older engines.
//!
//! A generic `state -> state * a + c (mod m)` step. The exact multiplier,
//! increment, modulus and output-scaling for JScript are still being pinned down
//! empirically by this project; see `engines::jscript` for the candidates under
//! test.

/// A configurable LCG: `state = (state * mult + incr) & mask`.
#[derive(Clone, Copy, Debug)]
pub struct Lcg {
    pub state: u64,
    pub mult: u64,
    pub incr: u64,
    /// Modulus mask. For a power-of-two modulus use `modulus - 1`; for a prime
    /// modulus handle the reduction in `next` via `modulus`.
    pub mask: u64,
    /// If non-zero, reduce modulo this instead of masking (for prime moduli).
    pub modulus: u64,
}

impl Lcg {
    /// Power-of-two-modulus LCG (the common case).
    pub fn pow2(state: u64, mult: u64, incr: u64, bits: u32) -> Self {
        let mask = if bits >= 64 { u64::MAX } else { (1u64 << bits) - 1 };
        Self { state, mult, incr, mask, modulus: 0 }
    }

    /// Prime-modulus LCG.
    pub fn prime(state: u64, mult: u64, incr: u64, modulus: u64) -> Self {
        Self { state, mult, incr, mask: u64::MAX, modulus }
    }

    #[inline]
    pub fn next_state(&mut self) -> u64 {
        let v = self.state.wrapping_mul(self.mult).wrapping_add(self.incr);
        self.state = if self.modulus != 0 { v % self.modulus } else { v & self.mask };
        self.state
    }
}
