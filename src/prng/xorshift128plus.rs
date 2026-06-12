//! xorshift128+ — the core generator behind V8 (Chrome/Edge/Node), SpiderMonkey
//! (Firefox) and JavaScriptCore (Safari) `Math.random()`.
//!
//! All three engines share the *same* state transition; they differ only in how
//! the 128-bit state is folded down into a `f64` in `[0, 1)`. Those conversions
//! live in the `engines` module, not here.
//!
//! The transition is fully invertible, which is what makes prediction practical:
//! once the 128-bit state is recovered from a handful of observed outputs we can
//! step forwards to predict *and* backwards to reconstruct earlier draws (V8, in
//! particular, serves its cache in reverse — see `engines::v8`).

/// The 128-bit xorshift128+ state, as two 64-bit lanes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct XorShift128Plus {
    pub s0: u64,
    pub s1: u64,
}

impl XorShift128Plus {
    pub fn new(s0: u64, s1: u64) -> Self {
        Self { s0, s1 }
    }

    /// Advance the state one step. Mirrors V8's `XorShift128`
    /// (`base/utils/random-number-generator.h`) exactly; SpiderMonkey and JSC
    /// use the identical recurrence.
    #[inline]
    pub fn next_state(&mut self) {
        let mut s1 = self.s0;
        let s0 = self.s1;
        self.s0 = s0;
        s1 ^= s1 << 23;
        s1 ^= s1 >> 17;
        s1 ^= s0;
        s1 ^= s0 >> 26;
        self.s1 = s1;
    }

    /// Invert one step: given the current state, recover the state that produced
    /// it. Useful for walking back through a V8 reverse-served cache.
    #[inline]
    pub fn prev_state(&mut self) {
        // Forward step set: new_s0 = old_s1, new_s1 = f(old_s0, old_s1).
        // So old_s1 == current s0. We then undo f to recover old_s0.
        let old_s1 = self.s0;
        let s0 = old_s1; // == the `s0` used inside the forward step
        let mut x = self.s1;
        x ^= s0 >> 26;
        x ^= s0;
        x = undo_rshift(x, 17);
        x = undo_lshift(x, 23);
        // `x` is now old_s0.
        self.s1 = old_s1;
        self.s0 = x;
    }

    /// The pre-conversion 64-bit output most engines start from. V8 ignores this
    /// (it reads `s0` directly after stepping); SpiderMonkey and JSC use the sum.
    #[inline]
    pub fn sum(&self) -> u64 {
        self.s0.wrapping_add(self.s1)
    }
}

/// Invert `y = x ^ (x << shift)`, reconstructing `x` from the low bits up.
/// The low `shift` bits of `x` equal the low bits of `y`; each higher bit is
/// `x_i = y_i ^ x_{i-shift}`.
fn undo_lshift(y: u64, shift: u32) -> u64 {
    let mut x: u64 = 0;
    for i in 0..64 {
        let bit = if i < shift {
            (y >> i) & 1
        } else {
            ((y >> i) & 1) ^ ((x >> (i - shift)) & 1)
        };
        x |= bit << i;
    }
    x
}

/// Invert `y = x ^ (x >> shift)`, reconstructing `x` from the high bits down.
fn undo_rshift(y: u64, shift: u32) -> u64 {
    let mut x: u64 = 0;
    for i in (0..64).rev() {
        let hi = i + shift;
        let bit = if hi >= 64 {
            (y >> i) & 1
        } else {
            ((y >> i) & 1) ^ ((x >> hi) & 1)
        };
        x |= bit << i;
    }
    x
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn step_is_invertible() {
        let mut s = XorShift128Plus::new(0x0123_4567_89ab_cdef, 0xfedc_ba98_7654_3210);
        let start = s;
        for _ in 0..1000 {
            s.next_state();
        }
        for _ in 0..1000 {
            s.prev_state();
        }
        assert_eq!(s, start);
    }

    #[test]
    fn shift_inverses_round_trip() {
        for &v in &[0u64, 1, 0xdead_beef_cafe_babe, u64::MAX, 0x8000_0000_0000_0001] {
            assert_eq!(undo_lshift(v ^ (v << 23), 23), v);
            assert_eq!(undo_rshift(v ^ (v >> 17), 17), v);
        }
    }
}
