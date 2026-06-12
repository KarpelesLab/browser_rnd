//! Presto `Math.random()` — Opera 7–12 (Carakan engine).
//!
//! UNIQUE AMONG BROWSERS: Presto backs `Math.random()` with a **cryptographically
//! secure** RNG, not a fast PRNG. Every call consumes 64 bits of **SNOW 2.0**
//! stream-cipher keystream (`modules/libcrypto`), and the generator is
//! continuously reseeded at runtime with real entropy (UI events, message loop,
//! time, SSL, …), tracking an entropy counter up to 576 bits.
//!
//! Double conversion (`OpRandomGenerator::GetDouble`):
//! ```text
//! ui1 = keystream[0] - 1
//! ui2 = (keystream[1] - 1) & ~((1<<11) - 1)   // clear low 11 bits
//! double = ui1 / 2^32 + ui2 / 2^64            // 53-bit, in (0,1)
//! ```
//! (The `-1` keeps the result strictly below 1.0; the low 11 bits of the second
//! word are masked because they fall below double precision.) This explains the
//! 2⁻⁵³ grid of `samples/presto/opera10.txt`.
//!
//! RECOVERY IS INFEASIBLE BY DESIGN. There is no low-entropy state to recover:
//! predicting outputs would require breaking SNOW 2.0, and even then the
//! continuous entropy injection defeats state reconstruction from outputs. So
//! unlike every other engine here, Presto's `Math.random()` is genuinely
//! unpredictable — we model only the forward conversion, for documentation.
//!
//! (The `#ifdef _STANDALONE` embeddable build instead XORs several `op_rand()`
//! calls into 32 bits and divides by 2^32 — a weak fallback never shipped in the
//! browser.)

const P32: f64 = 4_294_967_296.0; // 2^32
const P64: f64 = 18_446_744_073_709_551_616.0; // 2^64

/// The forward double conversion from two 32-bit keystream words. Useful for
/// documentation/tests; the keystream itself comes from SNOW 2.0 and cannot be
/// predicted from outputs.
pub fn to_double(keystream0: u32, keystream1: u32) -> f64 {
    let ui1 = keystream0.wrapping_sub(1);
    let ui2 = keystream1.wrapping_sub(1) & !((1u32 << 11) - 1);
    (ui1 as f64) / P32 + (ui2 as f64) / P64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn to_double_in_unit_interval_and_on_grid() {
        for (a, b) in [(1u32, 1u32), (u32::MAX, u32::MAX), (0x1234_5678, 0x9abc_def0)] {
            let d = to_double(a, b);
            assert!((0.0..1.0).contains(&d), "{d} out of range");
            // value is a multiple of 2^-53
            assert!((d * 9_007_199_254_740_992.0).fract().abs() < 1e-3);
        }
    }
}
