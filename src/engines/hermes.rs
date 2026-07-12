//! Hermes `Math.random()` — the engine behind **React Native** apps.
//!
//! Hermes never wrote its own PRNG. `mathRandom` (`lib/VM/JSLib/Math.cpp`) just
//! seeds a C++ standard-library engine once from `std::random_device` and folds
//! every subsequent draw into a `double` with `std::uniform_real_distribution<>
//! (0.0, 1.0)`. So the algorithm is entirely determined by *which* stdlib engine
//! the `RuntimeCommonStorage::randomEngine_` field names — and that changed
//! exactly **once** in Hermes' public history:
//!
//! | Era | Dates | `randomEngine_` | Seed | Per-call draws |
//! |---|---|---|---|---|
//! | **1 — LCG** | 2019-07-10 … 2023-11-08 | `std::minstd_rand` | 32-bit (`random_device()` ×1) | 2 |
//! | **2 — Mersenne** | 2023-11-08 … present | `std::mt19937_64` | 64-bit (`random_device()` ×2) | 1 |
//!
//! The switch is commit `20c11c441` / PR #1175 (["Switch Math.random() to faster
//! 64-bit seeded implementation"](https://github.com/facebook/hermes/pull/1175)),
//! motivated by issue #1169: a single 32-bit `random_device()` seed gives only
//! ~4·10⁹ streams, so ~100 k UUIDs collide with ~71 % probability (birthday
//! bound). Despite the PR text benchmarking `lcg64` / `xoroshiro128+` / bit-twiddle
//! double conversions, the **merged** change only swapped the engine type to
//! `std::mt19937_64` and widened the seed; the conversion stayed
//! `uniform_real_distribution`.
//!
//! ## The double conversion is implementation-defined
//! `uniform_real_distribution<>(0,1)(g)` calls `std::generate_canonical<double,
//! 53>(g)`, whose exact arithmetic is *not* standardized. React Native ships
//! **libc++** on iOS and Android, so libc++'s formula
//! (`libcxx/include/__random/generate_canonical.h`) is authoritative here:
//! ```text
//! R  = g.max() - g.min() + 1
//! k  = ceil(53 / floor(log2 R))            // draws needed for 53 mantissa bits
//! s  = (g()-g.min())                        // first draw = LOW digit
//! for i in 1..k:  s += (g()-g.min()) * R^i  // later draws = higher digits
//! return s / R^k
//! ```
//! (libstdc++ implements the same standard algorithm and yields the same `k`
//! and layout for both Hermes engines.)
//!
//! ## Era 1 — `std::minstd_rand` (the Park–Miller MINSTD LCG)
//! `std::minstd_rand = linear_congruential_engine<uint_fast32_t, 48271, 0,
//! 2147483647>`: `state = state·48271 mod (2³¹−1)`, with `min()=1`, `max()=
//! 2³¹−2`, so `R = 2³¹−2 = 2147483646` and `k = ceil(53/30) = 2`. Each
//! `Math.random()` is therefore **two** LCG steps:
//! ```text
//! g0 = step(state); g1 = step(g0); state = g1
//! value = ((g0-1) + (g1-1)·R) / R²          // grid 1/R² ≈ 2⁻⁶²·⁰⁰
//! ```
//! The high digit is `g1` — the raw LCG state itself — so `g1-1 = floor(value·R)`
//! recovers the **entire 31-bit state from a single output** (the modulus is only
//! 2³¹). That, plus the non-power-of-two `1/R²` grid, makes Era 1 the most
//! trivially crackable engine in this crate: [`recover`] locks the state in O(1)
//! and steps both ways. See [`generate`] / [`recover`] below.
//!
//! ## Era 2 — `std::mt19937_64`
//! `R = 2⁶⁴` so `k = ceil(53/64) = 1`: one 64-bit Mersenne-Twister output per
//! call, `value = out / 2⁶⁴` (the top 53 bits, on the ordinary 2⁻⁵³ grid — hence
//! indistinguishable *by grid alone* from SpiderMonkey/Dart). [`generate_mt`]
//! reproduces it. Recovery is not O(1): MT19937-64 has 19937 bits of state and
//! each output leaks only its top 53 bits, so pinning the state needs ~625
//! consecutive outputs and a GF(2) solve over the tempering+truncation — a bulk
//! job, not wired into the predictor here (documented, not implemented).

// ---- Era 1: std::minstd_rand ------------------------------------------------

/// MINSTD modulus, `2³¹ − 1` (a Mersenne prime).
const M: u64 = 2_147_483_647;
/// MINSTD multiplier (`std::minstd_rand`, *not* `minstd_rand0`'s 16807).
const A: u64 = 48_271;
/// `g.max()-g.min()+1 = (M-1) - 1 + 1 = M-1`. The libc++ radix for the 2-draw
/// canonical fold.
const R: u64 = M - 1; // 2_147_483_646
const RF: f64 = R as f64;
const R2F: f64 = RF * RF; // R² as f64 (≈ 4.61e18)

/// One MINSTD step: `state = state·48271 mod (2³¹−1)`. Valid states are `1..=M-1`.
#[inline]
pub fn step(s: u32) -> u32 {
    ((s as u64 * A) % M) as u32
}

/// Modular inverse of `A` modulo `M` (prime), via Fermat: `A^(M-2) mod M`.
/// Public so callers stepping the stream backward can compute it once.
pub fn a_inv() -> u64 {
    let mut base = A % M;
    let mut exp = M - 2;
    let mut acc = 1u64;
    while exp > 0 {
        if exp & 1 == 1 {
            acc = (acc * base) % M;
        }
        base = (base * base) % M;
        exp >>= 1;
    }
    acc
}

/// Invert one MINSTD step: `prev = state·A⁻¹ mod M`.
#[inline]
pub fn prev(s: u32, inv: u64) -> u32 {
    ((s as u64 * inv) % M) as u32
}

/// The state a fresh `std::minstd_rand` reaches after `seed(v)`:
/// `state = v mod M`, bumped to 1 if that is 0 (LCG fixed point).
pub fn seeded(v: u32) -> u32 {
    let s = (v as u64 % M) as u32;
    if s == 0 {
        1
    } else {
        s
    }
}

/// Generate `n` doubles from `state` (the LCG state *before* the first output),
/// matching libc++ `uniform_real_distribution<>(0,1)` over `std::minstd_rand`.
pub fn generate(mut state: u32, n: usize) -> Vec<f64> {
    let mut out = Vec::with_capacity(n);
    for _ in 0..n {
        let g0 = step(state); // low digit
        let g1 = step(g0); // high digit == new LCG state
        state = g1;
        out.push(((g0 - 1) as f64 + (g1 - 1) as f64 * RF) / R2F);
    }
    out
}

/// Recover the LCG state *before* the first observed output, closed-form.
///
/// The high digit `g1-1 = floor(value·R)` is the raw LCG state of the first
/// output's second step, so one value pins the whole 31-bit state. f64 rounding
/// of `value` can only nudge `floor(value·R)` by ±1 (when `g0` sits at the very
/// edge of `[1, R]`), so we try three candidates and confirm by full
/// reproduction. Returns the pre-first-output state; step it forward with
/// [`generate`] or backward with [`prev`].
pub fn recover(values: &[f64]) -> Option<u32> {
    if values.len() < 2 {
        return None;
    }
    let inv = a_inv();
    let base = (values[0] * RF).floor() as i64; // ≈ g1-1 of output 0
    for d in [0i64, -1, 1] {
        let g1m1 = base + d;
        if !(0..R as i64).contains(&g1m1) {
            continue;
        }
        let g1 = (g1m1 as u32) + 1; // LCG state after output 0
        // state before output 0 = two steps back from g1.
        let state = prev(prev(g1, inv), inv);
        if generate(state, values.len())
            .iter()
            .zip(values)
            .all(|(a, b)| (a - b).abs() < 1e-12)
        {
            return Some(state);
        }
    }
    None
}

/// Recover the exact 32-bit value passed to `std::minstd_rand::seed()` — i.e.
/// the raw `std::random_device()` draw a fresh realm used — assuming the capture
/// starts at the realm's first `Math.random()`. Only recoverable when the seed
/// is already reduced (`< M`); a raw `random_device()` ≥ M is aliased to
/// `seed mod M` and cannot be distinguished (returns that residue).
pub fn recover_seed(values: &[f64]) -> Option<u32> {
    // The pre-first-output state *is* `seed mod M` (minstd applies no warm-up).
    recover(values)
}

// ---- Era 2: std::mt19937_64 -------------------------------------------------

const NN: usize = 312;
const MM: usize = 156;
const MATRIX_A: u64 = 0xB502_6F5A_A966_19E9;
const UM: u64 = 0xFFFF_FFFF_8000_0000; // upper 33 bits
const LM: u64 = 0x7FFF_FFFF; // lower 31 bits
const P64: f64 = 18_446_744_073_709_551_616.0; // 2^64

/// A `std::mt19937_64` instance (Mersenne Twister, 64-bit).
#[derive(Clone)]
pub struct Mt19937_64 {
    mt: [u64; NN],
    idx: usize,
}

impl Mt19937_64 {
    /// Seed exactly as `std::mt19937_64::seed(v)` (`init_genrand64`).
    pub fn seeded(seed: u64) -> Self {
        let mut mt = [0u64; NN];
        mt[0] = seed;
        for i in 1..NN {
            mt[i] = 6_364_136_223_846_793_005u64
                .wrapping_mul(mt[i - 1] ^ (mt[i - 1] >> 62))
                .wrapping_add(i as u64);
        }
        Mt19937_64 { mt, idx: NN }
    }

    /// The 64-bit seed Hermes builds: `(hi << 32) | lo` from two 32-bit
    /// `std::random_device()` draws.
    pub fn hermes_seeded(hi: u32, lo: u32) -> Self {
        Self::seeded(((hi as u64) << 32) | lo as u64)
    }

    fn generate_block(&mut self) {
        for i in 0..NN {
            let x = (self.mt[i] & UM) | (self.mt[(i + 1) % NN] & LM);
            let mut xa = x >> 1;
            if x & 1 != 0 {
                xa ^= MATRIX_A;
            }
            self.mt[i] = self.mt[(i + MM) % NN] ^ xa;
        }
        self.idx = 0;
    }

    /// Next raw 64-bit output.
    pub fn next_u64(&mut self) -> u64 {
        if self.idx >= NN {
            self.generate_block();
        }
        let mut x = self.mt[self.idx];
        self.idx += 1;
        x ^= (x >> 29) & 0x5555_5555_5555_5555;
        x ^= (x << 17) & 0x71D6_7FFF_EDA6_0000;
        x ^= (x << 37) & 0xFFF7_EEE0_0000_0000;
        x ^= x >> 43;
        x
    }
}

/// Generate `n` Era-2 doubles from a fresh `mt19937_64` with the given 64-bit
/// seed: libc++ `k = 1`, so `value = next_u64() / 2⁶⁴`.
pub fn generate_mt(seed: u64, n: usize) -> Vec<f64> {
    let mut g = Mt19937_64::seeded(seed);
    (0..n).map(|_| g.next_u64() as f64 / P64).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn minstd_step_matches_reference() {
        // std::minstd_rand seeded with 1 emits 48271 then 182605794 (known values).
        let mut s = seeded(1);
        s = step(s);
        assert_eq!(s, 48271);
        s = step(s);
        assert_eq!(s, 182_605_794);
    }

    #[test]
    fn step_inverts() {
        let inv = a_inv();
        let mut s = seeded(0x1234_5678);
        for _ in 0..10_000 {
            let n = step(s);
            assert_eq!(prev(n, inv), s);
            s = n;
        }
    }

    #[test]
    fn output_in_unit_interval() {
        for v in generate(seeded(0xDEAD_BEEF), 1000) {
            assert!((0.0..1.0).contains(&v), "{v} out of range");
        }
        for v in generate_mt(0x0123_4567_89AB_CDEF, 1000) {
            assert!((0.0..1.0).contains(&v), "{v} out of range");
        }
    }

    #[test]
    fn lcg_recover_round_trip() {
        for seed in [1u32, 2, 42, 0x0BAD_F00D, 0x7FFF_FFFE, 123_456_789] {
            let st = seeded(seed);
            let v = generate(st, 200);
            let got = recover(&v).expect("recover");
            assert_eq!(got, st, "seed {seed:#x}");
            assert!(generate(got, 200).iter().zip(&v).all(|(a, b)| (a - b).abs() < 1e-12));
        }
    }

    #[test]
    fn lcg_recover_from_midstream_slice() {
        // Recovery must work starting from any point in the stream.
        let full = generate(seeded(0x0051_1E55), 300);
        let st = recover(&full[137..237]).expect("recover");
        assert!(generate(st, 100).iter().zip(&full[137..237]).all(|(a, b)| (a - b).abs() < 1e-12));
    }

    #[test]
    fn mt19937_64_reference_value() {
        // Reference: std::mt19937_64 seeded with 5489 (default) -> first output.
        let mut g = Mt19937_64::seeded(5489);
        assert_eq!(g.next_u64(), 14_514_284_786_278_117_030);
    }
}
