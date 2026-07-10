//! Dart `Random` — the generator behind **Flutter** apps (`dart:math`).
//!
//! Flutter has no `Math.random()` of its own; every Flutter app draws from
//! Dart's `Random`. Across Dart's whole history there has been exactly **one**
//! non-secure algorithm — a **Multiply-With-Carry** generator with base 2³² and
//! multiplier `A = 0xffffda61` (Numerical Recipes 3rd ed., p.348, table B1). It
//! predates Flutter (introduced ~Dart 0.8, 2013) and has never changed, so it is
//! identical on **every Flutter version and platform**:
//!
//! | Backend | `Random([seed])` | Notes |
//! |---|---|---|
//! | VM / AOT (Android, iOS, desktop) | this MWC | `runtime/vm/random.cc` + `math_patch.dart` |
//! | dart2wasm | this MWC | `wasm/common/math_patch.dart` (same bits) |
//! | dart2js / DDC **with a seed** | this MWC | reimplemented in 32-bit JS, **bit-identical** |
//! | dart2js / DDC **without a seed** | *browser `Math.random()`* | `_JSRandom` delegates to V8/SpiderMonkey/JSC — see those engines |
//! | `Random.secure()` (any) | OS / `crypto.getRandomValues` CSPRNG | unpredictable by design |
//!
//! So the only real per-platform *variation* is the web-**unseeded** case, which
//! is just the host browser engine this crate already cracks, and `secure()`.
//!
//! ## The algorithm (`math_patch.dart`, `random.cc`)
//! ```text
//! state : u64
//! next_state():  state = A*(state & 0xffffffff) + (state >> 32)   // A = 0xffffda61
//! nextDouble():  a = next_state(); bits26 = a & (2^26-1)          // low 26 bits
//!                b = next_state(); bits27 = b & (2^27-1)          // low 27 bits
//!                return (bits26 * 2^27 + bits27) / 2^53            // grid 2^-53
//! ```
//! Two MWC steps per double, so a capture observes the low 26/27 bits of *every*
//! state in a contiguous chain — enough to recover the full 64-bit state with z3.
//!
//! ## Seeding
//! `Random(seed)` runs the seed through the **Thomas Wang 64-bit mix** (`mix64`,
//! a bijection) and then cranks four warm-up `next_state` calls:
//! `state = mix64(seed); state.next_state() ×4`. Seedless `Random()` pulls
//! `seed` from the VM's entropy source, **falling back to
//! `OS::GetCurrentTimeMicros()`** if none is wired up (`random.cc`). Because
//! `mix64` is invertible, a capture taken from a *fresh* `Random(seed)` recovers
//! the exact user seed ([`recover_seed`]).

/// MWC multiplier (base 2³²). Numerical Recipes 3rd ed., p.348 B1.
const A: u64 = 0xffff_da61;
/// `A = 2³² − C`, so one step is `lo' = (hi − C·lo) mod 2³²` — the key to a
/// closed-form recovery (see [`recover`]). `C = 0x259f = 9631`.
const C: u64 = (1 << 32) - A;
const MASK32: u64 = 0xFFFF_FFFF;
const P53: f64 = 9_007_199_254_740_992.0; // 2^53
const P27: f64 = 134_217_728.0; // 2^27

/// One MWC step: `state = A·(state_lo) + state_hi`.
#[inline]
pub fn next_state(s: u64) -> u64 {
    A.wrapping_mul(s & MASK32).wrapping_add(s >> 32)
}

/// Invert one MWC step. `s' = A·lo + hi` with `lo, hi < 2³²`; since `A ≈ 2³²`,
/// `lo ≈ s'/A` and at most a couple of candidates need checking.
#[inline]
pub fn prev_state(s: u64) -> u64 {
    let base = s / A;
    for d in 0..=2u64 {
        let lo = base.wrapping_sub(d);
        if lo > MASK32 {
            continue;
        }
        let hi = s.wrapping_sub(A.wrapping_mul(lo));
        if hi <= MASK32 {
            let prev = (hi << 32) | lo;
            if next_state(prev) == s {
                return prev;
            }
        }
    }
    s // unreachable for a valid MWC state
}

/// Generate `n` doubles from `state` (the state *before* the first output).
pub fn generate(mut state: u64, n: usize) -> Vec<f64> {
    let mut out = Vec::with_capacity(n);
    for _ in 0..n {
        state = next_state(state);
        let bits26 = (state & MASK32) & ((1 << 26) - 1);
        state = next_state(state);
        let bits27 = (state & MASK32) & ((1 << 27) - 1);
        out.push((bits26 as f64 * P27 + bits27 as f64) / P53);
    }
    out
}

/// The state a fresh `Random(seed)` starts from: `mix64(seed)` then four
/// warm-up steps. Reproduces the Dart VM / AOT / wasm sequence exactly.
pub fn seeded(seed: u64) -> u64 {
    let mut s = mix64(seed);
    for _ in 0..4 {
        s = next_state(s);
    }
    s
}

/// Thomas Wang's 64-bit integer mix, exactly as Dart's `_setupSeed` /
/// `mix64` (with the `n==0 → 0x5a17` guard the VM applies).
pub fn mix64(mut n: u64) -> u64 {
    n = (!n).wrapping_add(n << 21);
    n ^= n >> 24;
    n = n.wrapping_mul(265);
    n ^= n >> 14;
    n = n.wrapping_mul(21);
    n ^= n >> 28;
    n = n.wrapping_add(n << 31);
    if n == 0 {
        0x5a17
    } else {
        n
    }
}

/// Invert [`mix64`] (each step is a bijection on `u64`). Note the `0x5a17`
/// zero-guard is not inverted — it only fires for the single seed whose mix is
/// 0, which is reported as `0x5a17` and can't be distinguished from that seed.
pub fn mix64_inv(mut n: u64) -> u64 {
    // n = n + (n << 31)   →  n *= (1 + 2^31)
    n = n.wrapping_mul(minv(1u64.wrapping_add(1 << 31)));
    // n ^= n >> 28
    n = inv_xorshr(n, 28);
    // n *= 21
    n = n.wrapping_mul(minv(21));
    // n ^= n >> 14
    n = inv_xorshr(n, 14);
    // n *= 265
    n = n.wrapping_mul(minv(265));
    // n ^= n >> 24
    n = inv_xorshr(n, 24);
    // n = (~n) + (n << 21) = n*(2^21 - 1) - 1   →   n = (n + 1) * inv(2^21 - 1)
    n.wrapping_add(1).wrapping_mul(minv((1 << 21) - 1))
}

/// Modular inverse of an odd `a` modulo 2⁶⁴ (Newton's iteration).
fn minv(a: u64) -> u64 {
    let mut x = 1u64;
    for _ in 0..6 {
        x = x.wrapping_mul(2u64.wrapping_sub(a.wrapping_mul(x)));
    }
    x
}

/// Invert `y = x ^ (x >> s)` for `0 < s < 64`.
fn inv_xorshr(y: u64, s: u32) -> u64 {
    let mut x = y;
    // Each pass fixes another `s` high bits; ceil(64/s) passes suffice.
    for _ in 0..(64 / s + 1) {
        x = y ^ (x >> s);
    }
    x
}

/// Recover the full 64-bit MWC state from observed doubles — closed-form, no
/// solver. Each `nextDouble` exposes the low **26** bits of one state's `lo`
/// word and the low **27** bits of the next. Because `A = 2³² − C`, one step is
/// `lo_{j+1} = (hi_j − C·lo_j) mod 2³²`, so `hi_j = (lo_{j+1} + C·lo_j) mod 2³²`:
/// two consecutive full `lo` words pin the entire 64-bit state. The first
/// output's two states give `lo₁` (missing 6 high bits) and `lo₂` (missing 5),
/// so a 2¹¹ brute over those high bits, verified by full reproduction, is
/// conclusive. Returns the state *before* the first observed output.
pub fn recover(values: &[f64]) -> Option<u64> {
    if values.len() < 3 {
        return None;
    }
    let n0 = (values[0] * P53).round() as u64;
    let l1 = n0 >> 27; // low 26 bits of lo₁ (first state)
    let l2 = n0 & ((1 << 27) - 1); // low 27 bits of lo₂ (second state)
    for h1 in 0..(1u64 << 6) {
        let lo1 = (h1 << 26) | l1;
        for h2 in 0..(1u64 << 5) {
            let lo2 = (h2 << 27) | l2;
            let hi1 = (lo2 + C.wrapping_mul(lo1)) & MASK32;
            let s1 = (hi1 << 32) | lo1; // full state after the first step
            let st = prev_state(s1); // step back to the pre-output state
            if generate(st, values.len())
                .iter()
                .zip(values)
                .all(|(a, b)| (a - b).abs() < 1e-15)
            {
                return Some(st);
            }
        }
    }
    None
}

/// Recover the exact user seed passed to `Random(seed)`, assuming the capture
/// begins at the generator's **first** `nextDouble` (no prior draws). Steps the
/// recovered state back through the four warm-up cranks and inverts `mix64`.
/// Unlike Safari's GameRand there is no seed-time invariant, so an unknown
/// warm-up can't be pinned — hence the fresh-start assumption.
pub fn recover_seed(values: &[f64]) -> Option<u64> {
    let mut s = recover(values)?;
    for _ in 0..4 {
        s = prev_state(s);
    }
    Some(mix64_inv(s))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mix64_inverts() {
        for seed in [0u64, 1, 12345, 0x1234_5678, 0xdead_beef_cafe_babe, u64::MAX] {
            let m = mix64(seed);
            if m != 0x5a17 {
                assert_eq!(mix64_inv(m), seed, "seed {seed:#x}");
            }
        }
    }

    #[test]
    fn state_steps_invert() {
        let mut s = seeded(0x0bad_f00d);
        for _ in 0..1000 {
            let n = next_state(s);
            assert_eq!(prev_state(n), s);
            s = n;
        }
    }

    #[test]
    fn output_in_unit_interval() {
        for d in generate(seeded(1), 500) {
            assert!((0.0..1.0).contains(&d));
        }
    }

    #[test]
    fn seed_round_trip() {
        // A fresh Random(seed) → capture → recover the exact seed.
        let seed = 0x1357_9bdf;
        let v = generate(seeded(seed), 200);
        assert_eq!(recover_seed(&v), Some(seed));
    }

    #[test]
    fn recover_round_trip() {
        let v = generate(seeded(0x2233_4455), 300);
        let st = recover(&v).expect("recover");
        assert!(generate(st, 300).iter().zip(&v).all(|(a, b)| (a - b).abs() < 1e-15));
    }
}
