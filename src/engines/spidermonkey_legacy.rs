//! Legacy SpiderMonkey `Math.random()` — Firefox before ~49 (e.g. 1.0, 3.x).
//!
//! A drand48-style 48-bit LCG (identical constants to `java.util.Random`):
//! ```text
//! state = (state * 0x5DEECE66D + 0xB) mod 2^48
//! next(bits) = state >> (48 - bits)        // after stepping
//! double = ((next(26) << 27) + next(27)) * 2^-53
//! ```
//! So each emitted double consumes TWO LCG steps. Confirmed by full reproduction
//! of `samples/spidermonkey/firefox1-winxp.txt` (see `tests/recover.rs`).
//!
//! Recovery is a 2^22 brute force over the low bits of the first intermediate
//! state, validated against the rest of the sequence — milliseconds in practice.

const MULT: u64 = 0x5DEECE66D;
const ADD: u64 = 0xB;
const MASK: u64 = (1 << 48) - 1;
const P53: f64 = 9_007_199_254_740_992.0; // 2^53

#[inline]
fn step(s: u64) -> u64 {
    s.wrapping_mul(MULT).wrapping_add(ADD) & MASK
}

/// Multiplicative inverse of MULT modulo 2^48 (MULT is odd), via Newton iteration.
fn inv_mult() -> u64 {
    let mut x = 1u64;
    for _ in 0..6 {
        x = x.wrapping_mul(2u64.wrapping_sub(MULT.wrapping_mul(x)));
    }
    x & MASK
}

#[inline]
fn prev(s: u64, inv: u64) -> u64 {
    ((s + MASK + 1 - ADD) & MASK).wrapping_mul(inv) & MASK
}

/// One double from the state, returning it and the advanced state.
#[inline]
fn next_double(state: u64) -> (f64, u64) {
    let a = step(state);
    let b = step(a);
    (((((a >> 22) << 27) + (b >> 21)) as f64) / P53, b)
}

/// Generate `n` doubles starting from `seed` (the 48-bit state before the first
/// emitted value).
pub fn generate(seed: u64, n: usize) -> Vec<f64> {
    let mut state = seed & MASK;
    let mut out = Vec::with_capacity(n);
    for _ in 0..n {
        let (d, ns) = next_double(state);
        out.push(d);
        state = ns;
    }
    out
}

/// Recover the 48-bit seed (state before the first value) from observed outputs.
/// Verified by full reproduction, so `Some` is conclusive.
pub fn recover(values: &[f64]) -> Option<u64> {
    if values.len() < 2 {
        return None;
    }
    let m0 = (values[0] * P53).round() as u64;
    let hi0 = m0 >> 27; // next(26)
    let lo0 = m0 & ((1 << 27) - 1); // next(27)
    let inv = inv_mult();
    for x in 0..(1u64 << 22) {
        let s1 = (hi0 << 22) | x; // state after the first LCG step
        if step(s1) >> 21 == lo0 {
            let seed = prev(s1, inv);
            if generate(seed, values.len())
                .iter()
                .zip(values)
                .all(|(a, b)| (a - b).abs() < 1e-12)
            {
                return Some(seed);
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recover_round_trip() {
        let seed = 0x1234_5678_9abc & MASK;
        let vals = generate(seed, 200);
        assert_eq!(recover(&vals), Some(seed));
    }
}
