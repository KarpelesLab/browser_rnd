//! Internet Explorer `Math.random()` — JScript (IE 6/7/8) AND early Chakra
//! (IE 9/10/11). Both use the **same** generator: a POSIX drand48-style 48-bit
//! LCG (identical constants to legacy SpiderMonkey / `java.util.Random`), with
//! **two** steps per call producing a 54-bit double:
//!
//! ```text
//! state = (state * 0x5DEECE66D + 0xB) mod 2^48        // per step
//! sn   = step(state); hi = sn >> 21;                  // high 27 bits
//! state= step(sn);    lo = state >> 21;               // high 27 bits
//! double = (hi * 2^27 + lo) / 2^54                    // 54-bit, grid 2^-54
//! ```
//!
//! Confirmed by full reproduction of every IE capture in `samples/ie/` plus
//! `ie10`/`ie11` (4095–4096/4096). (Later Chakra switched to xorshift128+.)
//!
//! Note the engine emits 54 bits — one more than the 53-bit norm — so values are
//! on the 2^-54 grid. The low bit of a value ≥ 0.5 is rounded away by f64, so
//! recovery anchors on a value < 0.5 (exact) and verifies by value.

const MULT: u64 = 0x5DEECE66D;
const ADD: u64 = 0xB;
const MASK: u64 = (1 << 48) - 1;
const P54: f64 = 18_014_398_509_481_984.0; // 2^54

#[inline]
fn step(s: u64) -> u64 {
    s.wrapping_mul(MULT).wrapping_add(ADD) & MASK
}

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

/// Generate `n` doubles from `seed` (the 48-bit state before the first output).
pub fn generate(seed: u64, n: usize) -> Vec<f64> {
    let mut state = seed & MASK;
    let mut out = Vec::with_capacity(n);
    for _ in 0..n {
        let sn = step(state);
        let hi = sn >> 21;
        state = step(sn);
        let lo = state >> 21;
        out.push(((hi << 27) + lo) as f64 / P54);
    }
    out
}

/// Recover the 48-bit seed (state before the first output) from observed values.
/// Brute-forces the 21 hidden low bits of the first state at an anchor value
/// < 0.5, then steps back to the seed. Verified by full reproduction.
pub fn recover(values: &[f64]) -> Option<u64> {
    if values.len() < 3 {
        return None;
    }
    let a0 = (0..values.len()).find(|&i| values[i] < 0.5)?;
    let n0 = (values[a0] * P54).round() as u64;
    let hi = n0 >> 27;
    let lo = n0 & ((1 << 27) - 1);
    let inv = inv_mult();
    for x in 0..(1u64 << 21) {
        let s1 = (hi << 21) | x; // first stepped state of output a0
        if step(s1) >> 21 != lo {
            continue;
        }
        // seed before output 0 = prev applied (2*a0 + 1) times to s1
        let mut seed = s1;
        for _ in 0..(2 * a0 + 1) {
            seed = prev(seed, inv);
        }
        if generate(seed, values.len())
            .iter()
            .zip(values)
            .all(|(a, b)| (a - b).abs() < 1e-12)
        {
            return Some(seed);
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
        let v = generate(seed, 300);
        assert_eq!(recover(&v), Some(seed));
    }
}
