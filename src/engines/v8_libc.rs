//! Oldest V8 `Math.random()` — Chrome 1 (V8 0.3.x, 2008), before V8 had its own
//! PRNG. It just combined two host `libc random()` calls (`src/runtime.cc`):
//!
//! ```text
//! lo = random() / (RAND_MAX + 1.0)   // FIRST call  -> low part
//! hi = random()                      // SECOND call -> high part
//! result = (hi + lo) / (RAND_MAX + 1.0)
//! ```
//!
//! On Windows (the `chrome1-2008` capture) `random()` is the MSVCRT `rand()` LCG
//! with `RAND_MAX = 0x7FFF`, so each call yields 15 bits and
//! `N = hi·2¹⁵ + lo` (grid 2⁻³⁰). rand(): `s = s*214013 + 2531011 (mod 2³²)`,
//! output `(s >> 16) & 0x7FFF`. Confirmed by full reproduction of
//! `samples/v8/chrome1-2008.txt`.
//!
//! PLATFORM-SPECIFIC: this models the Windows/MSVCRT build. A Linux/macOS Chrome 1
//! would use glibc's additive-feedback `random()` instead (different model).

const A: u64 = 214013;
const C: u64 = 2531011;
const MOD: u64 = 1 << 32;
const P30: f64 = 1_073_741_824.0; // 2^30

#[inline]
fn lcg(s: u32) -> u32 {
    (((s as u64).wrapping_mul(A).wrapping_add(C)) & (MOD - 1)) as u32
}
#[inline]
fn rand_out(s: u32) -> u64 {
    ((s >> 16) & 0x7FFF) as u64
}

fn inv_a() -> u64 {
    let mut x = 1u64;
    for _ in 0..6 {
        x = x.wrapping_mul(2u64.wrapping_sub(A.wrapping_mul(x)));
    }
    x & (MOD - 1)
}

/// Generate `n` doubles from the MSVCRT `rand()` state before the first call.
pub fn generate(state: u32, n: usize) -> Vec<f64> {
    let mut s = state;
    let mut out = Vec::with_capacity(n);
    for _ in 0..n {
        s = lcg(s);
        let lo = rand_out(s); // first call -> low
        s = lcg(s);
        let hi = rand_out(s); // second call -> high
        out.push(((hi << 15) | lo) as f64 / P30);
    }
    out
}

/// Recover the 32-bit `rand()` state (before the first call) from observed
/// values. Brutes the 17 bits of the first-call state not pinned by its 15-bit
/// output. Verified by full reproduction, so `Some` is conclusive.
pub fn recover(values: &[f64]) -> Option<u32> {
    if values.len() < 3 {
        return None;
    }
    let n: Vec<u64> = values.iter().map(|&v| (v * P30).round() as u64).collect();
    let lo0 = n[0] & 0x7FFF; // first call output
    let hi0 = n[0] >> 15; // second call output
    let inv = inv_a();
    for x in 0..(1u64 << 17) {
        // first-call state: bits 16..30 = lo0; brute low 16 bits + bit 31
        let s1 = (((x >> 16) << 31) | (lo0 << 16) | (x & 0xFFFF)) as u32;
        if rand_out(lcg(s1)) != hi0 {
            continue;
        }
        // state before the first call = prev(s1)
        let pre = ((((s1 as u64) + MOD - C) & (MOD - 1)).wrapping_mul(inv) & (MOD - 1)) as u32;
        if generate(pre, values.len())
            .iter()
            .zip(values)
            .all(|(a, b)| (a - b).abs() < 1e-12)
        {
            return Some(pre);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recover_round_trip() {
        let v = generate(0x1357_9bdf, 300);
        let st = recover(&v).expect("recover");
        assert!(generate(st, 300).iter().zip(&v).all(|(a, b)| (a - b).abs() < 1e-12));
    }
}
