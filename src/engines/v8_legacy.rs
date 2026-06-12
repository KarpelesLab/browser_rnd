//! Legacy V8 `Math.random()` — pre-Chrome-49 (2008–2015), e.g. Chrome 10/20/30,
//! Opera 15–35.
//!
//! Two independent George-Marsaglia MWC16 lanes combined into a 32-bit result:
//! ```text
//! s0 = 18273 * (s0 & 0xffff) + (s0 >> 16)
//! s1 = 36969 * (s1 & 0xffff) + (s1 >> 16)
//! r  = ((s0 & 0xffff) << 16) | (s1 & 0xffff)
//! double = r * 2^-32
//! ```
//! No cache/reversal (that came with the xorshift128+ rewrite), so the stream is
//! contiguous from the first observed value. Confirmed by full reproduction of
//! `samples/v8/opera22.txt` (see `tests/recover.rs`).
//!
//! Recovery: `r` directly exposes the low 16 bits of each lane; the missing high
//! 16 bits of a lane follow from two consecutive lows via the MWC carry
//! relation, so no search is needed.

const MULT0: u64 = 18273;
const MULT1: u64 = 36969;
const P32: f64 = 4_294_967_296.0; // 2^32
const M16: u64 = 1 << 16;

#[inline]
fn lane_step(s: u32, mult: u64) -> u32 {
    (mult * ((s as u64) & 0xFFFF) + ((s as u64) >> 16)) as u32
}

/// Generate `n` doubles from the two 32-bit lane states.
pub fn generate(mut s0: u32, mut s1: u32, n: usize) -> Vec<f64> {
    let mut out = Vec::with_capacity(n);
    for _ in 0..n {
        let r = (((s0 as u64) & 0xFFFF) << 16) | ((s1 as u64) & 0xFFFF);
        out.push(r as f64 / P32);
        s0 = lane_step(s0, MULT0);
        s1 = lane_step(s1, MULT1);
    }
    out
}

/// Recover the missing high 16 bits of a lane from two consecutive lows.
fn lane_seed(lo0: u64, lo1: u64, mult: u64) -> u32 {
    let hi0 = (lo1 + M16 - (mult * lo0) % M16) % M16;
    ((hi0 << 16) | lo0) as u32
}

/// Recover both lane states (the seed producing `values[0]`) from observed
/// outputs. Verified by full reproduction, so `Some` is conclusive.
pub fn recover(values: &[f64]) -> Option<(u32, u32)> {
    if values.len() < 3 {
        return None;
    }
    let r: Vec<u64> = values.iter().map(|&v| (v * P32).round() as u64).collect();
    let a: Vec<u64> = r.iter().map(|x| (x >> 16) & 0xFFFF).collect();
    let b: Vec<u64> = r.iter().map(|x| x & 0xFFFF).collect();
    let s0 = lane_seed(a[0], a[1], MULT0);
    let s1 = lane_seed(b[0], b[1], MULT1);
    if generate(s0, s1, values.len())
        .iter()
        .zip(values)
        .all(|(x, y)| (x - y).abs() < 1e-15)
    {
        Some((s0, s1))
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recover_round_trip() {
        let vals = generate(0x1234_5678, 0x9abc_def0, 300);
        assert_eq!(recover(&vals), Some((0x1234_5678, 0x9abc_def0)));
    }
}
