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

// --- state recovery (GF(2)) -------------------------------------------------
// xorshift128+ is linear over GF(2) and V8's output is the top 52 bits of `s0`
// (no nonlinear integer addition, unlike SpiderMonkey/JSC), so the seed is
// recoverable by Gaussian elimination over a handful of observed values. The
// only unknown beyond the seed is the batch offset: the cache is global to the
// context, so a capture rarely starts on a 64-batch boundary — we search it.

use crate::gf2::solve_128;

type Sym = [u128; 64]; // each entry: which seed bits XOR into this state bit

fn sym_shl(x: &Sym, n: usize) -> Sym {
    let mut o = [0u128; 64];
    o[n..64].copy_from_slice(&x[..64 - n]);
    o
}
fn sym_shr(x: &Sym, n: usize) -> Sym {
    let mut o = [0u128; 64];
    o[..64 - n].copy_from_slice(&x[n..64]);
    o
}
fn sym_xor(a: &Sym, b: &Sym) -> Sym {
    let mut o = [0u128; 64];
    for i in 0..64 {
        o[i] = a[i] ^ b[i];
    }
    o
}

/// Symbolic xorshift128+ step, mirroring [`XorShift128Plus::next_state`].
fn sym_step(s0: &Sym, s1: &Sym) -> (Sym, Sym) {
    let mut t = *s0;
    let s0_old = *s1;
    t = sym_xor(&t, &sym_shl(&t, 23));
    t = sym_xor(&t, &sym_shr(&t, 17));
    t = sym_xor(&t, &s0_old);
    t = sym_xor(&t, &sym_shr(&s0_old, 26));
    (s0_old, t)
}

/// Observed index `j` at batch offset `o` maps to generation index: the cache is
/// filled gen[0..63] then served reversed, so serve[k] = gen[63 - (k mod 64)].
fn gen_index(o: usize, j: usize) -> usize {
    let serve = o + j;
    (serve / 64) * 64 + (63 - serve % 64)
}

/// Recover the seed state and batch offset from observed `Math.random()` values.
/// Returns `(seed, offset)` such that `generate(seed, offset + values.len())`
/// reproduces the capture after dropping the first `offset` served values.
/// Verified by full reproduction, so a `Some` result is conclusive.
pub fn recover(values: &[f64]) -> Option<(XorShift128Plus, usize)> {
    if values.len() < 8 {
        return None;
    }
    // Symbolic s0 after (g+1) steps, for 3 batches' worth of generation indices.
    let mut s0: Sym = std::array::from_fn(|i| 1u128 << i);
    let mut s1: Sym = std::array::from_fn(|i| 1u128 << (64 + i));
    let mut sym_for_gen: Vec<Sym> = Vec::with_capacity(192);
    for _ in 0..192 {
        let (n0, n1) = sym_step(&s0, &s1);
        s0 = n0;
        s1 = n1;
        sym_for_gen.push(s0);
    }

    let n_eq = values.len().min(60);
    for o in 0..CACHE_SIZE {
        let mut rows: Vec<(u128, u8)> = Vec::with_capacity(n_eq * 52);
        for j in 0..n_eq {
            let g = gen_index(o, j);
            if g >= sym_for_gen.len() {
                break;
            }
            let m = s0_high_bits(values[j]) >> 12; // 52-bit mantissa
            for b in 0..52 {
                rows.push((sym_for_gen[g][12 + b], ((m >> b) & 1) as u8));
            }
        }
        let Some(sol) = solve_128(rows) else { continue };
        let seed = XorShift128Plus::new(sol as u64, (sol >> 64) as u64);
        let regen = generate(seed, o + values.len());
        if regen[o..]
            .iter()
            .zip(values)
            .all(|(a, b)| (a - b).abs() < 1e-15)
        {
            return Some((seed, o));
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recover_round_trip() {
        let seed = XorShift128Plus::new(0x1234_5678_9abc_def0, 0x0fed_cba9_8765_4321);
        // Simulate a capture starting 5 values into a batch.
        let full = generate(seed, 5 + 300);
        let observed = &full[5..];
        let (rec, off) = recover(observed).expect("recover");
        assert_eq!(off, 5);
        assert_eq!(generate(rec, 5 + 300)[5..], full[5..]);
    }

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
