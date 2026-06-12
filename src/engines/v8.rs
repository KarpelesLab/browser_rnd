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

// --- early xorshift128+ (V8 4.9 "Stage B", Chrome ~49–55) -------------------
// Before the stable form above, V8's first xorshift128+ release used a DIFFERENT
// double conversion and serving order: `ToDouble = ((s0+s1) & mantissaMask) | exp`
// (low 52 bits of the *sum*, not `s0>>12`), served IN ORDER (cache slots 2..63
// ascending; state persisted in slots 0–1 — observationally a contiguous stream).
// The sum is nonlinear over GF(2), so recovery uses z3 (like SpiderMonkey).

const MANTISSA52: u64 = 0x000F_FFFF_FFFF_FFFF;
const P52: f64 = 4_503_599_627_370_496.0; // 2^52

/// Generate `n` doubles in the early-4.9 (Stage B) form: in-order, low 52 bits
/// of `s0+s1`.
pub fn generate_early(mut state: XorShift128Plus, n: usize) -> Vec<f64> {
    let mut out = Vec::with_capacity(n);
    for _ in 0..n {
        state.next_state();
        out.push((state.sum() & MANTISSA52) as f64 / P52);
    }
    out
}

/// Recover the early-4.9 (Stage B) state via z3. Returns `None` if z3 is missing
/// or the data isn't this variant. Verified by full reproduction.
pub fn recover_early(values: &[f64]) -> Option<XorShift128Plus> {
    use std::process::Command;
    if values.len() < 8 {
        return None;
    }
    let o: Vec<u64> = values.iter().map(|&x| (x * P52).round() as u64).collect();
    let mut smt = String::from(
        "(set-logic QF_BV)\n(declare-const s0 (_ BitVec 64))\n(declare-const s1 (_ BitVec 64))\n",
    );
    let (mut p0, mut p1) = ("s0".to_string(), "s1".to_string());
    for (i, &oi) in o.iter().take(8).enumerate() {
        let (t1, t2, f) = (format!("t1_{i}"), format!("t2_{i}"), format!("F_{i}"));
        smt.push_str(&format!("(declare-const {t1} (_ BitVec 64))(assert (= {t1} (bvxor {p0} (bvshl {p0} (_ bv23 64)))))\n"));
        smt.push_str(&format!("(declare-const {t2} (_ BitVec 64))(assert (= {t2} (bvxor {t1} (bvlshr {t1} (_ bv17 64)))))\n"));
        smt.push_str(&format!("(declare-const {f} (_ BitVec 64))(assert (= {f} (bvxor (bvxor {t2} {p1}) (bvlshr {p1} (_ bv26 64)))))\n"));
        smt.push_str(&format!("(assert (= ((_ extract 51 0) (bvadd {p1} {f})) (_ bv{oi} 52)))\n"));
        p0 = p1;
        p1 = f;
    }
    smt.push_str("(check-sat)\n(get-value (s0 s1))\n");
    let path = std::env::temp_dir().join(format!("v8b_{}.smt2", std::process::id()));
    std::fs::write(&path, &smt).ok()?;
    let out = Command::new("z3").arg("-T:120").arg(&path).output().ok()?;
    let _ = std::fs::remove_file(&path);
    let text = String::from_utf8_lossy(&out.stdout);
    if !text.contains("sat") || text.starts_with("unsat") {
        return None;
    }
    let h: Vec<u64> = text.split("#x").skip(1)
        .filter_map(|s| u64::from_str_radix(&s.chars().take_while(|c| c.is_ascii_hexdigit()).collect::<String>(), 16).ok())
        .collect();
    if h.len() < 2 {
        return None;
    }
    let state = XorShift128Plus::new(h[0], h[1]);
    if generate_early(state, values.len()).iter().zip(values).all(|(a, b)| (a - b).abs() < 1e-15) {
        Some(state)
    } else {
        None
    }
}

// --- V8 5.1–5.3 (Chrome 52–53, Opera 38–40) ---------------------------------
// Same Stage-B conversion `(s0+s1) & mantissaMask`, but the cache serving order
// REVERSED: each batch fills slots 2..63 forward (62 outputs) and is served
// top-down (slot 63 first, down to slot 2). So within each batch of 62 the
// observed order is the reverse of generation order. (Conversion stays sum-based
// until ~V8 7.0 / Chrome 70, which is when `s0>>12` + the FixedDoubleArray cache
// land — that's the stable form `recover` handles.)

const BATCH_5X: usize = 62;

/// Solve the in-order Stage-B system (`(s0+s1)&mask52`) for 8 outputs via z3.
fn z3_sum_low52(o: &[u64]) -> Option<(u64, u64)> {
    use std::process::Command;
    let mut smt = String::from("(set-logic QF_BV)\n(declare-const s0 (_ BitVec 64))\n(declare-const s1 (_ BitVec 64))\n");
    let (mut p0, mut p1) = ("s0".to_string(), "s1".to_string());
    for (i, &oi) in o.iter().take(8).enumerate() {
        let (t1, t2, f) = (format!("t1_{i}"), format!("t2_{i}"), format!("F_{i}"));
        smt.push_str(&format!("(declare-const {t1} (_ BitVec 64))(assert (= {t1} (bvxor {p0} (bvshl {p0} (_ bv23 64)))))\n"));
        smt.push_str(&format!("(declare-const {t2} (_ BitVec 64))(assert (= {t2} (bvxor {t1} (bvlshr {t1} (_ bv17 64)))))\n"));
        smt.push_str(&format!("(declare-const {f} (_ BitVec 64))(assert (= {f} (bvxor (bvxor {t2} {p1}) (bvlshr {p1} (_ bv26 64)))))\n"));
        smt.push_str(&format!("(assert (= ((_ extract 51 0) (bvadd {p1} {f})) (_ bv{oi} 52)))\n"));
        p0 = p1;
        p1 = f;
    }
    smt.push_str("(check-sat)\n(get-value (s0 s1))\n");
    let path = std::env::temp_dir().join(format!("v85x_{}.smt2", std::process::id()));
    std::fs::write(&path, &smt).ok()?;
    let out = Command::new("z3").arg("-T:30").arg(&path).output().ok()?;
    let _ = std::fs::remove_file(&path);
    let text = String::from_utf8_lossy(&out.stdout);
    if !text.contains("sat") || text.starts_with("unsat") {
        return None;
    }
    let h: Vec<u64> = text.split("#x").skip(1)
        .filter_map(|s| u64::from_str_radix(&s.chars().take_while(|c| c.is_ascii_hexdigit()).collect::<String>(), 16).ok())
        .collect();
    if h.len() < 2 { None } else { Some((h[0], h[1])) }
}

/// Generate `n` doubles in the V8 5.1–5.3 form: batches of 62 (`(s0+s1)&mask52`)
/// served in reverse, starting from `seed` (state before the first generated).
pub fn generate_5x(seed: XorShift128Plus, n: usize) -> Vec<f64> {
    let mut st = seed;
    let mut out = Vec::with_capacity(n + BATCH_5X);
    while out.len() < n {
        let mut batch = Vec::with_capacity(BATCH_5X);
        for _ in 0..BATCH_5X {
            st.next_state();
            batch.push((st.sum() & MANTISSA52) as f64 / P52);
        }
        for d in batch.into_iter().rev() {
            if out.len() < n {
                out.push(d);
            }
        }
    }
    out
}

/// Recover the V8 5.1–5.3 state + batch offset via z3. For batch offset `o`,
/// `values[0..62-o]` reversed is the in-order generation prefix, which the
/// Stage-B solver pins. Returns `(seed, offset)`; verified by full reproduction.
pub fn recover_5x(values: &[f64]) -> Option<(XorShift128Plus, usize)> {
    if values.len() < BATCH_5X + 8 {
        return None;
    }
    for o in 0..BATCH_5X - 8 {
        let take = BATCH_5X - o;
        let mut win: Vec<f64> = values[..take].to_vec();
        win.reverse();
        let o8: Vec<u64> = win[..8].iter().map(|&x| (x * P52).round() as u64).collect();
        let Some((s0, s1)) = z3_sum_low52(&o8) else { continue };
        let seed = XorShift128Plus::new(s0, s1);
        let regen = generate_5x(seed, o + values.len());
        if regen[o..].iter().zip(values).all(|(a, b)| (a - b).abs() < 1e-15) {
            return Some((seed, o));
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn early_round_trip() {
        let seed = XorShift128Plus::new(0xabcd_1234_5678_9012, 0x1111_2222_3333_4444);
        let v = generate_early(seed, 100);
        // forward model self-consistency (recover needs z3; covered in tests/recover.rs)
        assert!(v.iter().all(|d| (0.0..1.0).contains(d)));
        assert_eq!(generate_early(seed, 100), v);
    }

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
