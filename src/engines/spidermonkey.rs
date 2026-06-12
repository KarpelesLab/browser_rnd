//! SpiderMonkey `Math.random()` — Firefox and other Gecko browsers.
//!
//! State transition: xorshift128+ with shifts (23,17,26), identical to V8.
//! Output conversion uses the **low 53 bits** of the post-step sum (confirmed by
//! z3 recovery of `samples/firefox100.txt` and `mypal68.txt`):
//!
//! ```text
//! double = ((s0 + s1) & (2^53 - 1)) as f64 * 2^-53
//! ```
//!
//! (V8 instead uses the top 52 mantissa bits of `s0`; this low-53-of-the-sum
//! form is what distinguishes SpiderMonkey.) SpiderMonkey serves values
//! one-per-step in generation order — no reversed cache.
//!
//! Recovery is NOT GF(2)-linear (the integer addition is nonlinear over GF(2)),
//! so state recovery uses an SMT solver — see `relab`'s `smz3` experiment, which
//! recovers the 128-bit state from ~6 outputs via z3.
//!
//! VERSION SPLIT — this module models *modern* SpiderMonkey only. Gecko switched
//! `Math.random()` to xorshift128+ around Firefox 49 (2016). Earlier Firefox
//! (e.g. the 1.0 / rv:1.7 captures in `samples/`) used a legacy drand48-style
//! 48-bit LCG instead:
//!   state = (state * 0x5DEECE66D + 0xB) mod 2^48
//!   double = ((next(26) << 27) + next(27)) * 2^-53
//! Both produce 53-bit doubles, so the structural fingerprint cannot tell them
//! apart — only reproduction can. The legacy LCG path is not implemented yet;
//! see the `samples/` Firefox-1.0 fixture, which is the target for it.

use crate::prng::XorShift128Plus;

const TWO_POW_53: f64 = 9_007_199_254_740_992.0; // 2^53
const MASK_53: u64 = (1 << 53) - 1;

/// Convert a post-step sum (`s0 + s1`) to the double SpiderMonkey returns.
#[inline]
pub fn to_double(sum: u64) -> f64 {
    ((sum & MASK_53) as f64) / TWO_POW_53
}

/// Recover the low 53 bits of the sum from an observed double.
#[inline]
pub fn sum_low_bits(value: f64) -> u64 {
    (value * TWO_POW_53) as u64
}

/// Generate `n` doubles in observed order, starting from `state`.
pub fn generate(mut state: XorShift128Plus, n: usize) -> Vec<f64> {
    let mut out = Vec::with_capacity(n);
    for _ in 0..n {
        state.next_state();
        out.push(to_double(state.sum()));
    }
    out
}

/// Recover the 128-bit state from observed outputs using the `z3` SMT solver
/// (the `s0+s1` addition is nonlinear over GF(2), so no closed-form solve). The
/// returned state, fed to [`generate`], reproduces the capture. Returns `None`
/// if z3 is unavailable or the data doesn't match SpiderMonkey. Verified by full
/// reproduction, so `Some` is conclusive.
pub fn recover(values: &[f64]) -> Option<XorShift128Plus> {
    use std::process::Command;
    if values.len() < 8 {
        return None;
    }
    let o: Vec<u64> = values.iter().map(|&x| (x * TWO_POW_53).round() as u64).collect();
    let mut smt = String::from(
        "(set-logic QF_BV)\n(declare-const s0 (_ BitVec 64))\n(declare-const s1 (_ BitVec 64))\n",
    );
    let (mut p0, mut p1) = ("s0".to_string(), "s1".to_string());
    for (i, &oi) in o.iter().take(8).enumerate() {
        let (t1, t2, f) = (format!("t1_{i}"), format!("t2_{i}"), format!("F_{i}"));
        smt.push_str(&format!("(declare-const {t1} (_ BitVec 64))(assert (= {t1} (bvxor {p0} (bvshl {p0} (_ bv23 64)))))\n"));
        smt.push_str(&format!("(declare-const {t2} (_ BitVec 64))(assert (= {t2} (bvxor {t1} (bvlshr {t1} (_ bv17 64)))))\n"));
        smt.push_str(&format!("(declare-const {f} (_ BitVec 64))(assert (= {f} (bvxor (bvxor {t2} {p1}) (bvlshr {p1} (_ bv26 64)))))\n"));
        smt.push_str(&format!("(assert (= ((_ extract 52 0) (bvadd {p1} {f})) (_ bv{oi} 53)))\n"));
        p0 = p1;
        p1 = f;
    }
    smt.push_str("(check-sat)\n(get-value (s0 s1))\n");
    let dir = std::env::temp_dir().join(format!("sm_recover_{}.smt2", std::process::id()));
    std::fs::write(&dir, &smt).ok()?;
    let out = Command::new("z3").arg("-T:60").arg(&dir).output().ok()?;
    let _ = std::fs::remove_file(&dir);
    let text = String::from_utf8_lossy(&out.stdout);
    if !text.contains("sat") || text.starts_with("unsat") {
        return None;
    }
    let h: Vec<u64> = text
        .split("#x")
        .skip(1)
        .filter_map(|s| {
            u64::from_str_radix(&s.chars().take_while(|c| c.is_ascii_hexdigit()).collect::<String>(), 16).ok()
        })
        .collect();
    if h.len() < 2 {
        return None;
    }
    let state = XorShift128Plus::new(h[0], h[1]);
    if generate(state, values.len())
        .iter()
        .zip(values)
        .all(|(a, b)| (a - b).abs() < 1e-15)
    {
        Some(state)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn to_double_in_unit_interval() {
        for bits in [0u64, u64::MAX, 0x1234_5678_9abc_def0] {
            let d = to_double(bits);
            assert!((0.0..1.0).contains(&d), "{d} out of range");
        }
    }

    #[test]
    fn low_bits_round_trip() {
        let sum = 0x0000_0000_0000_0FFFu64 | (0x1A << 53);
        let d = to_double(sum);
        assert_eq!(sum_low_bits(d), sum & MASK_53);
    }
}
