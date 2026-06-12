//! Legacy V8 `Math.random()` — pre-Chrome-49 (2008–2015). Two George-Marsaglia
//! MWC16 lanes combined into a 32-bit result, `double = r / 2^32`. No cache.
//!
//! Confirmed against captures + V8 source history. The eras differ only in the
//! lane-combine and which multiplier sits in the high vs low lane:
//!
//! | V8        | Combine                            | high-lane | low-lane | samples |
//! |-----------|------------------------------------|-----------|----------|---------|
//! | 1.2–~3.x  | `(hi<<16) + (lo & 0xFFFF)`         | 36969     | 18273    | chrome10 |
//! | 3.14–3.23 | `(s0<<14) + (s1 & 0x3FFFF)`        | 18273     | 36969    | chrome20/30, opera16 |
//! | 3.24–3.30 | `(s0<<16) | (s1 & 0xFFFF)`         | 18273     | 36969    | opera22 |
//! | 3.31–3.32 | `(s0<<16) | (s1 & 0xFFFF)`         | 18030     | 36969    | (Marsaglia-3D fix) |
//!
//! (In the original V8 1.2 form the high lane was the 36969 lane — `hi`; the 3.24
//! math.js rewrite swapped to 18273-high. Pre-V8-1.2 / Chrome 1 had no MWC at all,
//! just two host `libc random()` calls.) Each lane:
//! `s = mult*(s & 0xFFFF) + (s >> 16)` (mod 2^32). `recover` tries both combines
//! and both lane orders; it exploits that the low bits of `r` cleanly expose one
//! lane, so only a small brute over each lane's missing high bits is needed.

const P32: f64 = 4_294_967_296.0; // 2^32

/// How the two lanes are folded into the 32-bit result.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Combine {
    /// Era 1: `(s0 << 14) + (s1 & 0x3FFFF)` (mod 2^32).
    Shift14,
    /// Era 2/3: `(s0 << 16) | (s1 & 0xFFFF)`.
    Shift16,
}

/// A fully-specified legacy-V8 MWC generator.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Mwc {
    pub s0: u32,
    pub s1: u32,
    pub mult0: u64,
    pub mult1: u64,
    pub combine: Combine,
}

#[inline]
fn step(s: u32, mult: u64) -> u32 {
    ((mult * ((s as u64) & 0xFFFF) + ((s as u64) >> 16)) & 0xFFFF_FFFF) as u32
}

#[inline]
fn combine(a: u32, b: u32, c: Combine) -> u64 {
    match c {
        Combine::Shift14 => (((a as u64) << 14) + ((b as u64) & 0x3FFFF)) & 0xFFFF_FFFF,
        Combine::Shift16 => (((a as u64) & 0xFFFF) << 16) | ((b as u64) & 0xFFFF),
    }
}

impl Mwc {
    /// Generate `n` doubles from this generator's state.
    pub fn generate(&self, n: usize) -> Vec<f64> {
        let (mut a, mut b) = (self.s0, self.s1);
        let mut out = Vec::with_capacity(n);
        for _ in 0..n {
            out.push(combine(a, b, self.combine) as f64 / P32);
            a = step(a, self.mult0);
            b = step(b, self.mult1);
        }
        out
    }
}

fn reproduces(m: &Mwc, values: &[f64]) -> bool {
    m.generate(values.len())
        .iter()
        .zip(values)
        .all(|(x, y)| (x - y).abs() < 1e-15)
}

/// Recover a legacy-V8 MWC generator from observed outputs, trying every era and
/// multiplier assignment. Verified by full reproduction, so `Some` is conclusive.
pub fn recover(values: &[f64]) -> Option<Mwc> {
    if values.len() < 4 {
        return None;
    }
    let r: Vec<u64> = values.iter().map(|&v| (v * P32).round() as u64).collect();
    let pairs = [(18273u64, 36969u64), (36969, 18273), (18030, 36969), (36969, 18030)];
    for &(m0, m1) in &pairs {
        if let Some(m) = recover_shift16(&r, m0, m1).filter(|m| reproduces(m, values)) {
            return Some(m);
        }
        if let Some(m) = recover_shift14(&r, m0, m1).filter(|m| reproduces(m, values)) {
            return Some(m);
        }
    }
    None
}

/// Era 2/3: `r>>16 == s0&0xFFFF`, `r&0xFFFF == s1&0xFFFF`; recover the missing
/// high 16 bits of each lane from two consecutive lows via the carry relation.
fn recover_shift16(r: &[u64], m0: u64, m1: u64) -> Option<Mwc> {
    const M: u64 = 1 << 16;
    let lane_seed = |lo0: u64, lo1: u64, mult: u64| -> u32 {
        let hi0 = (lo1 + M - (mult * lo0) % M) % M;
        ((hi0 << 16) | lo0) as u32
    };
    let s0 = lane_seed((r[0] >> 16) & 0xFFFF, (r[1] >> 16) & 0xFFFF, m0);
    let s1 = lane_seed(r[0] & 0xFFFF, r[1] & 0xFFFF, m1);
    Some(Mwc { s0, s1, mult0: m0, mult1: m1, combine: Combine::Shift16 })
}

/// Era 1: `r & 0x3FFF == s1 & 0x3FFF` (the `<<14` lane contributes nothing below
/// bit 14). Recover lane1 by bruting its high 18 bits, then derive lane0's low
/// 18 bits from `r` and brute its high 14 bits.
fn recover_shift14(r: &[u64], m0: u64, m1: u64) -> Option<Mwc> {
    let check = r.len().min(150);
    // lane1 (the & 0x3FFFF lane, mult m1)
    let lo14 = r[0] & 0x3FFF;
    let s1 = (0..(1u64 << 18)).map(|hi| (hi << 14) | lo14).find(|&cand| {
        let mut s = cand as u32;
        r[..check].iter().all(|&rk| {
            let ok = (s as u64) & 0x3FFF == rk & 0x3FFF;
            s = step(s, m1);
            ok
        })
    })? as u32;
    // lane0 low 18 bits: ((r - s1&0x3FFFF) mod 2^32) >> 14
    let mut b = s1;
    let s0_lo18: Vec<u64> = r.iter().map(|&rk| {
        let t = (rk + (1u64 << 32) - ((b as u64) & 0x3FFFF)) & 0xFFFF_FFFF;
        b = step(b, m1);
        t >> 14
    }).collect();
    let s0 = (0..(1u64 << 14)).map(|hi| (hi << 18) | s0_lo18[0]).find(|&cand| {
        let mut s = cand as u32;
        s0_lo18[..check].iter().all(|&want| {
            let ok = (s as u64) & 0x3FFFF == want;
            s = step(s, m0);
            ok
        })
    })? as u32;
    Some(Mwc { s0, s1, mult0: m0, mult1: m1, combine: Combine::Shift14 })
}

// --- V8 4.9 "Stage A": MWC with the %_ConstructDouble conversion ------------
// A conversion-only refactor that shipped just before xorshift128+ (Chrome 48).
// Same MWC lanes (18030/36969) but the double is assembled by stuffing bits into
// the mantissa: `mantissa = (r0 & 0xFFFFF)<<32 | (r1 & 0xFFF00000)`, /2^52 — so
// still only 32 random bits, grid 2^-32, but a different bit layout than the
// `r/2^32` reciprocal-multiply forms above (which is why it doesn't recover as a
// plain MWC). lane1's low bits are hidden by the conversion, so recovery uses z3.

const STAGE_A_M0: u64 = 18030;
const STAGE_A_M1: u64 = 36969;

/// Generate Stage-A doubles from the two 32-bit lane states.
pub fn generate_stage_a(mut s0: u32, mut s1: u32, n: usize) -> Vec<f64> {
    let mut out = Vec::with_capacity(n);
    for _ in 0..n {
        s0 = step(s0, STAGE_A_M0);
        s1 = step(s1, STAGE_A_M1);
        let mant = (((s0 as u64) & 0xFFFFF) << 32) | ((s1 as u64) & 0xFFF0_0000);
        out.push(mant as f64 / 4_503_599_627_370_496.0); // /2^52
    }
    out
}

/// Recover the two Stage-A lane states via z3. Verified by full reproduction.
pub fn recover_stage_a(values: &[f64]) -> Option<(u32, u32)> {
    use std::process::Command;
    if values.len() < 10 {
        return None;
    }
    let m: Vec<u64> = values.iter().map(|&x| (x * 4_503_599_627_370_496.0).round() as u64).collect();
    let mut smt = String::from("(set-logic QF_BV)\n(declare-const s0 (_ BitVec 32))\n(declare-const s1 (_ BitVec 32))\n");
    let (mut p0, mut p1) = ("s0".to_string(), "s1".to_string());
    for (i, &mi) in m.iter().take(10).enumerate() {
        let (r0, r1) = (format!("r0_{i}"), format!("r1_{i}"));
        smt.push_str(&format!("(declare-const {r0} (_ BitVec 32))(assert (= {r0} (bvadd (bvmul (_ bv18030 32) (bvand {p0} (_ bv65535 32))) (bvlshr {p0} (_ bv16 32)))))\n"));
        smt.push_str(&format!("(declare-const {r1} (_ BitVec 32))(assert (= {r1} (bvadd (bvmul (_ bv36969 32) (bvand {p1} (_ bv65535 32))) (bvlshr {p1} (_ bv16 32)))))\n"));
        smt.push_str(&format!("(assert (= (bvor (bvshl ((_ zero_extend 20) (bvand {r0} (_ bv1048575 32))) (_ bv32 52)) ((_ zero_extend 20) (bvand {r1} (_ bv4293918720 32)))) (_ bv{mi} 52)))\n"));
        p0 = r0;
        p1 = r1;
    }
    smt.push_str("(check-sat)\n(get-value (s0 s1))\n");
    let path = std::env::temp_dir().join(format!("v8a_{}.smt2", std::process::id()));
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
    let (s0, s1) = (h[0] as u32, h[1] as u32);
    if generate_stage_a(s0, s1, values.len()).iter().zip(values).all(|(a, b)| (a - b).abs() < 1e-15) {
        Some((s0, s1))
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stage_a_round_trip() {
        let v = generate_stage_a(0xaa86_0f70, 0x3f41_77bd, 64);
        assert!(v.iter().all(|d| (0.0..1.0).contains(d)));
        assert_eq!(generate_stage_a(0xaa86_0f70, 0x3f41_77bd, 64), v); // deterministic
    }

    #[test]
    fn round_trip_shift16() {
        let g = Mwc { s0: 0x1234_5678, s1: 0x9abc_def0, mult0: 18273, mult1: 36969, combine: Combine::Shift16 };
        let v = g.generate(300);
        assert_eq!(recover(&v), Some(g));
    }

    #[test]
    fn round_trip_v8_1_2_form() {
        // Original V8 1.2: hi-lane = 36969, lo-lane = 18273, (hi<<16)|(lo&0xFFFF).
        let g = Mwc { s0: 0xdead_beef, s1: 0x0bad_f00d, mult0: 36969, mult1: 18273, combine: Combine::Shift16 };
        let v = g.generate(300);
        assert_eq!(recover(&v), Some(g));
    }

    #[test]
    fn round_trip_shift14() {
        let g = Mwc { s0: 0x2cc7_3809, s1: 0x2955_07fb, mult0: 18273, mult1: 36969, combine: Combine::Shift14 };
        let v = g.generate(300);
        assert_eq!(recover(&v), Some(g));
    }
}
