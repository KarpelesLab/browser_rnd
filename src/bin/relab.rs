//! Reverse-engineering lab: a scratch harness for discovering/confirming the
//! recurrence behind a capture, by reproducing the full observed sequence.
//! Once an algorithm is confirmed here it gets promoted into `recover.rs` with a
//! validating test. Run: `cargo run --bin relab -- <experiment> <sample.txt>`.

use std::env;
use std::fs;

use browser_rnd::sample::Sample;

const P53: f64 = 9_007_199_254_740_992.0; // 2^53

fn load(path: &str) -> Sample {
    let text = fs::read_to_string(path).expect("read sample");
    Sample::parse(&text).expect("parse sample")
}

/// For each k in a range, report whether every value is an exact multiple of
/// 2^-k (i.e. value * 2^k is integral). The smallest such k is the output width
/// and pins the double-conversion denominator.
fn conv(values: &[f64]) {
    for k in [30u32, 31, 32, 48, 52, 53, 54, 55, 56, 60, 62, 63] {
        let scale = 2f64.powi(k as i32);
        let mut max_err = 0.0f64;
        for &v in values {
            let scaled = v * scale;
            let err = (scaled - scaled.round()).abs();
            if err > max_err {
                max_err = err;
            }
        }
        println!("  2^-{k}: max fractional error = {max_err:.3e}  {}",
            if max_err < 1e-3 { "<-- integral" } else { "" });
    }
}

// ---- drand48 / old SpiderMonkey -------------------------------------------
const D_MULT: u64 = 0x5DEECE66D;
const D_ADD: u64 = 0xB;
const D_MASK: u64 = (1 << 48) - 1;

fn d_step(s: u64) -> u64 {
    s.wrapping_mul(D_MULT).wrapping_add(D_ADD) & D_MASK
}
fn d_double(state_before: u64) -> (f64, u64) {
    let s1 = d_step(state_before);
    let s2 = d_step(s1);
    let hi = s1 >> 22; // next(26)
    let lo = s2 >> 21; // next(27)
    (((hi << 27) + lo) as f64 / P53, s2)
}

fn crack_drand48(values: &[f64]) {
    let m0 = (values[0] * P53).round() as u64;
    let hi0 = m0 >> 27;
    let lo0 = m0 & ((1 << 27) - 1);
    println!("  m0={m0} hi0={hi0} lo0={lo0}");
    let mut found = 0;
    for x in 0..(1u64 << 22) {
        let s1 = (hi0 << 22) | x;
        let s2 = d_step(s1);
        if (s2 >> 21) == lo0 {
            // s2 == state after producing values[0]; verify forward.
            let mut state = s2;
            let mut ok = 0usize;
            for &v in &values[1..] {
                let (d, ns) = d_double(state);
                if (d - v).abs() < 1e-12 {
                    ok += 1;
                    state = ns;
                } else {
                    break;
                }
            }
            println!("  candidate x={x:#x} s2={s2:#x} reproduced {}/{} forward",
                ok, values.len() - 1);
            if ok == values.len() - 1 {
                found += 1;
            }
        }
    }
    println!("  => {found} fully-matching state(s)");
}

// ---- MWC1616 / old V8 ------------------------------------------------------
const M16: u64 = 1 << 16;

/// One MWC16 lane: state = mult*(state & 0xffff) + (state >> 16).
fn mwc_lane_step(s: u64, mult: u64) -> u64 {
    mult * (s & 0xFFFF) + (s >> 16)
}

/// Given the observed low-16-bit sequence of a lane, find the multiplier C whose
/// carry relation holds for the most samples (NON-breaking count, so a single
/// glitch near the start doesn't zero the score). Returns best (C, score, n-2).
fn best_mwc_mult(lo: &[u64], window: usize) -> (u64, usize) {
    let n = lo.len().min(window);
    let (mut best_c, mut best_score) = (0u64, 0usize);
    for c in 1u64..M16 {
        let mut score = 0usize;
        for i in 1..n - 1 {
            let hi_im1 = (lo[i] + M16 - (c * lo[i - 1]) % M16) % M16;
            let hi_i = (lo[i + 1] + M16 - (c * lo[i]) % M16) % M16;
            if ((c * lo[i - 1] + hi_im1) >> 16) & 0xFFFF == hi_i {
                score += 1;
            }
        }
        if score > best_score {
            best_score = score;
            best_c = c;
        }
    }
    (best_c, best_score)
}

/// Full MWC1616 crack: split r into two lanes by the given bit layout, recover
/// both states, regenerate, and report how many of the N values reproduce.
/// `layout` = (lane0_shift, lane_bits): r = (lane0 << lane0_shift) | lane1, each
/// lane `lane_bits` wide.
fn crack_mwc(values: &[f64], scale_bits: u32, lane0_shift: u32, lane_bits: u32) {
    let scale = 2f64.powi(scale_bits as i32);
    let r: Vec<u64> = values.iter().map(|&v| (v * scale).round() as u64).collect();
    let lane_mask = (1u64 << lane_bits) - 1;
    let a: Vec<u64> = r.iter().map(|x| (x >> lane0_shift) & lane_mask).collect();
    let b: Vec<u64> = r.iter().map(|x| x & lane_mask).collect();
    println!("  scale 2^{scale_bits}, layout (a<<{lane0_shift})|b, {lane_bits} bits/lane");

    // Lanes only have 16-bit MWC structure when lane_bits==16; otherwise this is
    // a probe and best_mwc_mult will just report low scores.
    let (c0, s0) = best_mwc_mult(&a, 80);
    let (c1, s1) = best_mwc_mult(&b, 80);
    println!("  lane0: mult={c0} consistency={s0}/78   lane1: mult={c1} consistency={s1}/78");
    if s0 < 40 || s1 < 40 {
        println!("  (low consistency — wrong layout/scale for this sample)");
        return;
    }
    // Reproduce from each candidate start offset; report the longest run.
    let (mut best_start, mut best_run) = (0usize, 0usize);
    for start in 0..r.len().min(8) {
        let hi0a = (a[start + 1] + M16 - (c0 * a[start]) % M16) % M16;
        let hi0b = (b[start + 1] + M16 - (c1 * b[start]) % M16) % M16;
        let mut st0 = (hi0a << 16) | a[start];
        let mut st1 = (hi0b << 16) | b[start];
        let mut run = 0usize;
        for &want in &r[start..] {
            let pred = ((st0 & lane_mask) << lane0_shift) | (st1 & lane_mask);
            if pred != want {
                break;
            }
            run += 1;
            st0 = mwc_lane_step(st0, c0);
            st1 = mwc_lane_step(st1, c1);
        }
        if run > best_run {
            best_run = run;
            best_start = start;
        }
    }
    println!(
        "  reproduced {best_run}/{} from offset {best_start} (mult0={c0}, mult1={c1})",
        r.len() - best_start
    );
}

// ---- modern V8 xorshift128+ via GF(2) linear algebra -----------------------
// xorshift128+ is linear over GF(2); V8's output is the top 52 bits of s0 (no
// integer addition), so every observed bit is a linear equation in the 128 seed
// bits. Collect enough equations, Gaussian-eliminate, recover the seed.

type Sym = [u128; 64]; // each entry: which of the 128 seed bits XOR into this bit

fn sym_shl(x: &Sym, n: usize) -> Sym {
    let mut o = [0u128; 64];
    for i in n..64 {
        o[i] = x[i - n];
    }
    o
}
fn sym_shr(x: &Sym, n: usize) -> Sym {
    let mut o = [0u128; 64];
    for i in 0..64 - n {
        o[i] = x[i + n];
    }
    o
}
fn sym_xor(a: &Sym, b: &Sym) -> Sym {
    let mut o = [0u128; 64];
    for i in 0..64 {
        o[i] = a[i] ^ b[i];
    }
    o
}

/// Symbolic xorshift128+ step on (s0,s1) bit-symbol arrays, mirroring
/// XorShift128Plus::next_state exactly (V8 shifts 23,17,26).
fn sym_step(s0: &Sym, s1: &Sym) -> (Sym, Sym) {
    sym_step_shifts(s0, s1, 23, 17, 26)
}

fn sym_step_shifts(s0: &Sym, s1: &Sym, a: usize, b: usize, c: usize) -> (Sym, Sym) {
    let mut t = *s0;
    let s0_old = *s1;
    t = sym_xor(&t, &sym_shl(&t, a));
    t = sym_xor(&t, &sym_shr(&t, b));
    t = sym_xor(&t, &s0_old);
    t = sym_xor(&t, &sym_shr(&s0_old, c));
    (s0_old, t)
}

/// Solve a GF(2) system for 128 unknowns via Gauss-Jordan. Each row: (coeff over
/// 128 seed bits, rhs). Returns the seed bits, or None if inconsistent.
fn solve_gf2(mut mat: Vec<(u128, u8)>) -> Option<u128> {
    let mut pivot_for_col = [usize::MAX; 128];
    let mut r = 0usize;
    for col in 0..128 {
        let sel = (r..mat.len()).find(|&k| (mat[k].0 >> col) & 1 == 1);
        let Some(sel) = sel else { continue };
        mat.swap(r, sel);
        for k in 0..mat.len() {
            if k != r && (mat[k].0 >> col) & 1 == 1 {
                mat[k].0 ^= mat[r].0;
                mat[k].1 ^= mat[r].1;
            }
        }
        pivot_for_col[col] = r;
        r += 1;
    }
    if mat.iter().any(|&(c, b)| c == 0 && b == 1) {
        return None; // inconsistent
    }
    let mut sol: u128 = 0;
    for col in 0..128 {
        let pr = pivot_for_col[col];
        if pr != usize::MAX && mat[pr].1 == 1 {
            sol |= 1u128 << col;
        }
    }
    Some(sol)
}

/// Map observed index j (at batch offset `o`) to its generation index, given the
/// cache is filled gen[0..63] then served reversed (serve[k]=gen[63 - k%64]).
fn gen_index(o: usize, j: usize) -> usize {
    let serve = o + j;
    let batch = serve / 64;
    let pos = serve % 64;
    batch * 64 + (63 - pos)
}

/// GF(2) solve that returns the pivot/particular solution, IGNORING inconsistent
/// rows (used for fixed-point iteration where carries may be wrong).
fn solve_gf2_any(mut mat: Vec<(u128, u8)>) -> u128 {
    let mut pivot_for_col = [usize::MAX; 128];
    let mut r = 0usize;
    for col in 0..128 {
        let Some(sel) = (r..mat.len()).find(|&k| (mat[k].0 >> col) & 1 == 1) else { continue };
        mat.swap(r, sel);
        for k in 0..mat.len() {
            if k != r && (mat[k].0 >> col) & 1 == 1 {
                mat[k].0 ^= mat[r].0;
                mat[k].1 ^= mat[r].1;
            }
        }
        pivot_for_col[col] = r;
        r += 1;
    }
    let mut sol = 0u128;
    for col in 0..128 {
        let pr = pivot_for_col[col];
        if pr != usize::MAX && mat[pr].1 == 1 { sol |= 1u128 << col; }
    }
    sol
}

/// JScript via z3: solve for unknown multiplier a, increment c, and initial
/// state of a B-bit LCG where value = (top27(s_k) << 27 | top27(s_{k+1})) / 2^54
/// (two states per output). `hi` (top 27) is always exact; `lo` only when value
/// < 0.5 (f64 bit0). Scans modulus B passed as arg.
fn crack_jscript_z3(values: &[f64], b: u32) {
    use std::process::Command;
    let n: Vec<u64> = values.iter().map(|&x| (x * 2f64.powi(54)).round() as u64).collect();
    let win = 24usize.min(n.len());
    let hb = b - 1; // high bit index
    let lb = b - 27; // low index of the top-27 window
    let mut smt = format!("(set-logic QF_BV)\n(declare-const a (_ BitVec {b}))\n(declare-const c (_ BitVec {b}))\n(declare-const s0 (_ BitVec {b}))\n");
    let mut cur = "s0".to_string();
    for k in 0..win {
        let hi = n[k] >> 27;
        let lo = n[k] & ((1 << 27) - 1);
        let sb = format!("sb_{k}");
        let nx = format!("s_{k}");
        // hi from current state
        smt.push_str(&format!("(assert (= ((_ extract {hb} {lb}) {cur}) (_ bv{hi} 27)))\n"));
        // step to lo-state
        smt.push_str(&format!("(declare-const {sb} (_ BitVec {b}))\n(assert (= {sb} (bvadd (bvmul a {cur}) c)))\n"));
        if values[k] < 0.5 {
            smt.push_str(&format!("(assert (= ((_ extract {hb} {lb}) {sb}) (_ bv{lo} 27)))\n"));
        }
        // step to next output's hi-state
        smt.push_str(&format!("(declare-const {nx} (_ BitVec {b}))\n(assert (= {nx} (bvadd (bvmul a {sb}) c)))\n"));
        cur = nx;
    }
    smt.push_str("(check-sat)\n(get-value (a c s0))\n");
    std::fs::write("/tmp/js.smt2", &smt).unwrap();
    let out = match Command::new("z3").arg("-T:120").arg("/tmp/js.smt2").output() {
        Ok(o) => o,
        Err(e) => { println!("  z3 unavailable: {e}"); return; }
    };
    let text = String::from_utf8_lossy(&out.stdout);
    let first = text.lines().next().unwrap_or("?");
    if !text.contains("sat") || text.starts_with("unsat") {
        println!("  B={b}: {first}");
        return;
    }
    let nums: Vec<u128> = text.split("#x").skip(1)
        .filter_map(|s| u128::from_str_radix(&s.chars().take_while(|c| c.is_ascii_hexdigit()).collect::<String>(), 16).ok())
        .collect();
    if nums.len() < 3 { println!("  B={b}: parse fail: {text}"); return; }
    let (a, c, mut s) = (nums[0], nums[1], nums[2]);
    let md = 1u128 << b;
    let mut ok = 0;
    for &want in &values[..win.min(values.len()).max(200).min(values.len())] {
        let hi = (s >> (b - 27)) as u64;
        s = (a.wrapping_mul(s) + c) % md;
        let lo = (s >> (b - 27)) as u64;
        s = (a.wrapping_mul(s) + c) % md;
        let np = (hi << 27) | lo;
        if (np as f64 / 2f64.powi(54) - want).abs() < 3.0 / 2f64.powi(54) { ok += 1; } else { break; }
    }
    println!("  B={b}: z3 SAT a={a} c={c} s0={} -> reproduced {ok} outputs", nums[2]);
}

/// Test whether an IE/Chakra capture is xorshift128+ with a `w`-bit extraction
/// of (s0+s1) (low w bits). Free shifts (z3 finds them). value = N / 2^54.
fn crack_ie_xs_z3(values: &[f64], w: u32) {
    use std::process::Command;
    let o: Vec<u64> = values.iter().map(|&x| (x * 2f64.powi(54)).round() as u64).collect();
    let k = 6usize;
    let mut smt = String::from("(set-logic QF_BV)\n");
    for v in ["s0", "s1", "sa", "sb", "sc"] {
        smt.push_str(&format!("(declare-const {v} (_ BitVec 64))\n"));
    }
    for v in ["sa", "sb", "sc"] {
        smt.push_str(&format!("(assert (bvuge {v} (_ bv1 64)))(assert (bvule {v} (_ bv63 64)))\n"));
    }
    let (mut p0, mut p1) = ("s0".to_string(), "s1".to_string());
    let hb = w - 1;
    for i in 0..k {
        let (t1, t2, f) = (format!("t1_{i}"), format!("t2_{i}"), format!("F_{i}"));
        smt.push_str(&format!("(declare-const {t1} (_ BitVec 64))(assert (= {t1} (bvxor {p0} (bvshl {p0} sa))))\n"));
        smt.push_str(&format!("(declare-const {t2} (_ BitVec 64))(assert (= {t2} (bvxor {t1} (bvlshr {t1} sb))))\n"));
        smt.push_str(&format!("(declare-const {f} (_ BitVec 64))(assert (= {f} (bvxor (bvxor {t2} {p1}) (bvlshr {p1} sc))))\n"));
        smt.push_str(&format!("(assert (= ((_ extract {hb} 0) (bvadd {p1} {f})) (_ bv{} {w})))\n", o[i]));
        p0 = p1; p1 = f;
    }
    smt.push_str("(check-sat)\n(get-value (s0 s1 sa sb sc))\n");
    std::fs::write("/tmp/ie.smt2", &smt).unwrap();
    let out = match Command::new("z3").arg("-T:120").arg("/tmp/ie.smt2").output() {
        Ok(o) => o, Err(e) => { println!("  z3 err {e}"); return; }
    };
    let text = String::from_utf8_lossy(&out.stdout);
    println!("  w={w}: {}", text.lines().next().unwrap_or("?"));
    if text.contains("sat") && !text.starts_with("unsat") {
        let h: Vec<u64> = text.split("#x").skip(1)
            .filter_map(|s| u64::from_str_radix(&s.chars().take_while(|c| c.is_ascii_hexdigit()).collect::<String>(), 16).ok())
            .collect();
        let dec: Vec<u64> = text.split("(_ bv").skip(1)
            .filter_map(|s| s.chars().take_while(|c| c.is_ascii_digit()).collect::<String>().parse().ok()).collect();
        println!("    hexes={h:?} shift-decs(tail)={:?}", &dec[dec.len().saturating_sub(3)..]);
    }
}

/// Modern SpiderMonkey via z3, parameterized by xorshift128+ shift constants
/// (sa,sb,sc) and output mode. mode 0: (s0+s1)>>11 ; mode 1: s0>>11.
/// Returns Some((s0,s1)) if z3 finds a state reproducing the first `k` outputs.
fn sm_z3_variant(o: &[u64], k: usize, sa: u32, sb: u32, sc: u32, mode: u32) -> Option<(u64, u64)> {
    use std::process::Command;
    let mut smt = String::from("(set-logic QF_BV)\n(declare-const s0 (_ BitVec 64))\n(declare-const s1 (_ BitVec 64))\n");
    let (mut p0, mut p1) = ("s0".to_string(), "s1".to_string());
    for i in 0..k {
        let (t1, t2, f) = (format!("t1_{i}"), format!("t2_{i}"), format!("F_{i}"));
        smt.push_str(&format!("(declare-const {t1} (_ BitVec 64))\n(assert (= {t1} (bvxor {p0} (bvshl {p0} (_ bv{sa} 64)))))\n"));
        smt.push_str(&format!("(declare-const {t2} (_ BitVec 64))\n(assert (= {t2} (bvxor {t1} (bvlshr {t1} (_ bv{sb} 64)))))\n"));
        smt.push_str(&format!("(declare-const {f} (_ BitVec 64))\n(assert (= {f} (bvxor (bvxor {t2} {p1}) (bvlshr {p1} (_ bv{sc} 64)))))\n"));
        // new_s0 = p1, new_s1 = f
        let outexpr = if mode == 0 { format!("(bvadd {p1} {f})") } else { p1.clone() };
        smt.push_str(&format!("(assert (= ((_ extract 52 0) {outexpr}) (_ bv{} 53)))\n", o[i]));
        p0 = p1;
        p1 = f;
    }
    smt.push_str("(check-sat)\n(get-value (s0 s1))\n");
    std::fs::write("/tmp/sm.smt2", &smt).unwrap();
    let out = Command::new("z3").arg("-T:60").arg("/tmp/sm.smt2").output().ok()?;
    let text = String::from_utf8_lossy(&out.stdout);
    if !text.contains("sat") || text.starts_with("unsat") {
        return None;
    }
    let hexes: Vec<u64> = text.split("#x").skip(1)
        .filter_map(|s| u64::from_str_radix(&s.chars().take_while(|c| c.is_ascii_hexdigit()).collect::<String>(), 16).ok())
        .collect();
    if hexes.len() < 2 { return None; }
    Some((hexes[0], hexes[1]))
}

/// Let z3 solve for the xorshift128+ shift constants too (sa,sb,sc unknown).
fn sm_z3_freeshift(o: &[u64], k: usize) -> Option<(u64, u64, u32, u32, u32)> {
    use std::process::Command;
    let mut smt = String::from("(set-logic QF_BV)\n");
    for v in ["s0", "s1", "sa", "sb", "sc"] {
        smt.push_str(&format!("(declare-const {v} (_ BitVec 64))\n"));
    }
    for v in ["sa", "sb", "sc"] {
        smt.push_str(&format!("(assert (bvuge {v} (_ bv1 64)))\n(assert (bvule {v} (_ bv63 64)))\n"));
    }
    let (mut p0, mut p1) = ("s0".to_string(), "s1".to_string());
    for i in 0..k {
        let (t1, t2, f) = (format!("t1_{i}"), format!("t2_{i}"), format!("F_{i}"));
        smt.push_str(&format!("(declare-const {t1} (_ BitVec 64))\n(assert (= {t1} (bvxor {p0} (bvshl {p0} sa))))\n"));
        smt.push_str(&format!("(declare-const {t2} (_ BitVec 64))\n(assert (= {t2} (bvxor {t1} (bvlshr {t1} sb))))\n"));
        smt.push_str(&format!("(declare-const {f} (_ BitVec 64))\n(assert (= {f} (bvxor (bvxor {t2} {p1}) (bvlshr {p1} sc))))\n"));
        smt.push_str(&format!("(assert (= ((_ extract 52 0) (bvadd {p1} {f})) (_ bv{} 53)))\n", o[i]));
        p0 = p1; p1 = f;
    }
    smt.push_str("(check-sat)\n(get-value (s0 s1 sa sb sc))\n");
    std::fs::write("/tmp/smfree.smt2", &smt).unwrap();
    let out = Command::new("z3").arg("-T:300").arg("/tmp/smfree.smt2").output().ok()?;
    let text = String::from_utf8_lossy(&out.stdout);
    if !text.contains("sat") || text.starts_with("unsat") { return None; }
    let h: Vec<u64> = text.split("#x").skip(1)
        .filter_map(|s| u64::from_str_radix(&s.chars().take_while(|c| c.is_ascii_hexdigit()).collect::<String>(), 16).ok())
        .collect();
    // also parse decimal bvN for shifts if z3 prints them as (_ bvK 64)
    let dec: Vec<u64> = text.split("(_ bv").skip(1)
        .filter_map(|s| s.chars().take_while(|c| c.is_ascii_digit()).collect::<String>().parse().ok())
        .collect();
    let sh = if h.len() >= 5 { (h[2], h[3], h[4]) } else if dec.len() >= 3 { (dec[dec.len()-3], dec[dec.len()-2], dec[dec.len()-1]) } else { return None };
    Some((*h.first()?, *h.get(1)?, sh.0 as u32, sh.1 as u32, sh.2 as u32))
}

fn crack_sm_z3(values: &[f64]) {
    let base: Vec<u64> = values.iter().map(|&x| (x * 9_007_199_254_740_992.0).round() as u64).collect();
    // Confirmed: xorshift128+ (23,17,26), output = low 53 bits of (s0+s1).
    if let Some((s0v, s1v)) = sm_z3_variant(&base, 8, 23, 17, 26, 0) {
        let regen = browser_rnd::engines::spidermonkey::generate(
            browser_rnd::prng::XorShift128Plus::new(s0v, s1v), values.len());
        let ok = regen.iter().zip(values).take_while(|(x, y)| (**x - **y).abs() < 1e-15).count();
        println!("  z3 SAT: s0={s0v:#018x} s1={s1v:#018x} -> reproduced {ok}/{}", values.len());
        return;
    }
    println!("  (23,17,26) unsat; trying free-shift/orderings...");
    if let Some((s0v, s1v, sa, sb, sc)) = sm_z3_freeshift(&base, 6) {
        println!("  FREE-SHIFT SAT: s0={s0v:#018x} s1={s1v:#018x} shifts=({sa},{sb},{sc})");
        return;
    }
    let variants = [(23u32, 17u32, 26u32), (23, 18, 5)];
    // try contiguous, then mid-stream window, then de-reversed batches (cache?)
    for &cblk in &[1usize, 64, 128, 256] {
        let mut o = base.clone();
        if cblk > 1 {
            let mut i = 0;
            while i + cblk <= o.len() { o[i..i + cblk].reverse(); i += cblk; }
        }
        for start in [0usize, 100] {
            let win = &o[start..];
            for mode in [0u32, 1] {
                for &(sa, sb, sc) in &variants {
                    if let Some((s0v, s1v)) = sm_z3_variant(win, 8, sa, sb, sc, mode) {
                        // verify forward from recovered state
                        let regen = browser_rnd::engines::spidermonkey::generate(
                            browser_rnd::prng::XorShift128Plus::new(s0v, s1v), win.len().min(64));
                        let ok = regen.iter().zip(win)
                            .take_while(|(x, y)| ((**x * 9_007_199_254_740_992.0).round() as u64) == **y)
                            .count();
                        println!("  SAT blk={cblk} start={start} shifts=({sa},{sb},{sc}) mode={mode}: s0={s0v:#018x} s1={s1v:#018x} verify {ok}");
                        if ok > 20 { return; }
                    }
                }
            }
        }
    }
    println!("  all variants/orderings unsat");
}

fn crack_sm(values: &[f64]) {
    // Modern SpiderMonkey: out = (s0+s1) >> 11 (53 bits). State GF(2)-linear;
    // iterate: solve seed given carry guesses, recompute carries, repeat.
    use browser_rnd::prng::XorShift128Plus;
    let k = 12usize;
    let o: Vec<u64> = values.iter().map(|&x| (x * 9_007_199_254_740_992.0).round() as u64).collect();
    let mut s0: Sym = std::array::from_fn(|i| 1u128 << i);
    let mut s1: Sym = std::array::from_fn(|i| 1u128 << (64 + i));
    let (mut s0g, mut s1g): (Vec<Sym>, Vec<Sym>) = (vec![], vec![]);
    for _ in 0..k {
        let (n0, n1) = sym_step(&s0, &s1);
        s0 = n0; s1 = n1;
        s0g.push(s0); s1g.push(s1);
    }
    let mut carry = vec![[0u8; 64]; k];
    for iter in 0..200 {
        let mut rows = Vec::new();
        for ki in 0..k {
            for b in 0..53usize {
                let p = 11 + b;
                let coeff = s0g[ki][p] ^ s1g[ki][p];
                let rhs = (((o[ki] >> b) & 1) as u8) ^ carry[ki][p];
                rows.push((coeff, rhs));
            }
        }
        let sol = solve_gf2_any(rows);
        let mut st = XorShift128Plus::new(sol as u64, (sol >> 64) as u64);
        let mut good = 0;
        for ki in 0..k {
            st.next_state();
            let (a, b) = (st.s0 as u128, st.s1 as u128);
            for p in 11..64usize {
                let m = (1u128 << p) - 1;
                carry[ki][p] = ((((a & m) + (b & m)) >> p) & 1) as u8;
            }
            if (st.s0.wrapping_add(st.s1) >> 11) == o[ki] { good += 1; }
        }
        if good == k {
            // full verify against all values
            let seed = XorShift128Plus::new(sol as u64, (sol >> 64) as u64);
            let regen = browser_rnd::engines::spidermonkey::generate(seed, values.len());
            let ok = regen.iter().zip(values).take_while(|(x, y)| (**x - **y).abs() < 1e-15).count();
            println!("  converged at iter {iter}: seed=({:#018x},{:#018x}) reproduced {ok}/{}",
                sol as u64, (sol >> 64) as u64, values.len());
            return;
        }
    }
    println!("  did not converge in 200 iters");
}

fn crack_v8_xs(values: &[f64]) {
    // Symbolic seed bits (state before step 1 of the first observed batch).
    let mut s0: Sym = [0; 64];
    let mut s1: Sym = [0; 64];
    for i in 0..64 {
        s0[i] = 1u128 << i;
        s1[i] = 1u128 << (64 + i);
    }
    // sym_for_gen[g] = symbolic s0 after (g+1) steps. Cover 3 batches.
    let mut sym_for_gen: Vec<Sym> = Vec::with_capacity(192);
    for _ in 0..192 {
        let (n0, n1) = sym_step(&s0, &s1);
        s0 = n0;
        s1 = n1;
        sym_for_gen.push(s0);
    }

    let n_eq = 60usize; // observed values used for solving (≫ rank 128)
    for o in 0..64usize {
        let mut rows: Vec<(u128, u8)> = Vec::new();
        for j in 0..n_eq {
            let g = gen_index(o, j);
            if g >= sym_for_gen.len() {
                break;
            }
            let m = (values[j] + 1.0).to_bits() & 0x000F_FFFF_FFFF_FFFF;
            for b in 0..52usize {
                rows.push((sym_for_gen[g][12 + b], ((m >> b) & 1) as u8));
            }
        }
        let Some(sol) = solve_gf2(rows) else { continue };
        let seed0 = sol as u64;
        let seed1 = (sol >> 64) as u64;
        // Verify against the FULL sequence: generate o+len, drop the first o.
        let regen = browser_rnd::engines::v8::generate(
            browser_rnd::prng::XorShift128Plus::new(seed0, seed1),
            o + values.len(),
        );
        let ok = regen[o..]
            .iter()
            .zip(values)
            .take_while(|(a, b)| (**a - **b).abs() < 1e-15)
            .count();
        if ok == values.len() {
            println!("  offset={o}: seed s0={seed0:#018x} s1={seed1:#018x}");
            println!("  reproduced {ok}/{} (FULL)", values.len());
            return;
        }
    }
    println!("  no offset reproduced the sequence (model still wrong)");
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 3 {
        eprintln!("usage: relab <conv|drand48|mwc|mwc30> <sample.txt>");
        std::process::exit(2);
    }
    let exp = &args[1];
    let sample = load(&args[2]);
    let v = &sample.values;
    println!("loaded {} values from {}", v.len(), args[2]);
    match exp.as_str() {
        "id" => {
            use browser_rnd::engines::{jscript, spidermonkey, spidermonkey_legacy, v8, v8_legacy, v8_libc};
            // smallest grid 2^-k
            let mut grid = 0u32;
            for k in [30u32, 31, 32, 52, 53, 54] {
                let s = 2f64.powi(k as i32);
                if v.iter().all(|&x| (x * s - (x * s).round()).abs() < 1e-4) { grid = k; break; }
            }
            let id = match grid {
                30 => v8_libc::recover(v).map(|_| "Chrome1: libc rand()x2 (MSVCRT)".to_string()),
                32 => v8_legacy::recover(v).map(|m| format!(
                    "V8 MWC: combine={:?} hi-lane={} lo-lane={}", m.combine, m.mult0, m.mult1)),
                52 => v8::recover(v).map(|(_, off)| format!("modern V8 xorshift128+ (offset {off})")),
                54 => jscript::recover(v).map(|_| "IE drand48 27+27".to_string()),
                53 => spidermonkey_legacy::recover(v).map(|_| "drand48 (old SpiderMonkey)".to_string())
                    .or_else(|| spidermonkey::recover(v).map(|_| "modern SpiderMonkey xorshift128+ (z3)".to_string())),
                _ => None,
            };
            match id {
                Some(s) => println!("grid 2^-{grid} | {s}"),
                None => println!("grid 2^-{grid} | UNIDENTIFIED (likely Presto/CSPRNG or new variant)"),
            }
        }
        "jsc" => {
            match browser_rnd::engines::jsc::recover(v) {
                Some(st) => {
                    let regen = browser_rnd::engines::jsc::generate(st, v.len());
                    let ok = regen.iter().zip(v).take_while(|(a, b)| (**a - **b).abs() < 1e-15).count();
                    println!("  JSC GameRand: low={:#010x} high={:#010x} reproduced {ok}/{}", st.low, st.high, v.len());
                }
                None => println!("  not JSC GameRand"),
            }
        }
        "seedtime" => {
            use browser_rnd::engines::{jscript, spidermonkey_legacy, v8_libc};
            let epoch = sample.meta.get("epoch").cloned().unwrap_or_default();
            let date = sample.meta.get("date").cloned().unwrap_or_default();
            let e: i128 = epoch.parse().unwrap_or(0);
            if let Some((seed, back)) = browser_rnd::engines::jsc::recover_seed(v, 20_000_000) {
                println!("epoch={epoch} ({date})");
                println!("  Safari GameRand ORIGINAL 32-bit seed = {seed:#010x} = {seed}");
                println!("  ({back} draws consumed before our first captured value; full state is only 32 bits)");
            } else if let Some(seed) = jscript::recover(v) {
                println!("epoch={epoch} ({date})\n  IE drand48 seed(48b) = {seed:#014x} = {seed}");
                println!("  epoch_ms={e}  epoch_s={}  epoch_us={}", e / 1000, e * 1000);
            } else if let Some(st) = v8_libc::recover(v) {
                println!("epoch={epoch}\n  chrome1 rand state = {st:#010x} = {st}  (epoch_s={})", e / 1000);
                // step the MSVCRT LCG backward looking for an srand(time) seed
                // near the capture time (page loaded shortly before).
                let md = 1u64 << 32;
                let mut inv = 1u64; for _ in 0..6 { inv = inv.wrapping_mul(2u64.wrapping_sub(214013u64.wrapping_mul(inv))); } inv &= md - 1;
                let back = |s: u64| ((s + md - 2531011) & (md - 1)).wrapping_mul(inv) & (md - 1);
                let es = (e / 1000) as u64;
                let mut s = st as u64;
                let mut hits = 0;
                for k in 0..2_000_000u64 {
                    if s + 600 >= es && s <= es + 5 {
                        println!("  hit: srand seed={s} ({:+} s vs epoch) at k={k} rand-calls back", s as i64 - es as i64);
                        hits += 1;
                        if hits >= 8 { break; }
                    }
                    s = back(s);
                }
                if hits == 0 { println!("  no srand(time_s) seed within 600s in 2M steps -> not wall-clock srand"); }
            } else if let Some(seed) = spidermonkey_legacy::recover(v) {
                println!("epoch={epoch}\n  oldFF drand48 seed(48b) = {seed:#014x} = {seed}  (epoch_us={})", e * 1000);
            } else {
                println!("epoch={epoch}  (no time-seedable model matched)");
            }
        }
        "conv" => conv(v),
        "jstlcg" => {
            // JScript hypothesis: value = (top27(s_a)<<27 | top27(s_b)) / 2^54,
            // two consecutive LCG states s_a,s_b per output, state B bits, LCG
            // s' = M*s + A mod 2^B, output reads top 27 bits (h = B-27 hidden).
            // hi_k, lo_k, hi_{k+1} are top27 of THREE consecutive states, so
            // brute their h hidden bits each -> M, A directly.
            let p54 = 2f64.powi(54);
            let n: Vec<u64> = v.iter().map(|&x| (x * p54).round() as u64).collect();
            let k0 = (0..n.len() - 1).find(|&k| v[k] < 0.5).unwrap();
            let hi0 = n[k0] >> 27;
            let lo0 = n[k0] & ((1 << 27) - 1);
            let hi1 = n[k0 + 1] >> 27;
            let modinv = |a: u128, md: u128| -> u128 {
                let mut x = 1u128;
                for _ in 0..8 {
                    x = x.wrapping_mul(2u128.wrapping_sub(a.wrapping_mul(x))) % md;
                }
                x % md
            };
            let verify = |s_start: u128, m: u128, a: u128, b: u32, h: u32| -> usize {
                let md = 1u128 << b;
                let mut state = s_start;
                let mut ok = 0;
                for j in k0..n.len() {
                    let u = state;
                    let w = (m * u + a) % md;
                    let np = ((u >> h) << 27) | (w >> h);
                    if (np as f64 / p54 - v[j]).abs() < 1.5 / p54 * 2.0 {
                        ok += 1;
                    } else {
                        break;
                    }
                    state = (m * w + a) % md;
                }
                ok
            };
            let mut cracked = false;
            for b in 27..=40u32 {
                let h = b - 27;
                if h > 9 {
                    continue;
                }
                let md = 1u128 << b;
                let lim = 1u64 << h;
                'search: for r0 in 0..lim {
                    let s0 = ((hi0 << h) | r0) as u128;
                    for r1 in 0..lim {
                        let s1 = ((lo0 << h) | r1) as u128;
                        let d0 = (s1 + md - s0) % md;
                        if d0 & 1 == 0 {
                            continue;
                        }
                        let inv = modinv(d0, md);
                        for r2 in 0..lim {
                            let s2 = ((hi1 << h) | r2) as u128;
                            let m = ((s2 + md - s1) % md) * inv % md;
                            let a = (s1 + md - (m * s0) % md) % md;
                            if verify(s0, m, a, b, h) > 200 {
                                let full = verify(s0, m, a, b, h);
                                println!("  B={b} M={m} A={a} -> reproduced {full}/{} from k0={k0}", n.len() - k0);
                                cracked = true;
                                break 'search;
                            }
                        }
                    }
                }
                if cracked {
                    break;
                }
                println!("  B={b}: no solution (h={h})");
            }
        }
        "jstlcg1" => {
            // Single-step hypothesis: value = (state >> h) / 2^54 from a B-bit
            // LCG (B = 54 + h), one step per output. N_k,N_{k+1},N_{k+2} = top54
            // of three consecutive states; brute h hidden bits each -> M,A.
            let p54 = 2f64.powi(54);
            let n: Vec<u64> = v.iter().map(|&x| (x * p54).round() as u64).collect();
            // anchor: three consecutive values < 0.5 so N is exact
            let k0 = (0..n.len() - 2)
                .find(|&k| v[k] < 0.5 && v[k + 1] < 0.5 && v[k + 2] < 0.5)
                .unwrap();
            let (t0, t1, t2) = (n[k0] as u128, n[k0 + 1] as u128, n[k0 + 2] as u128);
            let modinv = |a: u128, md: u128| -> u128 {
                let mut x = 1u128;
                for _ in 0..8 {
                    x = x.wrapping_mul(2u128.wrapping_sub(a.wrapping_mul(x))) % md;
                }
                x % md
            };
            let mut cracked = false;
            for b in 54..=64u32 {
                let h = b - 54;
                if h > 9 {
                    continue;
                }
                let md = 1u128 << b;
                let lim = 1u64 << h;
                'search: for r0 in 0..lim {
                    let s0 = (t0 << h) | r0 as u128;
                    for r1 in 0..lim {
                        let s1 = (t1 << h) | r1 as u128;
                        let d0 = (s1 + md - s0) % md;
                        if d0 & 1 == 0 {
                            continue;
                        }
                        let inv = modinv(d0, md);
                        for r2 in 0..lim {
                            let s2 = (t2 << h) | r2 as u128;
                            let m = ((s2 + md - s1) % md) * inv % md;
                            let a = (s1 + md - (m * s0) % md) % md;
                            // verify forward from s0
                            let mut state = s0;
                            let mut ok = 0;
                            for j in k0..n.len() {
                                if ((state >> h) as f64 / p54 - v[j]).abs() < 3.0 / p54 {
                                    ok += 1;
                                } else {
                                    break;
                                }
                                state = (m * state + a) % md;
                            }
                            if ok > 200 {
                                println!("  B={b} M={m} A={a} -> reproduced {ok}/{} from k0={k0}", n.len() - k0);
                                cracked = true;
                                break 'search;
                            }
                        }
                    }
                }
                if cracked {
                    break;
                }
                println!("  B={b}: no solution (h={h})");
            }
        }
        "mwce1" => {
            // V8 era-1 MWC (3.14-3.23): r = ((s0<<14) + (s1 & 0x3FFFF)) mod 2^32,
            // lane0 mult 18273 (or 18030 in era-3), lane1 mult 36969, double=r/2^32.
            // r & 0x3FFF == s1 & 0x3FFF (clean), so recover lane1 then lane0.
            let p32 = 2f64.powi(32);
            let r: Vec<u64> = v.iter().map(|&x| (x * p32).round() as u64).collect();
            let step = |s: u64, m: u64| (m * (s & 0xFFFF) + (s >> 16)) & 0xFFFF_FFFF;
            for m0 in [18273u64, 18030] {
                let m1 = 36969u64;
                // 1) recover lane1 (mult 36969): low14 known = r&0x3FFF, brute high 18 bits
                let lo14 = r[0] & 0x3FFF;
                let mut s1_0 = None;
                for hi in 0..(1u64 << 18) {
                    let cand = (hi << 14) | lo14;
                    let mut s = cand;
                    let mut ok = true;
                    for &rk in r.iter().take(150) {
                        if s & 0x3FFF != rk & 0x3FFF { ok = false; break; }
                        s = step(s, m1);
                    }
                    if ok { s1_0 = Some(cand); break; }
                }
                let Some(s1_0) = s1_0 else { continue };
                // 2) recover lane0: s0&0x3FFFF = ((r - s1&0x3FFFF) mod 2^32) >> 14
                let mut s1 = s1_0;
                let s0_lo18: Vec<u64> = r.iter().map(|&rk| {
                    let t = (rk + (1u64 << 32) - (s1 & 0x3FFFF)) & 0xFFFF_FFFF;
                    let v = t >> 14;
                    s1 = step(s1, m1);
                    v
                }).collect();
                // brute high 14 bits of s0_0 (low18 known)
                let mut s0_0 = None;
                for hi in 0..(1u64 << 14) {
                    let cand = (hi << 18) | s0_lo18[0];
                    let mut s = cand;
                    let mut ok = true;
                    for &want in s0_lo18.iter().take(150) {
                        if s & 0x3FFFF != want { ok = false; break; }
                        s = step(s, m0);
                    }
                    if ok { s0_0 = Some(cand); break; }
                }
                let Some(s0_0) = s0_0 else { continue };
                // verify full reproduction
                let (mut a, mut b) = (s0_0, s1_0);
                let mut okc = 0;
                for &rk in &r {
                    let pred = ((a << 14) + (b & 0x3FFFF)) & 0xFFFF_FFFF;
                    if pred != rk { break; }
                    okc += 1;
                    a = step(a, m0); b = step(b, m1);
                }
                println!("  era1 m0={m0}: s0={s0_0:#x} s1={s1_0:#x} reproduced {okc}/{}", r.len());
                if okc == r.len() { return; }
            }
            println!("  era1: no match");
        }
        "derev" => {
            // Maybe values are served permuted (reversed batches, like V8). Try
            // de-reversing in blocks of size C, then test full-state LCG of
            // unknown modulus (gcd of determinant) on consecutive exact values.
            let bb: u32 = 54;
            let p = 2f64.powi(bb as i32);
            let n0: Vec<i128> = v.iter().map(|&x| (x * p).round() as i128).collect();
            let ex0: Vec<bool> = v.iter().map(|&x| x < 0.5).collect();
            fn gcd(a: i128, b: i128) -> i128 { if b == 0 { a.abs() } else { gcd(b, a % b) } }
            for c in [1usize, 8, 16, 32, 64, 128, 256, 512] {
                // de-reverse blocks of size c
                let mut n = n0.clone();
                let mut ex = ex0.clone();
                let mut i = 0;
                while i + c <= n.len() {
                    n[i..i + c].reverse();
                    ex[i..i + c].reverse();
                    i += c;
                }
                let mut g: i128 = 0;
                let mut used = 0;
                for k in 1..n.len() - 2 {
                    if ex[k - 1] && ex[k] && ex[k + 1] && ex[k + 2] {
                        let d = (n[k] - n[k - 1]) * (n[k + 2] - n[k + 1]) - (n[k + 1] - n[k]).pow(2);
                        g = gcd(g, d);
                        used += 1;
                    }
                }
                println!("  C={c:4}: gcd(Δ)={g} (log2≈{:.2}), windows={used}",
                    if g > 1 { (g as f64).log2() } else { 0.0 });
            }
        }
        "raw" => {
            let n: Vec<u64> = v.iter().map(|&x| (x * 2f64.powi(54)).round() as u64).collect();
            println!("  N (54-bit) hex, and N&0xff low byte, first 24:");
            for i in 0..24 {
                println!("    [{i:2}] N={:014x}  hi27={:07x} lo27={:07x}  low8={:08b}",
                    n[i], n[i] >> 27, n[i] & ((1 << 27) - 1), (n[i] & 0xff) as u8);
            }
            // duplicate / collision check
            let mut sorted = n.clone();
            sorted.sort_unstable();
            let dups = sorted.windows(2).filter(|w| w[0] == w[1]).count();
            println!("  duplicates among {} values: {dups}", n.len());
            // count low-bit zero rate (parity structure)
            for bit in 0..6 {
                let ones = n.iter().filter(|&&x| (x >> bit) & 1 == 1).count();
                println!("  bit {bit}: ones={ones}/{} ({:.1}%)", n.len(), 100.0 * ones as f64 / n.len() as f64);
            }
        }
        "bm" => {
            // Berlekamp-Massey over GF(2) on output bit-streams. Low linear
            // complexity => GF(2)-linear generator (xorshift/LFSR). High (~n/2)
            // => nonlinear over GF(2) (LCG/MWC with integer-multiply carries).
            let bits: u32 = 54; // values are N/2^54
            let n: Vec<u64> = v.iter().map(|&x| (x * 2f64.powi(bits as i32)).round() as u64).collect();
            fn bm_gf2(s: &[u8]) -> usize {
                let n = s.len();
                let mut b = vec![0u8; n];
                let mut c = vec![0u8; n];
                b[0] = 1; c[0] = 1;
                let mut l = 0usize;
                let mut m: i64 = -1;
                for i in 0..n {
                    let mut d = s[i];
                    for j in 1..=l { d ^= c[j] & s[i - j]; }
                    if d == 1 {
                        let t = c.clone();
                        let shift = (i as i64 - m) as usize;
                        for j in 0..n - shift { c[j + shift] ^= b[j]; }
                        if 2 * l <= i { l = i + 1 - l; m = i as i64; b = t; }
                    }
                }
                l
            }
            // test several high bit positions (always exact: bit >= 1)
            for bp in [53u32, 50, 45, 40, 30] {
                let s: Vec<u8> = n.iter().map(|&x| ((x >> bp) & 1) as u8).collect();
                let l = bm_gf2(&s);
                println!("  bit {bp}: linear complexity = {l} / {} samples", s.len());
            }
        }
        "lcgmod" => {
            // Full-state LCG with UNKNOWN modulus m (possibly odd/prime):
            // N_{i+1}=a N_i + c mod m  =>  (N2-N1)^2 ≡ (N1-N0)(N3-N2) mod m.
            // So m | Δ = (N2-N1)^2 - (N1-N0)(N3-N2); gcd over many windows = m.
            let b: u32 = args.get(3).and_then(|s| s.parse().ok()).unwrap_or(54);
            let p = 2f64.powi(b as i32);
            let n: Vec<i128> = v.iter().map(|&x| (x * p).round() as i128).collect();
            let ex = |i: usize| v[i] < 0.5;
            fn gcd(a: i128, b: i128) -> i128 { if b == 0 { a.abs() } else { gcd(b, a % b) } }
            let mut g: i128 = 0;
            let mut used = 0;
            for k in 1..n.len() - 2 {
                if ex(k - 1) && ex(k) && ex(k + 1) && ex(k + 2) {
                    let delta = (n[k] - n[k - 1]) * (n[k + 2] - n[k + 1]) - (n[k + 1] - n[k]).pow(2);
                    g = gcd(g, delta);
                    used += 1;
                    if used > 60 && g != 0 { /* enough */ }
                }
            }
            println!("  windows used={used}, gcd(Δ) = {g}");
            if g != 0 {
                // factor out small spurious factors: report g and g/small
                println!("  candidate modulus m = {g}");
                println!("  log2(m) ≈ {:.3}", (g as f64).log2());
            }
        }
        "jsknown" => {
            // 27+27 truncated LCG with a KNOWN multiplier (h up to ~25): brute
            // only the first state-difference's hidden bits (2^(h+1)).
            let p54 = 2f64.powi(54);
            let nvals: Vec<u64> = v.iter().map(|&x| (x * p54).round() as u64).collect();
            let mut t = Vec::new();
            let mut ex = Vec::new();
            for (k, &n) in nvals.iter().enumerate() {
                t.push((n >> 27) as u128); ex.push(true);
                t.push((n & ((1 << 27) - 1)) as u128); ex.push(v[k] < 0.5);
            }
            let p = (0..t.len() - 4).find(|&i| (0..4).all(|j| ex[i + j])).unwrap();
            let mults: [u128; 16] = [
                25214903917, 214013, 1103515245, 1664525, 22695477, 134775813,
                69069, 1812433253, 1566083941, 1597334677, 16843009, 0x5851F42D4C957F2D,
                6364136223846793005, 2862933555777941757, 3935559000370003845, 44485709377909,
            ];
            let mut cracked = false;
            for b in [40u32, 42, 44, 46, 48, 50, 52, 53, 54] {
                let h = b - 27;
                if h > 26 { continue; }
                let md = 1u128 << b;
                let d0t = t[p + 1] as i128 - t[p] as i128;
                for &a in &mults {
                    let a = a % md;
                    let span = 1i128 << h;
                    for dd0 in -span + 1..span {
                        let d0 = ((d0t * (1 << h) + dd0).rem_euclid(md as i128)) as u128;
                        let mut s = t[p] << h;
                        let mut d = d0;
                        let mut ok = 0;
                        for i in 0..t.len() - p - 1 {
                            let sn = (s + d) % md;
                            if ((sn >> h) as i128 - t[p + i + 1] as i128).abs() <= 1 { ok += 1; } else { break; }
                            s = sn; d = a * d % md;
                        }
                        if ok > 150 {
                            println!("  CRACKED B={b} a={a} verified {ok} steps");
                            cracked = true;
                        }
                    }
                }
            }
            if !cracked { println!("  no known multiplier matched"); }
        }
        "jsdiff" => {
            // Recover a truncated LCG with UNKNOWN multiplier & increment by
            // brute-forcing the hidden bits of two consecutive state DIFFERENCES
            // (the increment cancels: D_{i+1} = a*D_i mod 2^B). Tries both the
            // single-step (w=54) and interleaved 27+27 (w=27) structures.
            let p54 = 2f64.powi(54);
            let nvals: Vec<u64> = v.iter().map(|&x| (x * p54).round() as u64).collect();
            let modinv = |a: u128, md: u128| -> u128 {
                let mut x = 1u128;
                for _ in 0..8 { x = x.wrapping_mul(2u128.wrapping_sub(a.wrapping_mul(x))) % md; }
                x % md
            };
            for &(w, label) in &[(54u32, "single"), (27u32, "27+27"), (27u32, "hi-only"), (27u32, "lo-only")] {
                // Build observed top-w sequence T and exactness flags.
                let (t, exact): (Vec<u128>, Vec<bool>) = if w == 54 {
                    (nvals.iter().map(|&n| n as u128).collect(),
                     v.iter().map(|&x| x < 0.5).collect())
                } else if label == "hi-only" {
                    (nvals.iter().map(|&n| (n >> 27) as u128).collect(),
                     vec![true; nvals.len()])
                } else if label == "lo-only" {
                    (nvals.iter().map(|&n| (n & ((1 << 27) - 1)) as u128).collect(),
                     v.iter().map(|&x| x < 0.5).collect())
                } else {
                    let mut t = Vec::new();
                    let mut e = Vec::new();
                    for (k, &n) in nvals.iter().enumerate() {
                        t.push((n >> 27) as u128); e.push(true);          // hi: always exact
                        t.push((n & ((1 << 27) - 1)) as u128); e.push(v[k] < 0.5); // lo
                    }
                    (t, e)
                };
                // anchor: 4 consecutive exact tops
                let Some(p) = (0..t.len()-4).find(|&i| (0..4).all(|j| exact[i+j])) else { continue };
                let mut cracked = false;
                for b in (w + 1)..=(w + 12) {
                    let h = b - w;
                    let md = 1u128 << b;
                    let span = 1i128 << h;
                    let d0t = (t[p + 1] as i128 - t[p] as i128) as i128;
                    let d1t = (t[p + 2] as i128 - t[p + 1] as i128) as i128;
                    'br: for dd0 in -span + 1..span {
                        let d0 = ((d0t * (1 << h) as i128 + dd0).rem_euclid(md as i128)) as u128;
                        if d0 & 1 == 0 { continue; }
                        let inv = modinv(d0, md);
                        for dd1 in -span + 1..span {
                            let d1 = ((d1t * (1 << h) as i128 + dd1).rem_euclid(md as i128)) as u128;
                            let a = d1 * inv % md;
                            // verify geometric D_i=a^i D0 reproduces top diffs (assume e_p≈0)
                            let mut s = t[p] << h;
                            let mut d = d0;
                            let mut ok = 0;
                            for i in 0..t.len() - p - 1 {
                                let sn = (s + d) % md;
                                let diff = (sn >> h) as i128 - (t[p + i + 1] as i128);
                                if diff.abs() <= 1 { ok += 1; } else { break; }
                                s = sn; d = a * d % md;
                            }
                            if ok > 150 {
                                println!("  [{label}] B={b} multiplier a={a} verified {ok} steps");
                                cracked = true;
                                break 'br;
                            }
                        }
                    }
                    if cracked { break; }
                }
                if !cracked { println!("  [{label}] no multiplier found (h<=12)"); }
            }
        }
        "lcg2" => {
            // Second-order linear recurrence mod 2^B: N_{k+1} = A*N_k + B*N_{k-1} + C.
            // N exact when value < 0.5; solve A,B from a run of 5 such, then C.
            let b: u32 = args.get(3).and_then(|s| s.parse().ok()).unwrap_or(54);
            let md: i128 = 1i128 << b;
            let p = 2f64.powi(b as i32);
            let n: Vec<i128> = v.iter().map(|&x| (x * p).round() as i128).collect();
            let ex = |i: usize| v[i] < 0.5;
            let modinv = |a: i128| -> Option<i128> {
                let a = a.rem_euclid(md);
                if a % 2 == 0 { return None; }
                let mut x = 1i128;
                for _ in 0..8 { let t=(2 - a*x % md).rem_euclid(md); x=(x*t).rem_euclid(md); }
                Some(x)
            };
            // find 5 consecutive exact
            let start = (0..n.len()-4).find(|&k| (0..5).all(|j| ex(k+j)));
            let Some(k) = start else { println!("  no run of 5 exact values"); return; };
            let (n0,n1,n2,n3,n4) = (n[k],n[k+1],n[k+2],n[k+3],n[k+4]);
            // [ (n2-n1) (n1-n0) ][A]=[n3-n2]; [ (n3-n2) (n2-n1) ][B]=[n4-n3]
            let (p00,p01,p10,p11)=((n2-n1).rem_euclid(md),(n1-n0).rem_euclid(md),(n3-n2).rem_euclid(md),(n2-n1).rem_euclid(md));
            let det=(p00*p11 - p01*p10).rem_euclid(md);
            let Some(idet)=modinv(det) else { println!("  det not invertible"); return; };
            let r0=(n3-n2).rem_euclid(md); let r1=(n4-n3).rem_euclid(md);
            let a=((p11*r0 - p01*r1).rem_euclid(md)*idet).rem_euclid(md);
            let bb=((p00*r1 - p10*r0).rem_euclid(md)*idet).rem_euclid(md);
            let c=(n2 - a*n1 % md - bb*n0 % md).rem_euclid(md);
            println!("  A={a} B={bb} C={c}");
            let mut ok=0; let mut tot=0;
            for i in k+2..n.len() {
                if ex(i) && ex(i-1) && ex(i-2) {
                    tot+=1;
                    if (a*n[i-1] + bb*n[i-2] + c).rem_euclid(md)==n[i] { ok+=1; }
                }
            }
            println!("  2nd-order relation holds {ok}/{tot} exact triples");
        }
        "lcgfull" => {
            // Test value = state/2^B with state a full LCG mod 2^B (no hidden
            // bits), single step per output. Also probes 2-steps-per-output.
            let b: u32 = args.get(3).and_then(|s| s.parse().ok()).unwrap_or(53);
            let md: i128 = 1 << b;
            let n: Vec<i128> = v.iter().map(|&x| (x * (md as f64)).round() as i128).collect();
            let modinv = |a: i128| -> Option<i128> {
                let a = a.rem_euclid(md);
                if a % 2 == 0 { return None; }
                let mut x = 1i128;
                for _ in 0..8 {
                    let t = (2 - a * x % md).rem_euclid(md);
                    x = (x * t).rem_euclid(md);
                }
                if a * x % md == 1 { Some(x) } else { None }
            };
            for stride in [1usize, 2, 3] {
                // find a base index whose forward difference is odd (invertible)
                let mut solved = None;
                for base in 0..200.min(n.len() - 2 * stride) {
                    let (i0, i1, i2) = (base, base + stride, base + 2 * stride);
                    let d0 = (n[i1] - n[i0]).rem_euclid(md);
                    if let Some(inv) = modinv(d0) {
                        let d1 = (n[i2] - n[i1]).rem_euclid(md);
                        let m = d1 * inv % md;
                        let a = (n[i1] - m * n[i0]).rem_euclid(md);
                        solved = Some((m, a));
                        break;
                    }
                }
                let Some((m, a)) = solved else {
                    println!("  stride={stride}: no invertible triple");
                    continue;
                };
                let mut ok = 0usize;
                for k in 0..n.len() - stride {
                    if (m * n[k] + a).rem_euclid(md) == n[k + stride] {
                        ok += 1;
                    }
                }
                println!("  stride={stride} B={b}: M={m} A={a} -> {ok}/{} hold", n.len() - stride);
            }
        }
        "msvcrt" => {
            // Chrome 1 (Windows): two MSVCRT rand() calls per Math.random.
            // rand(): s = s*214013 + 2531011 (mod 2^32); out = (s>>16) & 0x7FFF.
            // value = (r1<<15 | r2) / 2^30.
            let p30 = 2f64.powi(30);
            let n: Vec<u64> = v.iter().map(|&x| (x * p30).round() as u64).collect();
            let m = 1u64 << 32;
            let mut done = false;
            'consts: for &(a, c, name) in &[
                (214013u64, 2531011u64, "msvcrt"),
                (1103515245u64, 12345u64, "ansi-c"),
                (1103515245u64, 12345u64, "ansi-c"),
            ] {
                let lcg = |s: u64| (s.wrapping_mul(a).wrapping_add(c)) & (m - 1);
                for &(sh, mask, lbl) in &[(16u32, 0x7FFFu64, "hi15"), (16, 0xFFFF, "hi16"), (0, 0x7FFF, "lo15")] {
                    let ext = |s: u64| (s >> sh) & mask;
                    let bits = (mask + 1).trailing_zeros();
                    let r1 = n[0] >> bits;
                    let r2 = n[0] & mask;
                    let hidden = 32 - bits; // bits not pinned by r1
                    if hidden > 20 { continue; }
                    let _ = lbl;
                    for x in 0..(1u64 << hidden) {
                        // r1 occupies bits [sh, sh+bits); brute the other `hidden` bits:
                        // x's low `sh` bits -> state bits [0,sh); x's rest -> bits [sh+bits,32)
                        let xlow = x & ((1u64 << sh).wrapping_sub(1));
                        let xhigh = x >> sh;
                        let s1 = ((xhigh << (sh + bits)) | (r1 << sh) | xlow) & (m - 1);
                        let s2 = lcg(s1);
                        if ext(s2) != r2 { continue; }
                        let mut st = s2;
                        let mut ok = 0usize;
                        for &want in &n[1..] {
                            let a1 = lcg(st);
                            let a2 = lcg(a1);
                            let np = (ext(a1) << bits) | ext(a2);
                            if np == want { ok += 1; st = a2; } else { break; }
                        }
                        if ok > 100 {
                            println!("  {name}/{lbl} rand x2: s1={s1:#x} reproduced {ok}/{}", n.len() - 1);
                            done = true;
                            break 'consts;
                        }
                    }
                }
            }
            if !done { println!("  no LCG-rand x2 match"); }
        }
        "chrome1" => {
            // V8 0.3.9.5: lo=rand() (FIRST), hi=rand() (SECOND),
            // result = (hi + lo/(RAND_MAX+1)) / (RAND_MAX+1).
            // Windows: rand()=MSVCRT LCG, RAND_MAX+1=2^15, out=(s>>16)&0x7FFF.
            // => N = hi*2^15 + lo  (first call = low 15 bits, second = high).
            let p30 = 2f64.powi(30);
            let n: Vec<u64> = v.iter().map(|&x| (x * p30).round() as u64).collect();
            let m = 1u64 << 32;
            let lcg = |s: u64| (s.wrapping_mul(214013).wrapping_add(2531011)) & (m - 1);
            let out = |s: u64| (s >> 16) & 0x7FFF;
            let lo0 = n[0] & 0x7FFF; // first call
            let hi0 = n[0] >> 15;    // second call
            let mut done = false;
            for x in 0..(1u64 << 17) {
                // first-call state: bits 16-30 = lo0; brute low 16 + bit 31
                let s1 = ((x >> 16) << 31) | (lo0 << 16) | (x & 0xFFFF);
                let s2 = lcg(s1);
                if out(s2) != hi0 { continue; }
                let mut st = s2;
                let mut ok = 0usize;
                for &want in &n[1..] {
                    let a1 = lcg(st);  // first call (low)
                    let a2 = lcg(a1);  // second call (high)
                    if (out(a2) << 15) | out(a1) == want { ok += 1; st = a2; } else { break; }
                }
                if ok > 100 {
                    println!("  CHROME1 MSVCRT rand x2: first-state={s1:#x} reproduced {ok}/{}", n.len() - 1);
                    done = true;
                    break;
                }
            }
            if !done { println!("  no chrome1 match"); }
        }
        "chakra" => {
            // ChakraCore (IE9-11): drand48 48-bit LCG, TWO steps per output,
            // value = ((sn>>21)<<27 | (seed>>21)) / 2^54. Anchor on a value<0.5
            // (exact), brute the 21 low bits of the first state, verify by value.
            let p54 = 2f64.powi(54);
            let n: Vec<u64> = v.iter().map(|&x| (x * p54).round() as u64).collect();
            let a0 = (0..n.len()).find(|&i| v[i] < 0.5).unwrap();
            let hi = n[a0] >> 27;
            let lo = n[a0] & ((1 << 27) - 1);
            let mut done = false;
            for x in 0..(1u64 << 21) {
                let s1 = (hi << 21) | x;
                let s2 = d_step(s1);
                if s2 >> 21 != lo { continue; }
                // verify forward from a0 by value (tolerant of f64 bit0 rounding)
                let mut st = s1;
                let mut ok = 0usize;
                for &want in &v[a0..] {
                    let h = st >> 21;
                    let s_b = d_step(st);
                    let l = s_b >> 21;
                    let val = ((h << 27) + l) as f64 / p54;
                    if (val - want).abs() < 3.0 / p54 { ok += 1; } else { break; }
                    st = d_step(s_b);
                }
                if ok > 100 {
                    println!("  CHAKRA drand48 27+27: s1={s1:#x} reproduced {ok}/{} from idx {a0}", v.len() - a0);
                    done = true;
                    break;
                }
            }
            if !done { println!("  no chakra/drand48 match"); }
        }
        "jscript48" => {
            // Hypothesis: value = (next(27)<<27 | next(27)) / 2^54 from a 48-bit
            // LCG with drand48 constants; next(27) = state >> 21.
            let p54 = 2f64.powi(54);
            let n: Vec<u64> = v.iter().map(|&x| (x * p54).round() as u64).collect();
            let hi = n[0] >> 27;
            let lo = n[0] & ((1 << 27) - 1);
            let mut hits = 0;
            for x in 0..(1u64 << 21) {
                let s1 = (hi << 21) | x;
                let s2 = d_step(s1);
                if s2 >> 21 == lo {
                    // verify a few more outputs (2 steps each)
                    let mut st = s2;
                    let mut ok = 0;
                    for k in 1..n.len().min(20) {
                        let a = d_step(st);
                        let b = d_step(a);
                        if ((a >> 21) << 27) + (b >> 21) == n[k] {
                            ok += 1;
                            st = b;
                        } else {
                            break;
                        }
                    }
                    hits += 1;
                    if ok >= 10 {
                        println!("  MATCH drand48 constants: x={x:#x} verified {ok} more outputs");
                    }
                }
            }
            println!("  {hits} candidate(s) for first output; (0 verified => wrong constants)");
        }
        "jscript54" => {
            // Hypothesis: value = N / 2^54 with N the full state of an LCG
            // N_{n+1} = (M*N_n + A) mod 2^54. N is exact when value < 0.5.
            const B: u32 = 54;
            const MOD: i128 = 1 << B;
            let n: Vec<i128> = v.iter().map(|&x| (x * (MOD as f64)).round() as i128).collect();
            let exact = |i: usize| v[i] < 0.5; // N fully recoverable
            // find a consecutive triple, all exact, with (N1-N0) odd
            let modinv = |a: i128| -> Option<i128> {
                let a = a.rem_euclid(MOD);
                let mut x = 1i128;
                for _ in 0..7 {
                    let t = (2 - a * x % MOD).rem_euclid(MOD);
                    x = (x * t).rem_euclid(MOD);
                }
                if a * x % MOD == 1 { Some(x) } else { None }
            };
            let mut found = None;
            for i in 0..n.len() - 2 {
                if exact(i) && exact(i + 1) && exact(i + 2) {
                    let d0 = ((n[i + 1] - n[i]) % MOD + MOD) % MOD;
                    let d1 = ((n[i + 2] - n[i + 1]) % MOD + MOD) % MOD;
                    if let Some(inv) = modinv(d0) {
                        let m = d1 * inv % MOD;
                        let a = ((n[i + 1] - m * n[i]) % MOD + MOD) % MOD;
                        found = Some((m, a));
                        break;
                    }
                }
            }
            match found {
                None => println!("  no clean triple / not a 54-bit LCG"),
                Some((m, a)) => {
                    println!("  candidate M={m} A={a}");
                    // verify: predict N over exact positions
                    let mut ok = 0usize;
                    let mut tot = 0usize;
                    for i in 0..n.len() - 1 {
                        if exact(i) && exact(i + 1) {
                            tot += 1;
                            if (m * n[i] + a) % MOD == n[i + 1] {
                                ok += 1;
                            }
                        }
                    }
                    println!("  LCG relation holds {ok}/{tot} exact consecutive pairs");
                }
            }
        }
        "denom" => {
            // For each value, print continued-fraction convergent denominators q
            // where |v - p/q| is ~0 — the true fixed denominator recurs across all.
            for &val in v.iter().take(6) {
                print!("  v={val:.17} -> q in {{");
                let (mut p0, mut q0, mut p1, mut q1) = (0i128, 1i128, 1i128, 0i128);
                let mut x = val;
                for _ in 0..40 {
                    let a = x.floor();
                    let (p2, q2) = (a as i128 * p1 + p0, a as i128 * q1 + q0);
                    if q2 != 0 {
                        let approx = p2 as f64 / q2 as f64;
                        if (approx - val).abs() < 1e-15 && q2 > 1 {
                            print!("{q2} ");
                        }
                    }
                    p0 = p1; q0 = q1; p1 = p2; q1 = q2;
                    let frac = x - a;
                    if frac.abs() < 1e-12 { break; }
                    x = 1.0 / frac;
                }
                println!("}}");
            }
        }
        "dump" => {
            let bits: u32 = args.get(3).and_then(|s| s.parse().ok()).unwrap_or(32);
            let scale = 2f64.powi(bits as i32);
            println!("  first values as integers r = round(d * 2^{bits}):");
            for &val in v.iter().take(10) {
                let r = (val * scale).round() as u64;
                println!("    d={val:.17}  r={r:#011x} ({r})  hi16={:#06x} lo16={:#06x}",
                    (r >> 16) & 0xFFFF, r & 0xFFFF);
            }
        }
        "drand48" => crack_drand48(v),
        "v8xs" => crack_v8_xs(v),
        "v8scan" => {
            // In-order, free shifts; scan output extraction modes. value*2^52 grid.
            use std::process::Command;
            let m52: Vec<u64> = v.iter().map(|&x| ((x + 1.0).to_bits()) & 0x000F_FFFF_FFFF_FFFF).collect();
            // exprs: new_s0=p1, new_s1=F, sum=(bvadd p1 F)
            let modes: [(&str, &str, &str); 6] = [
                ("s0>>12", "{P1}", "63 12"), ("s1>>12", "{F}", "63 12"), ("sum>>12", "(bvadd {P1} {F})", "63 12"),
                ("s0&m52", "{P1}", "51 0"), ("s1&m52", "{F}", "51 0"), ("sum&m52", "(bvadd {P1} {F})", "51 0"),
            ];
            for (name, expr, bits) in modes {
                let mut smt = String::from("(set-logic QF_BV)\n");
                for d in ["s0","s1","sa","sb","sc"] { smt.push_str(&format!("(declare-const {d} (_ BitVec 64))\n")); }
                for d in ["sa","sb","sc"] { smt.push_str(&format!("(assert (bvuge {d} (_ bv1 64)))(assert (bvule {d} (_ bv63 64)))\n")); }
                let (mut p0, mut p1s) = ("s0".to_string(), "s1".to_string());
                for i in 0..7 {
                    let (t1,t2,f)=(format!("t1_{i}"),format!("t2_{i}"),format!("F_{i}"));
                    smt.push_str(&format!("(declare-const {t1} (_ BitVec 64))(assert (= {t1} (bvxor {p0} (bvshl {p0} sa))))\n"));
                    smt.push_str(&format!("(declare-const {t2} (_ BitVec 64))(assert (= {t2} (bvxor {t1} (bvlshr {t1} sb))))\n"));
                    smt.push_str(&format!("(declare-const {f} (_ BitVec 64))(assert (= {f} (bvxor (bvxor {t2} {p1s}) (bvlshr {p1s} sc))))\n"));
                    let e = expr.replace("{P1}", &p1s).replace("{F}", &f);
                    let width = if bits == "63 12" { 52 } else { 52 };
                    smt.push_str(&format!("(assert (= ((_ extract {bits}) {e}) (_ bv{} {width})))\n", m52[i]));
                    p0 = p1s; p1s = f;
                }
                smt.push_str("(check-sat)\n");
                std::fs::write("/tmp/scan.smt2", &smt).unwrap();
                let out = Command::new("z3").arg("-T:90").arg("/tmp/scan.smt2").output().unwrap();
                let res = String::from_utf8_lossy(&out.stdout);
                println!("  mode {name:10}: {}", res.lines().next().unwrap_or("?"));
            }
        }
        "v8z3sumtop" => {
            // in-order, output = (s0+s1) >> 12 (TOP 52 of the sum), free shifts.
            use std::process::Command;
            let m: Vec<u64> = v.iter().map(|&x| ((x + 1.0).to_bits()) & 0x000F_FFFF_FFFF_FFFF).collect();
            let mut smt = String::from("(set-logic QF_BV)\n");
            for d in ["s0","s1","sa","sb","sc"] { smt.push_str(&format!("(declare-const {d} (_ BitVec 64))\n")); }
            for d in ["sa","sb","sc"] { smt.push_str(&format!("(assert (bvuge {d} (_ bv1 64)))(assert (bvule {d} (_ bv63 64)))\n")); }
            let (mut p0, mut p1) = ("s0".to_string(), "s1".to_string());
            for i in 0..8 {
                let (t1,t2,f)=(format!("t1_{i}"),format!("t2_{i}"),format!("F_{i}"));
                smt.push_str(&format!("(declare-const {t1} (_ BitVec 64))(assert (= {t1} (bvxor {p0} (bvshl {p0} sa))))\n"));
                smt.push_str(&format!("(declare-const {t2} (_ BitVec 64))(assert (= {t2} (bvxor {t1} (bvlshr {t1} sb))))\n"));
                smt.push_str(&format!("(declare-const {f} (_ BitVec 64))(assert (= {f} (bvxor (bvxor {t2} {p1}) (bvlshr {p1} sc))))\n"));
                smt.push_str(&format!("(assert (= ((_ extract 63 12) (bvadd {p1} {f})) (_ bv{} 52)))\n", m[i]));
                p0 = p1; p1 = f;
            }
            smt.push_str("(check-sat)\n(get-value (s0 s1 sa sb sc))\n");
            std::fs::write("/tmp/v8st.smt2", &smt).unwrap();
            let out = Command::new("z3").arg("-T:300").arg("/tmp/v8st.smt2").output().unwrap();
            let text = String::from_utf8_lossy(&out.stdout);
            println!("  {}", text.lines().next().unwrap_or("?"));
            if text.contains("sat") && !text.starts_with("unsat") {
                let dec: Vec<u64> = text.split("(_ bv").skip(1).filter_map(|s| s.chars().take_while(|c| c.is_ascii_digit()).collect::<String>().parse().ok()).collect();
                println!("    shifts(tail)={:?}", &dec[dec.len().saturating_sub(3)..]);
            }
        }
        "v8z3" => {
            // Early V8 via z3, free shifts, output = s0>>12 (52-bit) served IN ORDER.
            use std::process::Command;
            let k = 8usize;
            let m: Vec<u64> = v.iter().map(|&x| ((x + 1.0).to_bits()) & 0x000F_FFFF_FFFF_FFFF).collect();
            let mut smt = String::from("(set-logic QF_BV)\n");
            for d in ["s0", "s1", "sa", "sb", "sc"] { smt.push_str(&format!("(declare-const {d} (_ BitVec 64))\n")); }
            for d in ["sa", "sb", "sc"] { smt.push_str(&format!("(assert (bvuge {d} (_ bv1 64)))(assert (bvule {d} (_ bv63 64)))\n")); }
            let (mut p0, mut p1) = ("s0".to_string(), "s1".to_string());
            for i in 0..k {
                let (t1, t2, f) = (format!("t1_{i}"), format!("t2_{i}"), format!("F_{i}"));
                smt.push_str(&format!("(declare-const {t1} (_ BitVec 64))(assert (= {t1} (bvxor {p0} (bvshl {p0} sa))))\n"));
                smt.push_str(&format!("(declare-const {t2} (_ BitVec 64))(assert (= {t2} (bvxor {t1} (bvlshr {t1} sb))))\n"));
                smt.push_str(&format!("(declare-const {f} (_ BitVec 64))(assert (= {f} (bvxor (bvxor {t2} {p1}) (bvlshr {p1} sc))))\n"));
                // new_s0 = p1; output = new_s0 >> 12 = extract[63:12] of p1
                smt.push_str(&format!("(assert (= ((_ extract 63 12) {p1}) (_ bv{} 52)))\n", m[i]));
                p0 = p1; p1 = f;
            }
            smt.push_str("(check-sat)\n(get-value (s0 s1 sa sb sc))\n");
            std::fs::write("/tmp/v8.smt2", &smt).unwrap();
            let out = Command::new("z3").arg("-T:300").arg("/tmp/v8.smt2").output().unwrap();
            let text = String::from_utf8_lossy(&out.stdout);
            println!("  {}", text.lines().next().unwrap_or("?"));
            if text.contains("sat") && !text.starts_with("unsat") {
                let dec: Vec<u64> = text.split("(_ bv").skip(1)
                    .filter_map(|s| s.chars().take_while(|c| c.is_ascii_digit()).collect::<String>().parse().ok()).collect();
                let h: Vec<u64> = text.split("#x").skip(1)
                    .filter_map(|s| u64::from_str_radix(&s.chars().take_while(|c| c.is_ascii_hexdigit()).collect::<String>(),16).ok()).collect();
                println!("    shifts(dec tail)={:?} hexes={:?}", &dec[dec.len().saturating_sub(3)..], h);
            }
        }
        "v8shifts" => {
            // Early-V8 probe: reversed cache of 64 + s0>>12, but scan shift triples.
            let mant = |x: f64| ((x + 1.0).to_bits()) & 0x000F_FFFF_FFFF_FFFF;
            let mut hit = false;
            for &(a, b, c) in &[(23usize, 17usize, 26usize), (23, 18, 5), (23, 17, 26), (17, 23, 26), (23, 9, 26)] {
                let mut s0: Sym = std::array::from_fn(|i| 1u128 << i);
                let mut s1: Sym = std::array::from_fn(|i| 1u128 << (64 + i));
                let mut sym: Vec<Sym> = Vec::new();
                for _ in 0..192 { let (n0, n1) = sym_step_shifts(&s0, &s1, a, b, c); s0 = n0; s1 = n1; sym.push(s0); }
                for o in 0..64usize {
                    let mut rows = Vec::new();
                    for j in 0..60usize {
                        let g = (o + j) / 64 * 64 + (63 - (o + j) % 64);
                        if g >= sym.len() { break; }
                        let m = mant(v[j]) >> 0;
                        for bb in 0..52 { rows.push((sym[g][12 + bb], ((m >> bb) & 1) as u8)); }
                    }
                    let Some(sol) = solve_gf2(rows) else { continue };
                    // verify with reversed-cache generation using these shifts
                    let mut st = browser_rnd::prng::XorShift128Plus::new(sol as u64, (sol >> 64) as u64);
                    let mut served = Vec::new();
                    while served.len() < o + v.len().min(200) {
                        let mut batch = vec![];
                        for _ in 0..64 {
                            // step with these shifts manually
                            let (mut x, s0o) = (st.s0, st.s1);
                            st.s0 = s0o;
                            x ^= x << a; x ^= x >> b; x ^= s0o; x ^= s0o >> c; st.s1 = x;
                            batch.push(browser_rnd::engines::v8::to_double(st.s0));
                        }
                        for d in batch.into_iter().rev() { served.push(d); }
                    }
                    let ok = served[o..].iter().zip(v).take_while(|(p, q)| **p == **q).count();
                    if ok > 100 { println!("  REVERSED-CACHE shifts=({a},{b},{c}) offset={o} reproduced {ok}+"); hit = true; break; }
                }
                if hit { break; }
            }
            if !hit { println!("  no reversed-cache shift variant fit"); }
        }
        "v8stagea" => {
            // Early-4.9 MWC (Stage A): lanes 18030/36969, value mantissa =
            // (r0 & 0xFFFFF)<<32 | (r1 & 0xFFF00000), where r0,r1 are the stepped
            // 32-bit lane states. z3 solves the two 32-bit lane states.
            use std::process::Command;
            let k = 10usize;
            let m: Vec<u64> = v.iter().map(|&x| (x * 4_503_599_627_370_496.0).round() as u64).collect();
            let mut smt = String::from("(set-logic QF_BV)\n(declare-const s0 (_ BitVec 32))\n(declare-const s1 (_ BitVec 32))\n");
            let (mut p0, mut p1) = ("s0".to_string(), "s1".to_string());
            for i in 0..k {
                let (r0, r1) = (format!("r0_{i}"), format!("r1_{i}"));
                smt.push_str(&format!("(declare-const {r0} (_ BitVec 32))(assert (= {r0} (bvadd (bvmul (_ bv18030 32) (bvand {p0} (_ bv65535 32))) (bvlshr {p0} (_ bv16 32)))))\n"));
                smt.push_str(&format!("(declare-const {r1} (_ BitVec 32))(assert (= {r1} (bvadd (bvmul (_ bv36969 32) (bvand {p1} (_ bv65535 32))) (bvlshr {p1} (_ bv16 32)))))\n"));
                // mantissa (52-bit) = ((r0 & 0xFFFFF) << 32) | (r1 & 0xFFF00000)
                smt.push_str(&format!("(assert (= (bvor (bvshl ((_ zero_extend 20) (bvand {r0} (_ bv1048575 32))) (_ bv32 52)) ((_ zero_extend 20) (bvand {r1} (_ bv4293918720 32)))) (_ bv{} 52)))\n", m[i]));
                p0 = r0; p1 = r1;
            }
            smt.push_str("(check-sat)\n(get-value (s0 s1))\n");
            std::fs::write("/tmp/v8a.smt2", &smt).unwrap();
            let out = Command::new("z3").arg("-T:120").arg("/tmp/v8a.smt2").output().unwrap();
            let text = String::from_utf8_lossy(&out.stdout);
            if !text.contains("sat") || text.starts_with("unsat") { println!("  {}", text.lines().next().unwrap_or("?")); return; }
            let h: Vec<u64> = text.split("#x").skip(1)
                .filter_map(|s| u64::from_str_radix(&s.chars().take_while(|c| c.is_ascii_hexdigit()).collect::<String>(),16).ok()).collect();
            // verify forward
            let (mut s0, mut s1) = (h[0] as u32, h[1] as u32);
            let step = |s: u32, mu: u64| ((mu * ((s as u64)&0xFFFF) + ((s as u64)>>16)) & 0xFFFFFFFF) as u32;
            let mut ok = 0usize;
            for &want in &m {
                s0 = step(s0, 18030); s1 = step(s1, 36969);
                let mant = (((s0 as u64) & 0xFFFFF) << 32) | ((s1 as u64) & 0xFFF00000);
                if mant == want { ok += 1; } else { break; }
            }
            println!("  STAGE-A MWC 18030/36969 + ConstructDouble: s0={:#x} s1={:#x} reproduced {ok}/{}", h[0], h[1], v.len());
        }
        "v8revsum" => {
            // Hypothesis: reversed cache of 64 + Stage-B conversion (s0+s1)&mask52.
            // For batch offset o, observed[0..63-o] reversed == gen[0..63-o] (in order),
            // so de-reverse that window and run the in-order Stage-B z3 solve, then
            // verify with a reversed-cache sum-low52 generator.
            use std::process::Command;
            let p52 = 4_503_599_627_370_496.0f64;
            let solve = |win: &[f64]| -> Option<(u64, u64)> {
                let o: Vec<u64> = win.iter().map(|&x| (x * p52).round() as u64).collect();
                let mut smt = String::from("(set-logic QF_BV)\n(declare-const s0 (_ BitVec 64))\n(declare-const s1 (_ BitVec 64))\n");
                let (mut p0, mut p1) = ("s0".to_string(), "s1".to_string());
                for i in 0..8 {
                    let (t1, t2, f) = (format!("t1_{i}"), format!("t2_{i}"), format!("F_{i}"));
                    smt.push_str(&format!("(declare-const {t1} (_ BitVec 64))(assert (= {t1} (bvxor {p0} (bvshl {p0} (_ bv23 64)))))\n"));
                    smt.push_str(&format!("(declare-const {t2} (_ BitVec 64))(assert (= {t2} (bvxor {t1} (bvlshr {t1} (_ bv17 64)))))\n"));
                    smt.push_str(&format!("(declare-const {f} (_ BitVec 64))(assert (= {f} (bvxor (bvxor {t2} {p1}) (bvlshr {p1} (_ bv26 64)))))\n"));
                    smt.push_str(&format!("(assert (= ((_ extract 51 0) (bvadd {p1} {f})) (_ bv{} 52)))\n", o[i]));
                    p0 = p1; p1 = f;
                }
                smt.push_str("(check-sat)\n(get-value (s0 s1))\n");
                std::fs::write("/tmp/rev.smt2", &smt).ok()?;
                let out = Command::new("z3").arg("-T:30").arg("/tmp/rev.smt2").output().ok()?;
                let text = String::from_utf8_lossy(&out.stdout);
                if !text.contains("sat") || text.starts_with("unsat") { return None; }
                let h: Vec<u64> = text.split("#x").skip(1)
                    .filter_map(|s| u64::from_str_radix(&s.chars().take_while(|c| c.is_ascii_hexdigit()).collect::<String>(),16).ok()).collect();
                if h.len() < 2 { None } else { Some((h[0], h[1])) }
            };
            // V8 5.1-5.3: batch of 62 (slots 2..63) filled forward, served reversed.
            let gen_rev = |s0: u64, s1: u64, n: usize| -> Vec<f64> {
                let mut st = browser_rnd::prng::XorShift128Plus::new(s0, s1);
                let mut out = Vec::new();
                while out.len() < n {
                    let mut batch = Vec::with_capacity(62);
                    for _ in 0..62 { st.next_state(); batch.push((st.sum() & 0x000F_FFFF_FFFF_FFFF) as f64 / p52); }
                    for d in batch.into_iter().rev() { if out.len() < n { out.push(d); } }
                }
                out
            };
            let mut done = false;
            for o in 0..54usize {
                let take = 62 - o;
                if take < 8 { break; }
                let mut win: Vec<f64> = v[..take].to_vec();
                win.reverse();
                if let Some((s0, s1)) = solve(&win[..8.max(0)]) {
                    let regen = gen_rev(s0, s1, o + v.len());
                    let ok = regen[o..].iter().zip(v).take_while(|(a, b)| (**a - **b).abs() < 1e-15).count();
                    if ok > 100 {
                        println!("  REVERSED-CACHE + sum-low52: offset={o} s0={s0:#018x} s1={s1:#018x} reproduced {ok}/{}", v.len());
                        done = true; break;
                    }
                }
            }
            if !done { println!("  reversed-cache+sum-low52 did not fit"); }
        }
        "v8stageb" => {
            // Early-4.9 xorshift128+ (Stage B): in-order, ToDouble = (s0+s1) & (2^52-1).
            use std::process::Command;
            let k = 8usize;
            let o: Vec<u64> = v.iter().map(|&x| (x * 4_503_599_627_370_496.0).round() as u64).collect(); // *2^52
            let mut smt = String::from("(set-logic QF_BV)\n(declare-const s0 (_ BitVec 64))\n(declare-const s1 (_ BitVec 64))\n");
            let (mut p0, mut p1) = ("s0".to_string(), "s1".to_string());
            for i in 0..k {
                let (t1, t2, f) = (format!("t1_{i}"), format!("t2_{i}"), format!("F_{i}"));
                smt.push_str(&format!("(declare-const {t1} (_ BitVec 64))(assert (= {t1} (bvxor {p0} (bvshl {p0} (_ bv23 64)))))\n"));
                smt.push_str(&format!("(declare-const {t2} (_ BitVec 64))(assert (= {t2} (bvxor {t1} (bvlshr {t1} (_ bv17 64)))))\n"));
                smt.push_str(&format!("(declare-const {f} (_ BitVec 64))(assert (= {f} (bvxor (bvxor {t2} {p1}) (bvlshr {p1} (_ bv26 64)))))\n"));
                smt.push_str(&format!("(assert (= ((_ extract 51 0) (bvadd {p1} {f})) (_ bv{} 52)))\n", o[i]));
                p0 = p1; p1 = f;
            }
            smt.push_str("(check-sat)\n(get-value (s0 s1))\n");
            std::fs::write("/tmp/v8b.smt2", &smt).unwrap();
            let out = Command::new("z3").arg("-T:120").arg("/tmp/v8b.smt2").output().unwrap();
            let text = String::from_utf8_lossy(&out.stdout);
            if !text.contains("sat") || text.starts_with("unsat") { println!("  {}", text.lines().next().unwrap_or("?")); return; }
            let h: Vec<u64> = text.split("#x").skip(1)
                .filter_map(|s| u64::from_str_radix(&s.chars().take_while(|c| c.is_ascii_hexdigit()).collect::<String>(),16).ok()).collect();
            // verify forward with Stage B model
            let mut st = browser_rnd::prng::XorShift128Plus::new(h[0], h[1]);
            let mut ok = 0usize;
            for &want in v {
                st.next_state();
                let val = ((st.sum() & 0x000F_FFFF_FFFF_FFFF) as f64) / 4_503_599_627_370_496.0;
                if val == want { ok += 1; } else { break; }
            }
            println!("  STAGE-B xorshift128+ in-order, (s0+s1)&mask52: s0={:#018x} s1={:#018x} reproduced {ok}/{}", h[0], h[1], v.len());
        }
        "v8inorder" => {
            // Early V8 xorshift128+ hypothesis: s0>>12 served IN ORDER (no reversed
            // cache). observed[j] = s0 after (offset+j+1) steps. GF(2) solve.
            let mut s0: Sym = std::array::from_fn(|i| 1u128 << i);
            let mut s1: Sym = std::array::from_fn(|i| 1u128 << (64 + i));
            let mut sym: Vec<Sym> = Vec::new();
            for _ in 0..160 { let (n0, n1) = sym_step(&s0, &s1); s0 = n0; s1 = n1; sym.push(s0); }
            let mant = |x: f64| ((x + 1.0).to_bits()) & 0x000F_FFFF_FFFF_FFFF;
            let mut done = false;
            for off in 0..32usize {
                let mut rows = Vec::new();
                for j in 0..60usize {
                    let g = off + j;
                    let m = mant(v[j]);
                    for b in 0..52 { rows.push((sym[g][12 + b], ((m >> b) & 1) as u8)); }
                }
                let Some(sol) = solve_gf2(rows) else { continue };
                // verify in-order forward
                let mut st = browser_rnd::prng::XorShift128Plus::new(sol as u64, (sol >> 64) as u64);
                for _ in 0..off { st.next_state(); }
                let mut ok = 0usize;
                for &want in v {
                    st.next_state();
                    if browser_rnd::engines::v8::to_double(st.s0) == want { ok += 1; } else { break; }
                }
                if ok > 100 {
                    println!("  IN-ORDER xorshift128+ (no cache): offset={off} reproduced {ok}/{}", v.len());
                    done = true; break;
                }
            }
            if !done { println!("  in-order xorshift128+ did not fit"); }
        }
        "sm" => crack_sm(v),
        "smz3" => crack_sm_z3(v),
        "iez3" => {
            let w: u32 = args.get(3).and_then(|s| s.parse().ok()).unwrap_or(54);
            crack_ie_xs_z3(v, w);
        }
        "smz3test" => {
            // self-test: synthetic SM data from a known seed
            let syn = browser_rnd::engines::spidermonkey::generate(
                browser_rnd::prng::XorShift128Plus::new(0x1234_5678_9abc_def0, 0x0fed_cba9_8765_4321), 300);
            crack_sm_z3(&syn);
        }
        "jsz3" => {
            let b: u32 = args.get(3).and_then(|s| s.parse().ok()).unwrap_or(48);
            crack_jscript_z3(v, b);
        }
        "mwc" => crack_mwc(v, 32, 16, 16),
        "mwc30" => {
            // probe a few plausible 30-bit layouts
            crack_mwc(v, 30, 16, 16);
            crack_mwc(v, 30, 15, 15);
            crack_mwc(v, 30, 14, 16);
        }
        other => eprintln!("unknown experiment {other}"),
    }
}
