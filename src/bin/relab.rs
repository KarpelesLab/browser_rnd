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
    for k in [30u32, 31, 32, 48, 52, 53] {
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

/// Recover a lane's full 32-bit initial state from observed lows + multiplier.
fn recover_lane_state(lo: &[u64], c: u64) -> u64 {
    let hi0 = (lo[1] + M16 - (c * lo[0]) % M16) % M16;
    (hi0 << 16) | lo[0]
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
/// XorShift128Plus::next_state exactly.
fn sym_step(s0: &Sym, s1: &Sym) -> (Sym, Sym) {
    let mut t = *s0; // s1 := old s0
    let s0_old = *s1; // s0 := old s1
    t = sym_xor(&t, &sym_shl(&t, 23));
    t = sym_xor(&t, &sym_shr(&t, 17));
    t = sym_xor(&t, &s0_old);
    t = sym_xor(&t, &sym_shr(&s0_old, 26));
    (s0_old, t) // (new_s0, new_s1)
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
        "conv" => conv(v),
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
