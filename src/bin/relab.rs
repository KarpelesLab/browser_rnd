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
