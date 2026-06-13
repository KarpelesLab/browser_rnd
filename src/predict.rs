//! High-level prediction API.
//!
//! Give it a run of consecutive `Math.random()` outputs from one browser/context
//! and it (1) identifies the engine + era (and the browsers that ship it), and
//! (2) returns a [`Predictor`] that generates the values which come **next** and
//! the ones that came **before** — every supported generator is invertible.
//!
//! ```ignore
//! let p = browser_rnd::predict::recover(&values).unwrap();
//! println!("{} — {}", p.id().engine, p.id().algorithm);
//! let after  = p.forward(10);   // the next 10 Math.random() values
//! let before = p.backward(10);  // the 10 values before the first observed one
//! ```
//!
//! Presto/Opera is identified but not predictable (SNOW 2.0 CSPRNG).

use crate::engines::{jsc, jscript, spidermonkey, spidermonkey_legacy, v8, v8_legacy, v8_libc};
use crate::prng::XorShift128Plus;

/// What produced a capture.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Identification {
    pub engine: &'static str,
    pub algorithm: &'static str,
    pub browsers: &'static str,
    pub grid_bits: u32,
    pub time_seeded: &'static str,
    pub predictable: bool,
}

#[derive(Clone)]
enum Gen {
    V8Modern { seed: XorShift128Plus, offset: usize }, // reversed-64 cache, s0>>12
    V8StageB { seed: XorShift128Plus },                // in-order, (s0+s1)&mask52
    V8Rev5x { seed: XorShift128Plus, offset: usize },  // reversed-62 cache, (s0+s1)&mask52
    Mwc(v8_legacy::Mwc),
    MwcStageA { s0: u32, s1: u32 },
    Libc(u32),
    SmModern(XorShift128Plus),                         // in-order, (s0+s1)&mask53 low
    Drand48Sm(u64),                                    // 48-bit LCG, 26+27, /2^53
    Drand48Ie(u64),                                    // 48-bit LCG, 27+27, /2^54
    GameRand(jsc::GameRand),
}

/// A recovered generator positioned at a capture, able to extend it both ways.
#[derive(Clone)]
pub struct Predictor {
    id: Identification,
    gen: Gen,
    observed: usize,
}

// ---- small primitives for backward stepping --------------------------------
const D48_MULT: u64 = 0x5DEECE66D;
const D48_ADD: u64 = 0xB;
const D48_MASK: u64 = (1 << 48) - 1;

fn modinv_pow2(a: u64, bits: u32) -> u64 {
    let mut x = 1u64;
    for _ in 0..6 {
        x = x.wrapping_mul(2u64.wrapping_sub(a.wrapping_mul(x)));
    }
    if bits >= 64 { x } else { x & ((1 << bits) - 1) }
}

fn d48_prev(s: u64) -> u64 {
    let inv = modinv_pow2(D48_MULT, 48);
    ((s + D48_MASK + 1 - D48_ADD) & D48_MASK).wrapping_mul(inv) & D48_MASK
}

fn libc_prev(s: u32) -> u32 {
    let inv = modinv_pow2(214013, 32);
    ((((s as u64) + (1 << 32) - 2531011) & 0xFFFF_FFFF).wrapping_mul(inv) & 0xFFFF_FFFF) as u32
}

fn mwc_lane_prev(s2: u32, mult: u64) -> u32 {
    let step = |s: u32| ((mult * ((s as u64) & 0xFFFF) + ((s as u64) >> 16)) & 0xFFFF_FFFF) as u32;
    let base = (s2 as u64) / mult;
    for d in 0..=6u64 {
        let lo = base.saturating_sub(d);
        let hi = (s2 as u64).wrapping_sub(mult * lo);
        if hi < (1 << 16) {
            let cand = ((hi << 16) | lo) as u32;
            if step(cand) == s2 {
                return cand;
            }
        }
    }
    s2 // unreachable for valid MWC states
}

fn gamerand_back(g: jsc::GameRand) -> jsc::GameRand {
    let low = g.low.wrapping_sub(g.high);
    let high = g.high.wrapping_sub(low).rotate_right(16);
    jsc::GameRand { low, high }
}

/// Value served at (signed) served-index `s` for a V8 reversed cache of `batch`
/// gens. Negative `s` reaches earlier batches by stepping the state backward.
/// `sum52` selects the 5.x `(s0+s1)&mask52` conversion vs modern `s0>>12`.
fn v8_served(seed: XorShift128Plus, batch: i64, sum52: bool, s: i64) -> f64 {
    let b = s.div_euclid(batch);
    let pos = s.rem_euclid(batch);
    let gen = batch - 1 - pos; // 0-based gen within the batch (served reversed)
    let mut st = seed;
    if b >= 0 {
        for _ in 0..b * batch { st.next_state(); }
    } else {
        for _ in 0..-b * batch { st.prev_state(); }
    }
    for _ in 0..=gen { st.next_state(); }
    if sum52 {
        (st.sum() & 0x000F_FFFF_FFFF_FFFF) as f64 / 4_503_599_627_370_496.0
    } else {
        v8::to_double(st.s0)
    }
}

fn grid_bits(values: &[f64]) -> u32 {
    for k in [30u32, 31, 32, 52, 53, 54] {
        let s = 2f64.powi(k as i32);
        if values.iter().all(|&v| (v * s - (v * s).round()).abs() < 1e-4) {
            return k;
        }
    }
    0
}

impl Predictor {
    pub fn id(&self) -> &Identification {
        &self.id
    }

    /// The next `n` `Math.random()` values (those that come after the capture).
    pub fn forward(&self, n: usize) -> Vec<f64> {
        let o = self.observed;
        match &self.gen {
            Gen::V8Modern { seed, offset } => v8::generate(*seed, offset + o + n)[offset + o..].to_vec(),
            Gen::V8Rev5x { seed, offset } => v8::generate_5x(*seed, offset + o + n)[offset + o..].to_vec(),
            Gen::V8StageB { seed } => v8::generate_early(*seed, o + n)[o..].to_vec(),
            Gen::Mwc(m) => m.generate(o + n)[o..].to_vec(),
            Gen::MwcStageA { s0, s1 } => v8_legacy::generate_stage_a(*s0, *s1, o + n)[o..].to_vec(),
            Gen::Libc(st) => v8_libc::generate(*st, o + n)[o..].to_vec(),
            Gen::SmModern(seed) => spidermonkey::generate(*seed, o + n)[o..].to_vec(),
            Gen::Drand48Sm(seed) => spidermonkey_legacy::generate(*seed, o + n)[o..].to_vec(),
            Gen::Drand48Ie(seed) => jscript::generate(*seed, o + n)[o..].to_vec(),
            Gen::GameRand(st) => jsc::generate(*st, o + n)[o..].to_vec(),
        }
    }

    /// The `n` values immediately before the capture, chronological order (so the
    /// last element is the one right before the first observed value). For V8's
    /// cache models this is bounded by the page-start offset; for the others it
    /// rewinds the recurrence (valid back to the realm's seed).
    pub fn backward(&self, n: usize) -> Vec<f64> {
        match &self.gen {
            // V8 cache models: served-index walk handles crossing batch boundaries
            // backward (earlier batches via stepping the state back).
            Gen::V8Modern { seed, offset } => {
                let o = *offset as i64;
                ((o - n as i64)..o).map(|s| v8_served(*seed, 64, false, s)).collect()
            }
            Gen::V8Rev5x { seed, offset } => {
                let o = *offset as i64;
                ((o - n as i64)..o).map(|s| v8_served(*seed, 62, true, s)).collect()
            }
            // Contiguous models: rewind the anchor n outputs, then generate forward.
            Gen::V8StageB { seed } => {
                let mut s = *seed;
                for _ in 0..n { s.prev_state(); }
                v8::generate_early(s, n)
            }
            Gen::SmModern(seed) => {
                let mut s = *seed;
                for _ in 0..n { s.prev_state(); }
                spidermonkey::generate(s, n)
            }
            Gen::Drand48Sm(seed) => {
                let mut s = *seed;
                for _ in 0..2 * n { s = d48_prev(s); }
                spidermonkey_legacy::generate(s, n)
            }
            Gen::Drand48Ie(seed) => {
                let mut s = *seed;
                for _ in 0..2 * n { s = d48_prev(s); }
                jscript::generate(s, n)
            }
            Gen::Libc(st) => {
                let mut s = *st;
                for _ in 0..2 * n { s = libc_prev(s); }
                v8_libc::generate(s, n)
            }
            Gen::Mwc(m) => {
                let (mut a, mut b) = (m.s0, m.s1);
                for _ in 0..n {
                    a = mwc_lane_prev(a, m.mult0);
                    b = mwc_lane_prev(b, m.mult1);
                }
                v8_legacy::Mwc { s0: a, s1: b, ..*m }.generate(n)
            }
            Gen::MwcStageA { s0, s1 } => {
                let (mut a, mut b) = (*s0, *s1);
                for _ in 0..n {
                    a = mwc_lane_prev(a, 18030);
                    b = mwc_lane_prev(b, 36969);
                }
                v8_legacy::generate_stage_a(a, b, n)
            }
            Gen::GameRand(g) => {
                let mut s = *g;
                for _ in 0..n { s = gamerand_back(s); }
                jsc::generate(s, n)
            }
        }
    }
}

fn id(engine: &'static str, algorithm: &'static str, browsers: &'static str, grid: u32, time: &'static str) -> Identification {
    Identification { engine, algorithm, browsers, grid_bits: grid, time_seeded: time, predictable: true }
}

/// Recover a [`Predictor`] from consecutive observed values. Tries each engine
/// for the value grid and verifies by reproduction. Some paths use the z3 SMT
/// solver (modern SpiderMonkey, V8 4.9/5.x) and return `None` if z3 is absent.
pub fn recover(values: &[f64]) -> Option<Predictor> {
    let obs = values.len();
    let g = grid_bits(values);
    let wrap = |id, gen| Some(Predictor { id, gen, observed: obs });
    match g {
        30 => wrap(id("V8", "libc rand()×2 (srand(time))", "Chrome 1", 30, "yes — wall-clock ms"), Gen::Libc(v8_libc::recover(values)?)),
        32 => {
            if let Some(m) = v8_legacy::recover(values) {
                let alg = if m.combine == v8_legacy::Combine::Shift14 { "MWC1616 era 1 (<<14)" } else { "MWC1616 era 2/3 (<<16)" };
                return wrap(id("V8", alg, "Chrome 10–46, Opera 16–22", 32, "in-browser CSPRNG (≥Chrome 15)"), Gen::Mwc(m));
            }
            if let Some(st) = jsc::recover(values) {
                return wrap(id("JavaScriptCore", "GameRand (32-bit seed)", "Safari ≤8, iOS", 32, "no — crypto, but 32-bit"), Gen::GameRand(st));
            }
            if let Some((s0, s1)) = v8_legacy::recover_stage_a(values) {
                return wrap(id("V8", "MWC + %_ConstructDouble (4.9 Stage A)", "Chrome 48", 32, "CSPRNG"), Gen::MwcStageA { s0, s1 });
            }
            None
        }
        52 => {
            if let Some((seed, offset)) = v8::recover(values) {
                return wrap(id("V8", "xorshift128+ (s0>>12, reversed cache)", "Chrome 70+, Edge, Brave, Vivaldi, Opera", 52, "no — OS CSPRNG"), Gen::V8Modern { seed, offset });
            }
            if let Some(seed) = v8::recover_early(values) {
                return wrap(id("V8", "xorshift128+ in-order ((s0+s1)&mask52, 4.9 Stage B)", "Chrome 49–50", 52, "no — OS CSPRNG"), Gen::V8StageB { seed });
            }
            if let Some((seed, offset)) = v8::recover_5x(values) {
                return wrap(id("V8", "xorshift128+ reversed-62 ((s0+s1)&mask52, V8 5.1–5.3)", "Chrome 52–53, Opera 38–40", 52, "no — OS CSPRNG"), Gen::V8Rev5x { seed, offset });
            }
            None
        }
        53 => {
            if let Some(seed) = spidermonkey_legacy::recover(values) {
                return wrap(id("SpiderMonkey", "drand48 48-bit LCG (26+27)", "Firefox ≤48", 53, "yes if ≤FF23, else CSPRNG"), Gen::Drand48Sm(seed));
            }
            if let Some(seed) = spidermonkey::recover(values) {
                return wrap(id("SpiderMonkey", "xorshift128+ ((s0+s1) low 53)", "Firefox 49+, Pale Moon", 53, "no — OS CSPRNG"), Gen::SmModern(seed));
            }
            None
        }
        54 => wrap(id("JScript/Chakra", "drand48 48-bit LCG (27+27 → 2⁻⁵⁴)", "Internet Explorer 6–11", 54, "yes — RDTSC timer"), Gen::Drand48Ie(jscript::recover(values)?)),
        _ => None,
    }
}

/// Identify the engine/era without committing to recovery. Returns an
/// `Identification` (with `predictable: false` for Presto, which can't be
/// recovered). Note: this still runs recovery internally to be certain.
pub fn identify(values: &[f64]) -> Option<Identification> {
    if let Some(p) = recover(values) {
        return Some(p.id);
    }
    // Grid 2⁻⁵³ that isn't drand48 or modern SpiderMonkey is almost certainly Presto.
    if grid_bits(values) == 53 {
        return Some(Identification {
            engine: "Presto",
            algorithm: "SNOW 2.0 stream cipher (CSPRNG)",
            browsers: "Opera 7–12",
            grid_bits: 53,
            time_seeded: "n/a — continuously reseeded",
            predictable: false,
        });
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    // For each non-z3 engine: generate a known stream, hand the predictor a middle
    // slice, and check it reconstructs the future and the past exactly.
    fn check(full: &[f64], engine: &str) {
        let (a, b) = (40usize, 110usize);
        let p = recover(&full[a..b]).unwrap_or_else(|| panic!("{engine}: recover failed"));
        assert_eq!(p.id().engine, engine, "{engine}: wrong engine ({})", p.id().engine);
        assert!(p.forward(30).iter().zip(&full[b..b + 30]).all(|(x, y)| (x - y).abs() < 1e-12), "{engine}: forward");
        assert!(p.backward(a).iter().zip(&full[..a]).all(|(x, y)| (x - y).abs() < 1e-12), "{engine}: backward");
    }

    #[test]
    fn drand48_sm() {
        check(&spidermonkey_legacy::generate(0x1234_5678_9abc & D48_MASK, 200), "SpiderMonkey");
    }
    #[test]
    fn drand48_ie() {
        check(&jscript::generate(0x2233_4455_6677 & D48_MASK, 200), "JScript/Chakra");
    }
    #[test]
    fn mwc() {
        let g = v8_legacy::Mwc { s0: 0x1111_2222, s1: 0x3333_4444, mult0: 18273, mult1: 36969, combine: v8_legacy::Combine::Shift16 };
        check(&g.generate(200), "V8");
    }
    #[test]
    fn libc() {
        check(&v8_libc::generate(0x0bad_f00d, 200), "V8");
    }
    #[test]
    fn gamerand() {
        check(&jsc::generate(jsc::GameRand::seeded(0xdead_beef), 200), "JavaScriptCore");
    }
    #[test]
    fn modern_v8() {
        let full = v8::generate(XorShift128Plus::new(0x9e37_79b9_7f4a_7c15, 0x1234_5678_9abc_def0), 200);
        check(&full, "V8");
    }
}
