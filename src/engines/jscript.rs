//! Legacy JScript `Math.random()` — MSIE 6 / 7 / 8.
//!
//! JScript predates the xorshift128+ era; its `Math.random()` is LCG-family. The
//! exact multiplier, increment, modulus and output scaling are NOT yet confirmed
//! in this project — this module lists candidate parameter sets to *test against
//! real captures* (`samples/`) rather than asserting any is correct. Once a
//! candidate reproduces a captured sequence, promote it to the verified path.
//!
//! EMPIRICAL FINDING (from `samples/ie6.txt`, a genuine MSIE 6.0 on Windows XP):
//! vintage JScript emits **full 53-bit doubles**, same structural resolution as
//! the modern xorshift128+ engines — so it is NOT the ~15-bit, `rand()`-style
//! generator one might assume. Two consequences:
//!   - The narrow `msvc-lcg` candidate below (15-bit output) is ruled out by the
//!     observed 53-bit resolution; a wide generator that fills a 53-bit mantissa
//!     (an LCG-built double, à la old SpiderMonkey/Java) is the plausible shape.
//!   - Do NOT read `.NET CLR` / `.NET4.0` tokens in an MSIE UA as "modern IE in
//!     compat mode". IE appends the *installed* .NET framework versions to its
//!     UA; a real IE6 on an XP box with .NET installed shows them too.
//! ie7.txt and ie8.txt also read 53-bit, consistent with the same engine family.

use crate::prng::Lcg;

/// A named candidate LCG configuration to evaluate against captured JScript
/// output. None are confirmed; this is the search space, not the answer.
pub struct Candidate {
    pub name: &'static str,
    pub make: fn(seed: u64) -> Lcg,
    /// How the engine is believed to scale state into `[0, 1)`, for this guess.
    pub scale: fn(state: u64) -> f64,
}

/// Classic MSVC-runtime-style LCG (`state = state*214013 + 2531011`, bits 16..30
/// of the 31-bit state form the output). Listed because several MS engines of
/// the era reused it; treat as unverified.
fn msvc_make(seed: u64) -> Lcg {
    Lcg::pow2(seed, 214_013, 2_531_011, 31)
}
fn msvc_scale(state: u64) -> f64 {
    (((state >> 16) & 0x7FFF) as f64) / 32_768.0
}

/// 53-bit-mantissa LCG candidate: a full-width multiply scaled by 2^-53.
fn wide_make(seed: u64) -> Lcg {
    Lcg::pow2(seed, 6_364_136_223_846_793_005, 1_442_695_040_888_963_407, 64)
}
fn wide_scale(state: u64) -> f64 {
    ((state >> 11) as f64) / 9_007_199_254_740_992.0
}

pub const CANDIDATES: &[Candidate] = &[
    Candidate { name: "msvc-lcg", make: msvc_make, scale: msvc_scale },
    Candidate { name: "wide-lcg", make: wide_make, scale: wide_scale },
];

/// Generate `n` doubles from a named candidate, for comparison against a capture.
pub fn generate(candidate: &Candidate, seed: u64, n: usize) -> Vec<f64> {
    let mut lcg = (candidate.make)(seed);
    let mut out = Vec::with_capacity(n);
    for _ in 0..n {
        let s = lcg.next_state();
        out.push((candidate.scale)(s));
    }
    out
}
