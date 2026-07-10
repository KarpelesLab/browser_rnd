//! Engine fingerprinting from a captured sample.
//!
//! Two independent signals:
//!  1. The userAgent string (a prior — see [`Sample::guess_engine`]).
//!  2. The *structure of the values themselves*, which is harder to spoof and
//!     works even with no/garbage UA.
//!
//! The most useful structural signal is the **mantissa resolution**: how many
//! fractional bits the engine actually populates.
//!  - V8 returns `mantissa52 / 2^52` → every value is a multiple of `2^-52`
//!    (so `v * 2^53` is always even). Resolution 52.
//!  - SpiderMonkey and JSC return `m / 2^53` with `m` up to 53 bits → `v * 2^53`
//!    is sometimes odd. Resolution 53.
//!  - Legacy JScript yields far fewer bits (LCG scaled by a small denominator).
//!    Resolution ≪ 52.
//!
//! Resolution cannot separate SpiderMonkey from JSC (both are `m/2^53`); only
//! reproduction from a recovered state can, which is where the UA prior and the
//! `engines::{spidermonkey,jsc}` models come in.

use crate::engines::Engine;
use crate::sample::Sample;

#[derive(Clone, Debug)]
pub struct Fingerprint {
    /// Highest number of fractional bits observed across the sample (1..=53).
    pub resolution_bits: u32,
    /// Engines consistent with the structural signal, most-likely first.
    pub structural_candidates: Vec<Engine>,
    /// Engine implied by the userAgent, if any.
    pub ua_guess: Option<Engine>,
}

/// Largest `n` in `1..=53` such that some value requires `n` fractional bits to
/// represent exactly (i.e. `round(v * 2^n)` is odd). Returns 0 if all values are
/// zero. This estimates the generator's output width.
pub fn mantissa_resolution(values: &[f64]) -> u32 {
    let mut max_bits = 0u32;
    for &v in values {
        if v <= 0.0 {
            continue;
        }
        // Scale to the full 53-bit grid; the position of the lowest set bit tells
        // us how many bits this particular value needed.
        let scaled = (v * 9_007_199_254_740_992.0).round() as u64; // v * 2^53
        if scaled == 0 {
            continue;
        }
        let bits = 53 - scaled.trailing_zeros();
        if bits > max_bits {
            max_bits = bits;
        }
    }
    max_bits
}

pub fn fingerprint(sample: &Sample) -> Fingerprint {
    let resolution_bits = mantissa_resolution(&sample.values);
    let structural_candidates = match resolution_bits {
        53 => vec![Engine::SpiderMonkey, Engine::JavaScriptCore, Engine::Dart],
        52 => vec![Engine::V8],
        // Below the modern engines' width ⇒ legacy / low-entropy generator.
        0..=40 => vec![Engine::JScript],
        // 41..=51: ambiguous — could be a modern engine that happened not to
        // exercise the top bits in a short sample. Offer the modern set.
        _ => vec![Engine::V8, Engine::SpiderMonkey, Engine::JavaScriptCore],
    };
    Fingerprint {
        resolution_bits,
        structural_candidates,
        ua_guess: sample.guess_engine(),
    }
}

/// A human-readable summary for the CLI.
pub fn report(sample: &Sample) -> String {
    let fp = fingerprint(sample);
    let mut out = String::new();
    out.push_str(&format!("values:        {}\n", sample.values.len()));
    if let Some(ua) = sample.user_agent() {
        out.push_str(&format!("userAgent:     {ua}\n"));
    }
    out.push_str(&format!("resolution:    {} bits\n", fp.resolution_bits));
    out.push_str(&format!(
        "ua guess:      {}\n",
        fp.ua_guess.map(Engine::name).unwrap_or("unknown")
    ));
    let names: Vec<&str> = fp.structural_candidates.iter().map(|e| e.name()).collect();
    out.push_str(&format!("structural:    {}\n", names.join(", ")));

    // Agreement check.
    let agrees = fp
        .ua_guess
        .map(|g| fp.structural_candidates.contains(&g))
        .unwrap_or(false);
    out.push_str(&format!(
        "verdict:       {}\n",
        match (fp.ua_guess, agrees) {
            (Some(g), true) => format!("{} (UA and structure agree)", g.name()),
            (Some(g), false) => format!(
                "conflict — UA says {}, structure says {}",
                g.name(),
                names.join("/")
            ),
            (None, _) => format!("{} (structure only)", names.join("/")),
        }
    ));
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engines::{spidermonkey, v8};
    use crate::prng::XorShift128Plus;

    #[test]
    fn detects_v8_resolution() {
        let vals = v8::generate(XorShift128Plus::new(1, 2), 200);
        assert_eq!(mantissa_resolution(&vals), 52);
    }

    #[test]
    fn detects_spidermonkey_resolution() {
        let vals = spidermonkey::generate(XorShift128Plus::new(1, 2), 200);
        assert_eq!(mantissa_resolution(&vals), 53);
    }
}
