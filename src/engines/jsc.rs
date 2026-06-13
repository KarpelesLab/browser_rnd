//! JavaScriptCore `Math.random()` — Safari / iOS WebViews.
//!
//! VERSION SPLIT:
//!  - Safari ≤ 8 used **WeakRandom = "GameRand"** (Ian Bullard, 2009): a tiny
//!    64-bit-state PRNG (two 32-bit words), output `m_high / 2^32` → grid 2⁻³².
//!    CONFIRMED: reproduces `samples/safari/safari5.1.7-winxp.txt` 4096/4096, so
//!    GameRand was in use by at least Safari 5.1.7 (2012).
//!  - Safari ≥ 9 switched WeakRandom to **xorshift128+** (like V8/SpiderMonkey),
//!    with JSC's own double conversion — TBD pending a Safari 9+ capture.
//!
//! GameRand (runtime/WeakRandom.h):
//! ```text
//! advance(): m_high = rotl32(m_high,16) + m_low; m_low += m_high; return m_high
//! get():     advance() / 2^32
//! seed:      m_low = seed ^ 0x49616E42 ("IanB"); m_high = seed
//! ```
//! The output is the *full* 32-bit `m_high` (no truncation), so two consecutive
//! outputs recover the hidden `m_low` in closed form — no search needed.

const P32: f64 = 4_294_967_296.0; // 2^32

/// GameRand state: the two 32-bit accumulators.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GameRand {
    pub low: u32,
    pub high: u32,
}

impl GameRand {
    /// Seed exactly as JSC does (per JSGlobalObject).
    pub fn seeded(seed: u32) -> Self {
        GameRand { low: seed ^ 0x4961_6E42, high: seed }
    }

    /// Advance and return the 32-bit output (`m_high` after mixing).
    #[inline]
    pub fn advance(&mut self) -> u32 {
        self.high = self.high.rotate_left(16).wrapping_add(self.low);
        self.low = self.low.wrapping_add(self.high);
        self.high
    }
}

/// Generate `n` doubles starting from `state` (state before the first output).
pub fn generate(mut state: GameRand, n: usize) -> Vec<f64> {
    let mut out = Vec::with_capacity(n);
    for _ in 0..n {
        out.push(state.advance() as f64 / P32);
    }
    out
}

/// Recover the state from observed outputs. `out_k = m_high` after step k, and
/// `m_high_k = rotl(m_high_{k-1},16) + m_low_{k-1}`, so `m_low` falls out of two
/// consecutive outputs; we then step back one to get the pre-first-output state.
/// Verified by full reproduction, so `Some` is conclusive.
pub fn recover(values: &[f64]) -> Option<GameRand> {
    if values.len() < 3 {
        return None;
    }
    let h: Vec<u32> = values.iter().map(|&v| (v * P32).round() as u32).collect();
    // state right after output 0: high = h[0], low = h[1] - rotl(h[0],16)
    let low0 = h[1].wrapping_sub(h[0].rotate_left(16));
    let high0 = h[0];
    // step back one: pre.low = low0 - high0 ; pre.high = rotr(high0 - pre.low, 16)
    let pre_low = low0.wrapping_sub(high0);
    let pre_high = high0.wrapping_sub(pre_low).rotate_right(16);
    let state = GameRand { low: pre_low, high: pre_high };
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

/// Step the GameRand state backward one advance (the advance is invertible).
fn step_back(s: GameRand) -> GameRand {
    let low = s.low.wrapping_sub(s.high); // prev_low (since low' = low + high')
    let high = s.high.wrapping_sub(low).rotate_right(16); // prev_high
    GameRand { low, high }
}

/// Recover the original 32-bit seed Safari was given (from `randomNumber()` per
/// global object). GameRand seeds with `m_low = seed ^ 0x49616E42`, `m_high =
/// seed`, so `high ^ low == 0x49616E42` exactly at seed time. We recover the
/// running state, then step backward until that invariant holds. Returns the
/// seed and how many draws preceded the first observed value, or `None` if not
/// found within `max_back` steps. The whole state is just 32 bits of entropy.
pub fn recover_seed(values: &[f64], max_back: usize) -> Option<(u32, usize)> {
    const IANB: u32 = 0x4961_6E42;
    let mut s = recover(values)?; // state before the first observed advance
    for k in 0..max_back {
        if s.high ^ s.low == IANB {
            return Some((s.high, k));
        }
        s = step_back(s);
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seed_round_trip() {
        // Seed, advance a warmup, capture — then recover the exact seed.
        let mut st = GameRand::seeded(0x0badf00d);
        for _ in 0..137 { st.advance(); } // warmup draws before our capture
        let v = generate(st, 300);
        let (seed, back) = recover_seed(&v, 1_000_000).expect("seed");
        assert_eq!(seed, 0x0badf00d);
        assert_eq!(back, 137);
    }

    #[test]
    fn recover_round_trip() {
        let v = generate(GameRand::seeded(0x12345678), 300);
        let st = recover(&v).expect("recover");
        assert!(generate(st, 300).iter().zip(&v).all(|(a, b)| (a - b).abs() < 1e-15));
    }

    #[test]
    fn output_in_unit_interval() {
        for d in generate(GameRand::seeded(1), 100) {
            assert!((0.0..1.0).contains(&d));
        }
    }
}
