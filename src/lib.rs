//! browser_rnd — analyze, reproduce, reverse engineer and brute force the
//! `Math.random()` PRNGs of various browsers, from MSIE 6 (JScript LCG) through
//! modern V8 / SpiderMonkey / JavaScriptCore (xorshift128+).
//!
//! Layout:
//! - [`prng`]    raw generators (xorshift128+, LCG), no browser quirks
//! - [`engines`] per-browser output conversions and serving order
//! - [`sample`]  parsing captured textarea dumps from the collector
//! - [`analyze`] engine fingerprinting and reproduction checks over a sample

pub mod analyze;
pub mod engines;
pub mod prng;
pub mod sample;

pub use engines::Engine;
pub use sample::Sample;
