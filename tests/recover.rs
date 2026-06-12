//! End-to-end recovery tests: take a real capture, recover the generator state,
//! and assert the recovered state reproduces the WHOLE observed sequence. This
//! is the project's definition of "reverse engineered": not recalled from
//! memory, but reproduced bit-for-bit from data.
//!
//! Each test is skipped (with a note) if its fixture is absent, so the suite
//! stays green on a partial checkout.

use std::fs;
use std::path::{Path, PathBuf};

use browser_rnd::engines::{spidermonkey, spidermonkey_legacy, v8, v8_legacy};
use browser_rnd::prng::XorShift128Plus;
use browser_rnd::sample::Sample;

fn load(rel: &str) -> Option<Vec<f64>> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("samples").join(rel);
    let text = fs::read_to_string(&path).ok()?;
    Some(Sample::parse(&text).expect("parse").values)
}

#[test]
fn old_spidermonkey_drand48() {
    let mut tried = 0;
    for rel in ["spidermonkey/firefox1-winxp.txt", "firefox3.txt"] {
        let Some(v) = load(rel) else { continue };
        tried += 1;
        let seed = spidermonkey_legacy::recover(&v).unwrap_or_else(|| panic!("{rel}: drand48"));
        let regen = spidermonkey_legacy::generate(seed, v.len());
        assert!(regen.iter().zip(&v).all(|(a, b)| (a - b).abs() < 1e-12), "{rel}");
    }
    if tried == 0 {
        eprintln!("skip: no drand48 fixtures");
    }
}

#[test]
fn old_v8_mwc1616_all_eras() {
    // Era 2/3 (<<16): opera22, chrome10. Era 1 (<<14): chrome20/30, opera16.
    let mut tried = 0;
    for rel in ["v8/opera22.txt", "chrome10.txt", "chrome20.txt", "chrome30.txt", "v8/opera16.txt"] {
        let Some(v) = load(rel) else { continue };
        tried += 1;
        let mwc = v8_legacy::recover(&v).unwrap_or_else(|| panic!("{rel}: mwc recover failed"));
        assert!(
            mwc.generate(v.len()).iter().zip(&v).all(|(a, b)| (a - b).abs() < 1e-15),
            "{rel}: reproduction mismatch"
        );
    }
    if tried == 0 {
        eprintln!("skip: no MWC fixtures");
    }
}

#[test]
fn modern_v8_xorshift128p() {
    // Any one modern V8 capture proves the path; try a few.
    let mut tried = 0;
    for rel in ["chrome100_win10.txt", "edge100.txt", "chrome77_android4.4.txt", "brave1.0.txt", "opera75.txt"] {
        let Some(v) = load(rel) else { continue };
        tried += 1;
        let (seed, off) = v8::recover(&v)
            .unwrap_or_else(|| panic!("{rel}: recover xorshift128+ failed"));
        let regen = v8::generate(seed, off + v.len());
        assert!(
            regen[off..].iter().zip(&v).all(|(a, b)| (a - b).abs() < 1e-15),
            "{rel}: reproduction mismatch"
        );
    }
    if tried == 0 {
        eprintln!("skip: no modern V8 fixtures");
    }
}

#[test]
fn modern_spidermonkey_xorshift128p() {
    // Needs the z3 SMT solver; skip if unavailable.
    if std::process::Command::new("z3").arg("--version").output().is_err() {
        eprintln!("skip: z3 not installed");
        return;
    }
    let mut tried = 0;
    for rel in ["firefox100.txt", "mypal68.txt"] {
        let Some(v) = load(rel) else { continue };
        tried += 1;
        let state = spidermonkey::recover(&v).unwrap_or_else(|| panic!("{rel}: SM recover failed"));
        assert!(
            spidermonkey::generate(state, v.len()).iter().zip(&v).all(|(a, b)| (a - b).abs() < 1e-15),
            "{rel}: reproduction mismatch"
        );
    }
    if tried == 0 {
        eprintln!("skip: no modern SpiderMonkey fixtures");
    }
}

// Keep an explicit reference so unused-import lints don't fire if a test is cut.
#[allow(dead_code)]
fn _types(_: XorShift128Plus, _: &Path) {}
