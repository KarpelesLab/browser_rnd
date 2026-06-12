//! End-to-end recovery tests: take a real capture, recover the generator state,
//! and assert the recovered state reproduces the WHOLE observed sequence. This
//! is the project's definition of "reverse engineered": not recalled from
//! memory, but reproduced bit-for-bit from data.
//!
//! Each test is skipped (with a note) if its fixture is absent, so the suite
//! stays green on a partial checkout.

use std::fs;
use std::path::{Path, PathBuf};

use browser_rnd::engines::{spidermonkey_legacy, v8, v8_legacy};
use browser_rnd::prng::XorShift128Plus;
use browser_rnd::sample::Sample;

fn load(rel: &str) -> Option<Vec<f64>> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("samples").join(rel);
    let text = fs::read_to_string(&path).ok()?;
    Some(Sample::parse(&text).expect("parse").values)
}

#[test]
fn old_spidermonkey_drand48_firefox1() {
    let Some(v) = load("spidermonkey/firefox1-winxp.txt") else {
        eprintln!("skip: fixture missing");
        return;
    };
    let seed = spidermonkey_legacy::recover(&v).expect("recover drand48");
    let regen = spidermonkey_legacy::generate(seed, v.len());
    assert!(regen.iter().zip(&v).all(|(a, b)| (a - b).abs() < 1e-12));
}

#[test]
fn old_v8_mwc1616_opera22() {
    let Some(v) = load("v8/opera22.txt") else {
        eprintln!("skip: fixture missing");
        return;
    };
    let (s0, s1) = v8_legacy::recover(&v).expect("recover mwc1616");
    let regen = v8_legacy::generate(s0, s1, v.len());
    assert!(regen.iter().zip(&v).all(|(a, b)| (a - b).abs() < 1e-15));
}

#[test]
fn modern_v8_xorshift128p() {
    // Any one modern V8 capture proves the path; try a few.
    let mut tried = 0;
    for rel in ["chrome100_win10.txt", "edge100.txt", "chrome77_android4.4.txt"] {
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

// Keep an explicit reference so unused-import lints don't fire if a test is cut.
#[allow(dead_code)]
fn _types(_: XorShift128Plus, _: &Path) {}
