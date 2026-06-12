//! End-to-end recovery tests: take a real capture, recover the generator state,
//! and assert the recovered state reproduces the WHOLE observed sequence. This
//! is the project's definition of "reverse engineered": not recalled from
//! memory, but reproduced bit-for-bit from data.
//!
//! Each test is skipped (with a note) if its fixture is absent, so the suite
//! stays green on a partial checkout.

use std::fs;
use std::path::{Path, PathBuf};

use browser_rnd::engines::{jsc, jscript, spidermonkey, spidermonkey_legacy, v8, v8_legacy, v8_libc};
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
    for rel in ["firefox/firefox1-winxp.txt", "firefox/firefox3.txt"] {
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
fn safari_jsc_gamerand() {
    let Some(v) = load("safari/safari5.1.7-winxp.txt") else {
        eprintln!("skip: fixture missing");
        return;
    };
    let state = jsc::recover(&v).expect("GameRand recover failed");
    assert!(jsc::generate(state, v.len()).iter().zip(&v).all(|(a, b)| (a - b).abs() < 1e-15));
}

#[test]
fn oldest_v8_chrome1_libc_rand() {
    let Some(v) = load("chrome/chrome1-2008.txt") else {
        eprintln!("skip: fixture missing");
        return;
    };
    let state = v8_libc::recover(&v).expect("chrome1 recover failed");
    assert!(v8_libc::generate(state, v.len()).iter().zip(&v).all(|(a, b)| (a - b).abs() < 1e-12));
}

#[test]
fn old_v8_mwc1616_all_eras() {
    // Era 2/3 (<<16): opera22, chrome10. Era 1 (<<14): chrome20/30, opera16.
    let mut tried = 0;
    for rel in ["opera/opera22.txt", "chrome/chrome10.txt", "chrome/chrome20.txt", "chrome/chrome30.txt", "opera/opera16.txt"] {
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
    for rel in ["chrome/chrome100-win10.txt", "edge/edge100.txt", "chrome/chrome77-android4.4.txt", "brave/brave1.0.txt", "opera/opera75.txt"] {
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
fn early_v8_mwc_stage_a() {
    // Chrome 48: MWC 18030/36969 with the %_ConstructDouble conversion. Needs z3.
    if std::process::Command::new("z3").arg("--version").output().is_err() {
        eprintln!("skip: z3 not installed");
        return;
    }
    let Some(v) = load("chrome/chrome48.txt") else {
        eprintln!("skip: fixture missing");
        return;
    };
    let (s0, s1) = v8_legacy::recover_stage_a(&v).expect("stage-A recover failed");
    assert!(v8_legacy::generate_stage_a(s0, s1, v.len()).iter().zip(&v).all(|(a, b)| (a - b).abs() < 1e-15));
}

#[test]
fn early_v8_xorshift128p_stage_b() {
    // Chrome ~49-55: xorshift128+ in-order, low 52 bits of (s0+s1). Needs z3.
    if std::process::Command::new("z3").arg("--version").output().is_err() {
        eprintln!("skip: z3 not installed");
        return;
    }
    let mut tried = 0;
    for rel in ["chrome/chrome49.txt", "chrome/chrome50.txt", "vivaldi/vivaldi1.0.txt"] {
        let Some(v) = load(rel) else { continue };
        tried += 1;
        let state = v8::recover_early(&v).unwrap_or_else(|| panic!("{rel}: stage-B recover failed"));
        assert!(
            v8::generate_early(state, v.len()).iter().zip(&v).all(|(a, b)| (a - b).abs() < 1e-15),
            "{rel}: reproduction mismatch"
        );
    }
    if tried == 0 {
        eprintln!("skip: no early-V8 fixtures");
    }
}

#[test]
fn internet_explorer_drand48_27_27() {
    // JScript (IE6/7/8) and early Chakra (IE9/10/11) share one generator.
    let mut tried = 0;
    for rel in [
        "ie/ie6-winxp.txt", "ie/ie7-winxp.txt", "ie/ie8-winxp.txt",
        "ie/ie9-vista.txt", "ie/ie10.txt", "ie/ie11.txt",
    ] {
        let Some(v) = load(rel) else { continue };
        tried += 1;
        let seed = jscript::recover(&v).unwrap_or_else(|| panic!("{rel}: IE recover failed"));
        assert!(
            jscript::generate(seed, v.len()).iter().zip(&v).all(|(a, b)| (a - b).abs() < 1e-12),
            "{rel}: reproduction mismatch"
        );
    }
    if tried == 0 {
        eprintln!("skip: no IE fixtures");
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
    for rel in ["firefox/firefox100.txt", "mypal/mypal68.txt"] {
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
