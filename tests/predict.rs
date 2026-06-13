//! Held-out prediction on REAL captures: hand the predictor a middle slice of an
//! actual browser capture and check it reconstructs the surrounding values it
//! never saw — forward and backward.

use std::fs;
use std::path::PathBuf;

use browser_rnd::predict;
use browser_rnd::sample::Sample;

fn load(rel: &str) -> Option<Vec<f64>> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("samples").join(rel);
    Some(Sample::parse(&fs::read_to_string(&path).ok()?).expect("parse").values)
}

fn held_out(rel: &str, engine: &str, needs_z3: bool) {
    if needs_z3 && std::process::Command::new("z3").arg("--version").output().is_err() {
        eprintln!("skip {rel}: z3 absent");
        return;
    }
    let Some(v) = load(rel) else { eprintln!("skip {rel}: missing"); return; };
    let (a, b) = (80usize, 200usize);
    let p = predict::recover(&v[a..b]).unwrap_or_else(|| panic!("{rel}: recover"));
    assert_eq!(p.id().engine, engine, "{rel}: engine");
    // forward: the values after the slice it never saw
    let fwd = p.forward(40);
    assert!(fwd.iter().zip(&v[b..b + 40]).all(|(x, y)| (x - y).abs() < 1e-12), "{rel}: forward mismatch");
    // backward: the values before the slice, chronological (last = just before v[a])
    let bwd = p.backward(a);
    assert!(bwd.iter().zip(&v[..a]).all(|(x, y)| (x - y).abs() < 1e-12), "{rel}: backward mismatch");
}

#[test] fn ie6_drand48() { held_out("ie/ie6-winxp.txt", "JScript/Chakra", false); }
#[test] fn firefox1_drand48() { held_out("firefox/firefox1-winxp.txt", "SpiderMonkey", false); }
#[test] fn opera22_mwc() { held_out("opera/opera22.txt", "V8", false); }
#[test] fn chrome10_mwc() { held_out("chrome/chrome10.txt", "V8", false); }
#[test] fn chrome1_libc() { held_out("chrome/chrome1-2008.txt", "V8", false); }
#[test] fn safari_gamerand() { held_out("safari/safari5.1.7-winxp.txt", "JavaScriptCore", false); }
#[test] fn chrome100_modern_v8() { held_out("chrome/chrome100-win10.txt", "V8", false); }
#[test] fn firefox100_modern_sm() { held_out("firefox/firefox100.txt", "SpiderMonkey", true); }
#[test] fn chrome53_v8_5x() { held_out("chrome/chrome53.txt", "V8", true); }
