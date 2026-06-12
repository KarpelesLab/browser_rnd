//! Fixture-driven tests over committed captures in `samples/`.
//!
//! These assert *integrity*, not engine identity. Identifying (and reproducing)
//! the generator behind each capture is the project's research goal, not a
//! stable invariant — and real captures defy assumptions (e.g. genuine MSIE 6.0
//! on Windows XP emits full 53-bit doubles, not the low-precision output one
//! might expect). So here we only check that each capture is well-formed, then
//! print its fingerprint as a diagnostic for `cargo test -- --nocapture`.
//!
//! Filenames are free-form (`ff1.txt`, `ie6.txt`, …). New captures are picked up
//! automatically. With no fixtures present this is a no-op so a fresh clone
//! stays green.

use std::fs;
use std::path::{Path, PathBuf};

use browser_rnd::analyze::fingerprint;
use browser_rnd::sample::Sample;

fn collect_txt(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(dir) else { return };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_txt(&path, out);
        } else if path.extension().and_then(|s| s.to_str()) == Some("txt") {
            out.push(path);
        }
    }
}

#[test]
fn fixtures_are_well_formed() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("samples");
    let mut checked = 0;

    let mut paths = Vec::new();
    collect_txt(&dir, &mut paths);
    paths.sort();

    for path in paths {
        let fname = path.strip_prefix(&dir).unwrap_or(&path).to_string_lossy().to_string();

        let text = fs::read_to_string(&path).expect("read fixture");
        let sample = Sample::parse(&text).unwrap_or_else(|e| panic!("{fname}: parse error: {e}"));

        // Integrity: the declared `count:` header must match the values present.
        // (Sample::parse already enforces every value is finite and in [0, 1).)
        if let Some(declared) = sample.meta.get("count").and_then(|c| c.parse::<usize>().ok()) {
            assert_eq!(
                declared,
                sample.values.len(),
                "{fname}: header count {} != {} values present",
                declared,
                sample.values.len()
            );
        }
        assert!(!sample.values.is_empty(), "{fname}: no values");

        // Diagnostic only — never fails the build.
        let fp = fingerprint(&sample);
        eprintln!(
            "fixture {fname}: {} values, {} bits, ua={}, structural={:?}",
            sample.values.len(),
            fp.resolution_bits,
            fp.ua_guess.map(|e| e.name()).unwrap_or("?"),
            fp.structural_candidates,
        );
        checked += 1;
    }

    if checked == 0 {
        eprintln!("note: no fixtures in samples/ yet — add captures to enable fixture tests");
    }
}
