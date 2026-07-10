//! Parsing for captured samples.
//!
//! The collector (`collector/index.html`) emits a deliberately dumb, ES3-
//! friendly, line-based format so it round-trips cleanly through a textarea in
//! anything from MSIE 6 to current Chrome:
//!
//! ```text
//! # browser_rnd sample v1
//! ua: Mozilla/5.0 ...
//! platform: Win32
//! count: 2048
//! ---
//! 0.123456789012345
//! 0.987654321098765
//! ...
//! ```
//!
//! Everything before the `---` separator is `key: value` metadata (plus `#`
//! comments); everything after is one `f64` per line.

use std::collections::BTreeMap;

use crate::engines::Engine;

/// A parsed capture: metadata headers plus the observed `Math.random()` values
/// in the order the browser served them.
#[derive(Clone, Debug, Default)]
pub struct Sample {
    pub meta: BTreeMap<String, String>,
    pub values: Vec<f64>,
}

impl Sample {
    /// Parse the textarea contents.
    pub fn parse(text: &str) -> Result<Sample, String> {
        let mut meta = BTreeMap::new();
        let mut values = Vec::new();
        let mut in_values = false;

        for (lineno, raw) in text.lines().enumerate() {
            let line = raw.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if line == "---" {
                in_values = true;
                continue;
            }
            if !in_values {
                if let Some((k, v)) = line.split_once(':') {
                    meta.insert(k.trim().to_string(), v.trim().to_string());
                    continue;
                }
                // A bare numeric line before any `---` also starts the value
                // block — tolerate collectors that omit the separator.
                if line.parse::<f64>().is_ok() {
                    in_values = true;
                } else {
                    return Err(format!("line {}: expected `key: value`, got {:?}", lineno + 1, line));
                }
            }
            if in_values {
                let v: f64 = line
                    .parse()
                    .map_err(|_| format!("line {}: not a number: {:?}", lineno + 1, line))?;
                if !(0.0..1.0).contains(&v) {
                    return Err(format!("line {}: value {} outside [0,1)", lineno + 1, v));
                }
                values.push(v);
            }
        }

        if values.is_empty() {
            return Err("no values found in sample".to_string());
        }
        Ok(Sample { meta, values })
    }

    pub fn user_agent(&self) -> Option<&str> {
        self.meta.get("ua").map(String::as_str)
    }

    /// Best-effort engine guess from the userAgent string alone. This is only a
    /// prior — the actual confirmation comes from reproducing the values.
    pub fn guess_engine(&self) -> Option<Engine> {
        let ua = self.user_agent()?.to_ascii_lowercase();
        // Order matters: Edge/Opera/Brave all carry "chrome"; old IE carries
        // "msie" or "trident".
        if ua.starts_with("dart") || ua.contains("flutter") {
            // Native Flutter/Dart capture (not a browser). Seedless Flutter *web*
            // uses the browser's Math.random and looks like a normal browser UA.
            Some(Engine::Dart)
        } else if ua.contains("msie") || ua.contains("trident") {
            Some(Engine::JScript)
        } else if ua.contains("firefox") || ua.contains("gecko/") {
            Some(Engine::SpiderMonkey)
        } else if ua.contains("chrome") || ua.contains("chromium") || ua.contains("edg/") {
            Some(Engine::V8)
        } else if ua.contains("safari") || ua.contains("applewebkit") {
            // AppleWebKit without Chrome ⇒ JSC (Safari). Chrome was caught above.
            Some(Engine::JavaScriptCore)
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_metadata_and_values() {
        let s = Sample::parse(
            "# header\nua: Mozilla/5.0 Firefox/120\ncount: 3\n---\n0.1\n0.2\n0.3\n",
        )
        .unwrap();
        assert_eq!(s.values, vec![0.1, 0.2, 0.3]);
        assert_eq!(s.user_agent(), Some("Mozilla/5.0 Firefox/120"));
        assert_eq!(s.guess_engine(), Some(Engine::SpiderMonkey));
    }

    #[test]
    fn tolerates_missing_separator() {
        let s = Sample::parse("ua: x\n0.5\n0.6\n").unwrap();
        assert_eq!(s.values, vec![0.5, 0.6]);
    }

    #[test]
    fn rejects_out_of_range() {
        assert!(Sample::parse("---\n1.5\n").is_err());
    }
}
