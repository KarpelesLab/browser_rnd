//! Per-browser-engine `Math.random()` models.
//!
//! Each engine pairs a raw PRNG (see `crate::prng`) with the engine-specific way
//! it folds state into a `f64` in `[0, 1)` and the order in which it serves
//! those values. The conversions are the part that actually distinguishes the
//! browsers — the underyling xorshift128+ recurrence is shared by V8,
//! SpiderMonkey and JSC.

pub mod jsc;
pub mod jscript;
pub mod presto;
pub mod spidermonkey;
pub mod spidermonkey_legacy;
pub mod v8;
pub mod v8_legacy;
pub mod v8_libc;

/// Which browser engine a sample is believed to come from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Engine {
    /// Chrome, Edge (Chromium), Opera, Brave, Node.js.
    V8,
    /// Firefox and other Gecko browsers.
    SpiderMonkey,
    /// Safari and iOS WebViews.
    JavaScriptCore,
    /// Legacy MSIE 6/7/8 JScript.
    JScript,
}

impl Engine {
    pub fn name(self) -> &'static str {
        match self {
            Engine::V8 => "v8",
            Engine::SpiderMonkey => "spidermonkey",
            Engine::JavaScriptCore => "javascriptcore",
            Engine::JScript => "jscript",
        }
    }

    /// All engines, in detection-priority order.
    pub fn all() -> &'static [Engine] {
        &[
            Engine::V8,
            Engine::SpiderMonkey,
            Engine::JavaScriptCore,
            Engine::JScript,
        ]
    }
}
