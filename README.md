# browser_rnd

Analyze, reproduce, reverse engineer and brute force the `Math.random()` PRNGs
of various browsers — in Rust. Coverage target: **MSIE 6 (JScript) through
current Chrome / Firefox / Safari**.

## Why each browser is different

`Math.random()` is not standardized beyond "a double in `[0, 1)`". Every engine
makes its own choices:

| Engine | Browsers | Core PRNG | Double conversion | Serving order |
|---|---|---|---|---|
| **V8** | Chrome, Edge, Opera, Brave, Node | xorshift128+ | `bitcast((s0>>12)\|exp) - 1` (52-bit) | **reversed** cache of 64 |
| **SpiderMonkey** | Firefox | xorshift128+ | `((s0+s1)>>11) * 2⁻⁵³` (high 53) | in order |
| **JavaScriptCore** | Safari, iOS | xorshift128+ | `((s0+s1) & (2⁵³-1)) * 2⁻⁵³` (low 53) | in order |
| **JScript** | MSIE 6/7/8 | LCG family *(TBD)* | low-precision scale *(TBD)* | in order |

The shared xorshift128+ recurrence is invertible, so once state is recovered we
can predict forwards and backwards. The conversion + serving-order quirks are
how we tell the engines apart and how we map observed doubles back to state bits.

## Workflow

1. **Capture.** Open `collector/index.html` in the target browser. It runs in
   ES3 so it works all the way back to MSIE 6. Copy the textarea.
2. **Save.** Drop the capture into `samples/<engine>-<browser><ver>-<os>.txt`.
   These are committed as regression fixtures (see `samples/README.md`).
3. **Analyze.** `cargo run -- analyze samples/v8-chrome126-win.txt`
   — fingerprints the engine from UA + value structure.
4. **Test.** `cargo test` runs unit tests plus fixture checks over `samples/`.

## Layout

```
collector/index.html   ES3 capture page (do not modernize — must run on IE6)
src/prng/              raw generators: xorshift128+, LCG (no browser quirks)
src/engines/           per-browser conversions + serving order
src/sample.rs          parse captured textarea dumps
src/analyze.rs         engine fingerprinting
samples/               committed real captures used as test fixtures
tests/fixtures.rs      checks each capture against its declared engine
```

## Status

- [x] xorshift128+ forward/backward, verified invertible
- [x] V8 / SpiderMonkey / JSC double conversions + generators
- [x] Structural fingerprinting (mantissa resolution) + UA prior
- [x] ES3 collector
- [ ] JScript (IE6) exact LCG constants — candidates in `engines::jscript`,
      to be pinned from real captures
- [ ] State recovery / brute force from observed outputs (V8 reversed-cache
      reconstruction, then SpiderMonkey/JSC)
