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

## Reverse-engineering status

Every "cracked" entry is validated by reproducing a real capture's full 4096-value
sequence (`tests/recover.rs`), not recalled from memory. The `grid` column is the
double-conversion denominator — the first thing the fingerprint pins down.

| Engine / era | Browsers (samples) | Grid | Algorithm | Recovery | Status |
|---|---|---|---|---|---|
| old SpiderMonkey | Firefox 1, 3 | 2⁻⁵³ | drand48 48-bit LCG, `(next26<<27)+next27` | 2²² brute | ✅ cracked |
| old V8 (MWC) | Chrome 10, Opera 22 | 2⁻³² | MWC1616, mults 18273/36969 | direct lane carry | ✅ cracked |
| modern V8 | Chrome 77/100, Edge 100, Opera 70/75, Brave | 2⁻⁵² | xorshift128+, `s0>>12`, reversed cache of 64 | GF(2) + offset search | ✅ cracked |
| modern SpiderMonkey | Firefox 100, Mypal 68 | 2⁻⁵³ | xorshift128+, `(s0+s1)>>11` | nonlinear (carry) → SAT/SMT | ⏳ structure known |
| JScript | IE 6/7/8/9/10/11 | **2⁻⁵⁴** | 27+27 truncated LCG, unknown constants | LLL lattice | ⏳ structure known |
| Presto | Opera 10 | 2⁻⁵³ | not drand48 — own generator | TBD | 🔬 investigating |
| oldest V8 | Chrome 1 (2008) | 2⁻³⁰ | 30-bit MWC variant | TBD | 🔬 investigating |

Notable findings:
- **JScript emits 54-bit values** (`N/2⁵⁴`), one bit wider than the 53-bit norm —
  and genuine MSIE6/XP, not a low-precision `rand()`. drand48 constants are ruled out.
- **V8 version split**: MWC1616 (~32-bit) before Chrome 49, xorshift128+ (52-bit,
  reversed cache) after. The capture rarely starts on a cache boundary, so recovery
  searches the batch offset (consistently 4–5 in practice).
- Captures that don't reproduce and need recapture: `vivaldi1.0`, `opera40`
  (xorshift, no offset fits), `opera16`, `chrome20`, `chrome30` (MWC lane
  inconsistency — likely non-contiguous runs).

## Infra status

- [x] xorshift128+ forward/backward (invertible), MWC, LCG generators
- [x] Structural fingerprinting (mantissa resolution / grid) + UA prior
- [x] ES3 collector (MSIE6 → modern)
- [x] GF(2) linear solver; state recovery for drand48, MWC1616, modern V8
- [x] `src/bin/relab.rs` reverse-engineering harness
- [ ] modern SpiderMonkey (SAT/carry), JScript (LLL), Presto, oldest-V8 recovery
