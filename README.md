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
| V8 MWC era 1 | Chrome 20/30, Opera 16 | 2⁻³² | MWC1616, `(s0<<14)+(s1&0x3FFFF)`, 18273/36969 | lane brute | ✅ cracked |
| V8 MWC era 2/3 | Chrome 10, Opera 22 | 2⁻³² | MWC1616, `(s0<<16)\|(s1&0xFFFF)`, 18273/18030/36969 | direct lane carry | ✅ cracked |
| modern V8 | Chrome 77/100, Edge 100, Opera 70/75, Brave | 2⁻⁵² | xorshift128+, `s0>>12`, reversed cache of 64 | GF(2) + offset search | ✅ cracked |
| modern SpiderMonkey | Firefox 100, Mypal 68 | 2⁻⁵³ | xorshift128+ (23,17,26), **low 53 bits** of `s0+s1` | **z3 SMT** | ✅ cracked |
| **IE (JScript + Chakra)** | **IE 6/7/8/9/10/11** | **2⁻⁵⁴** | **drand48 48-bit LCG, 27+27 → 2⁵⁴** | **2²¹ brute** | ✅ cracked |
| JSC (Safari ≤8) | *(no sample yet)* | 2⁻³² | GameRand (Ian Bullard), 2×u32 | closed-form | 🧩 modelled |
| Presto | Opera 10 | 2⁻⁵³ | **SNOW 2.0 CSPRNG** + entropy reseeding | **infeasible by design** | 🔒 unpredictable |
| oldest V8 | Chrome 1 (2008, Win) | 2⁻³⁰ | MSVCRT `rand()` × 2, `hi·2¹⁵+lo` | 2¹⁷ brute | ✅ cracked |

Notable findings:
- **IE 6–11 all share one generator**: drand48 (`0x5DEECE66D`,+11), two steps/call,
  `(hi27·2²⁷ + hi27)/2⁵⁴` — same constants as old SpiderMonkey, just 54-bit. Genuine
  MSIE6/XP. (54-bit means the low bit of any value ≥ 0.5 is rounded by f64, so recovery
  anchors on a value < 0.5.)
- **Modern Firefox uses the LOW 53 bits** of `s0+s1`, not `>>11`. The addition is
  nonlinear over GF(2), so recovery uses the z3 SMT solver.
- **V8 has 4 eras** (+ a pre-history): Chrome 1 (V8 0.3.x) had no custom PRNG —
  `result = (hi + lo/(RAND_MAX+1))/(RAND_MAX+1)` from two host `rand()` calls (on
  Windows, MSVCRT's 15-bit LCG → `hi·2¹⁵+lo`, the FIRST call is the low part). Then
  MWC era1 (`<<14`), era2 (`<<16`), era3 (18030), then xorshift128+ (Chrome 49+,
  52-bit, reversed cache of 64; recovery searches the batch offset, ~4–5).
- **Presto (Opera) is the lone holdout** — it deliberately uses a SNOW 2.0
  CSPRNG continuously reseeded with entropy, so its `Math.random()` is genuinely
  unpredictable (no fixed state to recover). Every other engine here is breakable.
- Captures needing recapture (non-contiguous): `vivaldi1.0`, `opera40`.

## Infra status

- [x] xorshift128+ / MWC / LCG / GameRand generators (forward + recover)
- [x] Structural fingerprinting (grid) + UA prior; ES3 collector (MSIE6 → modern)
- [x] GF(2) linear solver (modern V8); z3 SMT backend (modern SpiderMonkey)
- [x] `src/bin/relab.rs` reverse-engineering harness (z3 experiments)
- [ ] Presto and oldest-V8 (chrome1) recovery; a Safari capture to validate GameRand
