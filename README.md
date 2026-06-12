# browser_rnd

Analyze, reproduce, reverse engineer and brute force the `Math.random()` PRNGs
of various browsers — in Rust. Coverage target: **MSIE 6 (JScript) through
current Chrome / Firefox / Safari**.

## Why each browser is different

`Math.random()` is not standardized beyond "a double in `[0, 1)`", and every
engine — and every *era* of each engine — makes its own choices. For the current
engines:

| Engine | Browsers | Core PRNG | Double conversion | Serving order |
|---|---|---|---|---|
| **V8** | Chrome, Edge, Opera, Brave, Node | xorshift128+ | `bitcast((s0>>12)\|exp) - 1` (52-bit) | **reversed** cache of 64 |
| **SpiderMonkey** | Firefox | xorshift128+ | `((s0+s1) & (2⁵³-1)) * 2⁻⁵³` (**low** 53) | in order |
| **JavaScriptCore** | Safari ≤8, iOS | GameRand (2×u32) | `m_high / 2³²` (32-bit) | in order |

The conversion is the part that distinguishes them: V8 reads `s0` directly (so
its recovery is GF(2)-linear), while SpiderMonkey/JSC sum both lanes (`s0+s1`,
nonlinear over GF(2) → solved with z3). Older engines used entirely different
generators — see the full table below, which is the authoritative status.

## Workflow

1. **Capture.** Open `collector/index.html` in the target browser. It runs in
   ES3 so it works all the way back to MSIE 6. Copy the textarea.
2. **Save.** Drop the capture into `samples/` (organised by family, e.g.
   `samples/ie/`, `samples/v8/`). These are committed as regression fixtures.
3. **Analyze.** `cargo run -- analyze samples/ie/ie6-winxp.txt`
   — fingerprints the engine from UA + value structure (grid/resolution).
4. **Recover.** Confirmed algorithms live in `src/engines/` with a `recover`
   that reproduces the full capture; `cargo test` exercises them over `samples/`.
5. **Reverse new ones.** `src/bin/relab.rs` is the scratch harness for probing an
   unknown capture (`cargo run --bin relab -- <experiment> <sample>`); confirmed
   findings get promoted into an engine module with a recovery test.

## Layout

```
collector/index.html   ES3 capture page (do not modernize — must run on IE6)
src/prng/              raw generators: xorshift128+ (invertible), MWC, LCG
src/engines/           per-browser models (generate + recover):
                         v8, v8_legacy (MWC eras), v8_libc (Chrome 1),
                         spidermonkey, spidermonkey_legacy (drand48),
                         jscript (IE6-11), jsc (Safari GameRand), presto
src/gf2.rs             GF(2) linear solver (modern V8 recovery)
src/sample.rs          parse captured textarea dumps
src/analyze.rs         engine fingerprinting (grid / mantissa resolution + UA)
src/bin/relab.rs       reverse-engineering scratch harness (incl. z3 experiments)
samples/               committed real captures used as test fixtures
tests/fixtures.rs      well-formedness checks over every capture
tests/recover.rs       end-to-end: recover state → reproduce the full sequence
```

z3 (SMT solver) is an optional external tool; only the SpiderMonkey recovery and
some `relab` experiments use it, and tests that need it skip cleanly if absent.

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
| JSC (Safari ≤8) | Safari 5.1.7 | 2⁻³² | GameRand (Ian Bullard), 2×u32 | closed-form | ✅ cracked |
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

### Pinned version transitions (from the sample sweep)

The `relab id` classifier over the full sweep dates every switch:

```
Chrome:  v1  libc rand()x2 (2⁻³⁰)
         v10 MWC <<16, hi=36969          (the original V8 1.2 form)
         v20–32 MWC <<14, hi=18273       (era 1)
         v33–38 MWC <<16, hi=18273       (era 2)
         v40–46 MWC <<16, hi=18030       (era 3, the "Marsaglia-3D" fix)
         v48     MWC 18030 + %_ConstructDouble conv  (4.9 "Stage A")  ✅ z3
         v49–50  xorshift128+ in-order, (s0+s1)&mask52 (4.9 "Stage B") ✅ z3
         v52–53  xorshift128+, V8 5.1–5.3 variant     (🔬 open)
         v77+    xorshift128+ reversed cache, s0>>12   (stable)        ✅ GF(2)
Firefox: v1–26 drand48 → v50+ xorshift128+ (switch at FF48, late 2015)
Opera:   v10–11.60 Presto/SNOW2 → v16–22 MWC → v40+ xorshift128+
```

The V8 **4.9 transitional band is fully cracked**, and it turned out to be *two*
changes back-to-back (per the source): **Stage A** (Chrome 48) was a conversion-only
refactor — same MWC, but the double is mantissa-stuffed via `%_ConstructDouble`
(`(r0&0xFFFFF)<<32 | (r1&0xFFF00000)`, grid 2⁻³²). **Stage B** (Chrome 49–~55) is the
real rewrite: xorshift128+ served **in order** with `ToDouble = (s0+s1)&mantissaMask`
(low 52 bits of the *sum* — nonlinear, so z3). Only **later** (by Chrome 77) did V8
switch the conversion to `s0>>12` *and* add the reversed 64-cache — the stable form
that recovers with plain GF(2).

There's a **third, still-open xorshift variant** in between: V8 5.1–5.3 (Chrome 52–53,
Opera 38–40, ~mid-2016). A *clean Chrome* capture (chrome53) and a recaptured opera40
both fail identically — so it's a genuine algorithm variant, not a capture artifact.
It fits **none** of: in-order × {s0,s1,sum} × {top-52, low-52} (free shift), nor
reversed-cache + `s0>>12` (scanned shifts), nor reversed-cache + `(s0+s1)&mask52`.
It's almost certainly the reversed cache paired with a conversion/shift combo the
black-box search can't reach; closing it needs the V8 5.1–5.3 source.

## Infra status

- [x] xorshift128+ / MWC / LCG / GameRand generators (forward + recover)
- [x] Structural fingerprinting (grid) + UA prior; ES3 collector (MSIE6 → modern)
- [x] GF(2) linear solver (modern V8); z3 SMT backend (modern SpiderMonkey)
- [x] `src/bin/relab.rs` reverse-engineering harness (z3 experiments)
- [x] **Recovery for every engine except Presto** (which is a CSPRNG — not breakable)
- [ ] A Safari capture to validate the GameRand model + pin the modern-JSC extraction
- [ ] Optional: transition-boundary captures (Chrome 49/39, Firefox 49, legacy Edge)
