# Hermes `Math.random()` — full history

**Hermes** is the JavaScript engine Meta ships as the default runtime for
**React Native**. It never implemented its own PRNG: `Math.random()` is a thin
wrapper that seeds a **C++ standard-library** engine once from
`std::random_device` and folds every later draw into a `double` with
`std::uniform_real_distribution<>(0.0, 1.0)`. So the whole story is *which stdlib
engine* the `randomEngine_` field names — and across Hermes' entire public
history that changed **exactly once**.

Source of truth: `lib/VM/JSLib/Math.cpp` (`mathRandom`) and the
`randomEngine_` field in `include/hermes/VM/JSLib/RuntimeCommonStorage.h`
(renamed `JSLibStorage.h` in 2024, no behavioural change).

| Era | Dates (commit) | `randomEngine_` | Seed width | Draws / call | Grid |
|---|---|---|---|---|---|
| **1 — MINSTD LCG** | 2019-07-10 → 2023-11-08 (`f22a18f67` → `20c11c441`) | `std::minstd_rand` | 32-bit (`random_device()`×1) | **2** | `1/R²` (non-dyadic) |
| **2 — Mersenne** | 2023-11-08 → present (`20c11c441`) | `std::mt19937_64` | 64-bit (`random_device()`×2) | **1** | `2⁻⁵³`-ish |

Hermes was open-sourced on 2019-07-10 (`f22a18f67`, "Initial commit") already
using `std::minstd_rand`; there is no earlier public revision. The current
`main` (2026-07) still uses `std::mt19937_64`.

The commit date (2023-11-08) is the authoritative boundary. The mapping to a
React Native version is only approximate: the Hermes revision bundled in an RN
release is branched weeks before that release's GA, so a build's era is best
determined from its behaviour (grid / recoverability below), not its RN version
string. As a rough guide, RN ≤ 0.73 → Era 1, RN 0.74+ → Era 2.

## The one change: PR #1175 / issue #1169

Commit `20c11c441` — *"Switch Math.random() to faster 64-bit seeded
implementation"* (Aakash Patel, 2023-11-08), landing
[PR #1175](https://github.com/facebook/hermes/pull/1175) and resolving
[issue #1169](https://github.com/facebook/hermes/issues/1169).

The bug: `std::minstd_rand::result_type` is `unsigned int`, so the engine was
seeded with a **single 32-bit** `std::random_device()` value — only ~4·10⁹
possible streams. By the birthday bound, an app generating ~100 000 UUID-like
values hits a **~71 % chance of a stream collision**. Not a crypto flaw, but
real-world breakage for id generation.

The fix widened the seed to 64 bits (two `random_device()` calls packed
`hi<<32 | lo`) and swapped the engine to `std::mt19937_64`. Notably, although the
PR discussion benchmarks `lcg64`, `xoroshiro128+` and hand-rolled bit-twiddle
double conversions, the **merged diff only changed the engine type and the
seed** — the `std::uniform_real_distribution` conversion was kept:

```cpp
// include/hermes/VM/JSLib/RuntimeCommonStorage.h
-  std::minstd_rand randomEngine_;   // Era 1
+  std::mt19937_64  randomEngine_;   // Era 2
```
```cpp
// lib/VM/JSLib/Math.cpp — Era 2 seeding
auto randValue = randDevice();                                  // 32 bits
uint64_t seed = (uint64_t(randValue) << 32) | randDevice();     // 64 bits
storage->randomEngine_.seed(seed);
```

Everything else that ever touched `mathRandom` was cosmetic and RNG-irrelevant:
the `HERMESVM_SYNTH_REPLAY` seed-injection path (later removed with synth
replay), `encodeDoubleValue` → `encodeUntrustedNumberValue`, and the
`RuntimeCommonStorage` → `JSLibStorage` rename.

## The double conversion is implementation-defined

`uniform_real_distribution<double>(0,1)(g)` calls
`std::generate_canonical<double, 53>(g)`, whose exact arithmetic is **not**
fixed by the standard beyond the algorithm shape. React Native ships **libc++**
on iOS and Android, so libc++ is authoritative
(`libcxx/include/__random/generate_canonical.h`):

```cpp
R  = g.max() - g.min() + 1;
k  = ceil(53 / floor(log2 R));               // draws needed for 53 bits
s  = g() - g.min();                          // draw 0 -> LOW digit
for (i = 1; i < k; ++i) s += (g()-g.min()) * pow(R, i);  // later draws higher
return s / pow(R, k);
```

libstdc++ implements the same standard algorithm and yields the same `k` and
digit order for both engines — this repo's model was cross-checked bit-for-bit
against `g++`/libstdc++ output (`samples/hermes/*` are those reference vectors).

## Era 1 — `std::minstd_rand` (Park–Miller MINSTD)

`std::minstd_rand = linear_congruential_engine<uint_fast32_t, 48271, 0,
2147483647>` (note: `48271`, **not** `minstd_rand0`'s `16807`):

```text
state ∈ [1, 2³¹−2],  state = (state · 48271) mod (2³¹−1)
```

`min()=1`, `max()=2³¹−2`, so `R = max−min+1 = 2³¹−2 = 2147483646` and
`k = ceil(53 / floor(log2 R)) = ceil(53/30) = 2`. **Two** LCG steps per call:

```text
g0 = step(state); g1 = step(g0); state = g1
value = ((g0−1) + (g1−1)·R) / R²             // grid 1/R² ≈ 2⁻⁶², NON-dyadic
```

### Crackability — trivial (O(1))

The high digit `g1` **is the raw LCG state**, and it is the top part of the
value, so:

```text
g1 − 1 = floor(value · R)
```

recovers the **entire 31-bit state from a single output** (f64 rounding can only
nudge the floor by ±1, at the very edges of `g0 ∈ [1,R]`; try 3 candidates and
confirm by reproduction). The modulus is only 2³¹, so even brute force is
instant. Combined with the **non-dyadic `1/R²` grid** — unique among every
engine this crate models — Era 1 is both the easiest to *fingerprint* and the
easiest to *predict*. `engines::hermes::recover` returns the pre-first-output
state; step forward with `generate`, backward with `prev` (LCG inverse
`A⁻¹ mod M` via Fermat). The predictor extends the stream both ways and, for a
capture starting at a realm's first `Math.random()`, `recover_seed` returns the
32-bit `random_device()` value itself (modulo `M`).

## Era 2 — `std::mt19937_64`

`R = 2⁶⁴` ⇒ `k = ceil(53/64) = 1`: **one** 64-bit Mersenne-Twister output per
call, `value = next_u64() / 2⁶⁴` (the top 53 bits).

- **Grid**: because it's `mt/2⁶⁴` rounded to f64 rather than an integer×`2⁻⁵³`,
  small values keep sub-`2⁻⁵³` resolution — so it is *not* on the exact `2⁻⁵³`
  dyadic grid that modern SpiderMonkey and Dart sit on. That is the practical
  fingerprint separating Era 2 from those engines.
- **Crackability**: hard, not O(1). MT19937-64 has 19937 bits of state and each
  output exposes only its high 53 bits (low 11 lost to the `/2⁶⁴` truncation).
  Recovery needs ~625 consecutive outputs and a GF(2) solve over the
  tempering + truncation. `engines::hermes::generate_mt` reproduces the stream
  (validated against libstdc++), but state recovery is **not implemented** here
  — Era 2 is documented and reproducible, not yet predictable, so the CLI
  reports "could not identify" on an Era-2-only capture rather than guessing.

## Not covered by these two eras

- **`Math.random` mocking** (`HERMESVM_SYNTH_REPLAY`, historical): fed a fixed
  seed for deterministic replay; removed, never a production path.
- **Non-Hermes React Native (JSC)**: RN apps with Hermes *disabled* run on
  JavaScriptCore — see [`../src/engines/jsc.rs`](../src/engines/jsc.rs).
- **`Random.secure()` analogues**: Hermes has none; `Math.random` is the only
  JS-visible RNG and is never a CSPRNG in either era.

## Files

- Model + recovery: [`../src/engines/hermes.rs`](../src/engines/hermes.rs)
- Predictor wiring: [`../src/predict.rs`](../src/predict.rs) (`Gen::HermesLcg`)
- Reference vectors: `../samples/hermes/` (real libstdc++/libc++ stdlib output)
