# Dart / Flutter `Random` — source-verified analysis

**Canonical reference for the generator behind Flutter apps.** Reconstructed
from the [`dart-lang/sdk`](https://github.com/dart-lang/sdk) tree
(`sdk/lib/_internal/*/math_patch.dart`, `runtime/vm/random.cc`) and validated
against real captures produced by the Dart runtime itself
(`samples/dart/*.txt`, reproduced 4096/4096 by `tests/recover.rs`).

## TL;DR

Flutter has **no `Math.random()` of its own** — every Flutter app draws from
Dart's `dart:math` `Random`. Across the whole history of Dart there has been
exactly **one** non-secure algorithm, and it is **the same on every Flutter
version and every platform**:

> **Multiply-With-Carry**, base *b* = 2³², multiplier **`A = 0xffffda61`**
> (Numerical Recipes 3rd ed., p.348 table B1). State is a single 64-bit word;
> `nextDouble` takes the low **26 + 27 = 53** bits of two successive steps →
> grid **2⁻⁵³**.

So "variations in the RNG" comes down to the **backend**, not the algorithm:

| Backend (Flutter target) | `Random([seed])` uses | Predictable? |
|---|---|---|
| **VM / AOT** — Android, iOS, macOS, Windows, Linux | this MWC | ✅ recover state from ~1 output; seed too if fresh |
| **dart2wasm** | this MWC (bit-identical) | ✅ |
| **dart2js / DDC, `Random(seed)`** (explicit seed) | this MWC, reimplemented in 32-bit JS — **bit-identical output** | ✅ |
| **dart2js / DDC, `Random()`** (no seed) | **the browser's `Math.random()`** (`_JSRandom`) | ✅ — it's V8/SpiderMonkey/JSC, already cracked here |
| **`Random.secure()`** (any target) | OS CSPRNG / `crypto.getRandomValues` | 🔒 unpredictable by design |

The only genuine per-platform *fork* is **seedless web**, which just delegates
to the host browser engine (so a seedless Flutter-web app has the exact
predictability of whatever browser it runs in), and `secure()`.

## The algorithm

From `runtime/vm/random.cc` and `sdk/lib/_internal/vm/lib/math_patch.dart`
(the wasm and seeded-JS paths implement the identical math):

```text
state : u64
next_state():                       // MWC, A = 0xffffda61
    state = A * (state & 0xffffffff) + (state >> 32)

nextInt(2^k):  next_state();  return state & (2^k - 1)      // low k bits of lo word
nextDouble():
    bits26 = nextInt(1 << 26)        // low 26 bits after one step
    bits27 = nextInt(1 << 27)        // low 27 bits after the next step
    return (bits26 * 2^27 + bits27) / 2^53          // grid 2^-53
nextBool():   next_state();  return (state & 1) == 0
```

Two MWC steps per `nextDouble`, so a run of doubles observes the low 26/27 bits
of **every** state in a contiguous chain.

## Seeding

`Random(seed)` runs the user seed through the **Thomas Wang 64-bit mix**
(`_setupSeed` in the VM, `mix64` in wasm — the same bijection, with a
`result == 0 → 0x5a17` guard), then cranks **four** warm-up `next_state` calls:

```text
state = mix64(seed);  next_state() ×4
```

Seedless `Random()` pulls `seed` from the VM's entropy-source callback and, per
`random.cc`, **falls back to `OS::GetCurrentTimeMicros()`** when no entropy
source is wired in:

```cpp
// runtime/vm/random.cc
if (seed == 0) { /* try entropy_source_callback */ }
if (seed == 0) { seed = OS::GetCurrentTimeMicros(); }   // time fallback
```

Flutter's embedder installs a real entropy source, so shipped apps are
CSPRNG-seeded; the µs-time path is the standalone/fallback weakness worth
knowing about.

## Recovery (this crate — `engines::dart`)

State recovery is **closed-form, no solver** — much cheaper than the z3 paths
the browser engines need. The trick is that `A = 2³² − C` with `C = 0x259f`
(9631), so a step is just

```text
lo_{j+1} = (hi_j − C·lo_j)  mod 2³²      ⟹      hi_j = (lo_{j+1} + C·lo_j) mod 2³²
```

i.e. **two consecutive full `lo` words determine the entire 64-bit state.** The
first `nextDouble` hands us `lo₁` (missing its top 6 bits) and `lo₂` (missing its
top 5), so a **2¹¹ brute** over those truncated high bits — verified by full
reproduction — recovers the state conclusively. One `nextDouble` (three states
of context) is enough.

- `dart::recover(&values) -> Option<u64>` — the pre-output 64-bit state.
- `dart::recover_seed(&values) -> Option<u64>` — the **exact user seed**, when
  the capture starts at the generator's first draw: step back through the four
  warm-up cranks and invert `mix64` (each stage is a bijection over 2⁶⁴). Unlike
  Safari's GameRand there is no seed-time invariant, so an *unknown* warm-up
  offset can't be pinned — hence the fresh-start assumption.

`predict::recover` wires Dart into the grid-2⁻⁵³ family (alongside old/modern
SpiderMonkey), so `predict::identify`/`recover` name it and extend the stream
both ways; `forward`/`backward` rewind two states per double.

## History — no variation across Flutter's lifetime

`git log -S 0xffffda61` in the Dart tree shows the MWC arrived around **Dart
0.8** (2013, commit that "Add a per-isolate pseudo random number generator to
the VM internals"), replacing an older generator that was **removed** outright.
Flutter's first release (2017) shipped on Dart 1.x, so **for the entire
existence of Flutter the generator has been this one MWC** — the multiplier,
the 26+27 conversion, the Thomas Wang seed mix, and the four warm-up cranks
have never changed. There is nothing analogous to V8's many eras.

## Caveats

- **Seedless VM** (`Random()` with a real entropy source) is state-recoverable
  from outputs but **not seed-recoverable** (crypto-seeded).
- **Seedless web** is not Dart's MWC at all — it's `Math.random()`; identify the
  browser and use the V8 / SpiderMonkey / JSC path.
- **`Random.secure()`** is a CSPRNG on every platform — out of scope, like
  Presto.
