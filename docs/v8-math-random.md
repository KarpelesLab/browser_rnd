# V8 `Math.random()` — complete generator history

Authoritative, source-verified timeline of every generator V8 has ever used for
`Math.random()`, from the first Chrome (2008) to the current tree. Every row was
reconstructed directly from the V8 git history (`~/projects/v8`): commit hash,
release version (`include/v8-version.h` / `src/version.cc`), author date, and the
exact code. Chrome version mappings are approximate (V8 ships ahead of the Chrome
that embeds it).

This corrects two long-standing guesses in the sample-derived notes: the `<<14`
combine began at **3.4.9**, not 3.14, and the linear `s0>>12` form began at
**7.1**, not 7.7/Chrome 77. It also adds two eras the sample sweep never saw: a
4-day 4-lane dev experiment (2011), and the **Nov 2025 re-introduction of the
`s0+s1` add**, which makes the newest V8 nonlinear again.

> **On 30903:** the constant `30903` — Marsaglia's most-copied MWC multiplier —
> **never appears in V8's `Math.random`, in any version.** V8's MWC multipliers
> were `36969`, `18273`, `18030` (and, for 4 days in a 2011 dev branch, `23208`
> and `27753`). The number circulates in V8-4.x discussions only because the
> official [V8 blog post](https://v8.dev/blog/math-random) prints `30903` in its
> illustrative MWC1616 snippet — the shipped code used `36969` on that lane. See
> the `git grep` note at the bottom.

---

## Timeline

| # | Era | V8 version | Date | Commit | Chrome (approx) | Grid | Recoverable? |
|---|-----|-----------|------|--------|-----------------|------|--------------|
| 0 | host libc | ≤ 1.2.7 | 2008 | (initial) | 1–2 | host-dependent (2⁻³⁰ on Win MSVCRT) | ✅ brute |
| 1 | MWC1616 `<<16` (36969-hi) | 1.2.8 | 2009-06-15 | `ce7cdbd7994` | ~2–12 | 2⁻³² | ✅ |
| — | *4-lane experiment (dev only)* | 3.4.9-dev | 2011-06-30 | `03df9dd50bc` | — | 2⁻³² | never shipped |
| 2 | MWC1616 `<<14` (C++) | 3.4.9 | 2011-07-04 | `5f721c3f844` | ~13–32 | 2⁻³² | ✅ |
| 3 | MWC1616 `<<16` (moved to JS) | 3.23.11 | 2013-11-22 | `b6b84c02b24` | ~33–39 | 2⁻³² | ✅ |
| 4 | MWC1616 `<<16` + Marsaglia-3D fix | 3.30.0 | 2014-10-20 | `8325bfbfbfc` | ~40–48 | 2⁻³² | ✅ |
| — | *`%_ConstructDouble` refactor (dev only)* | 4.9-dev | 2015-11-02/20 | `5f4611bc953`, `623cbdc5432` | — | 2⁻³² | never shipped |
| 5 | xorshift128+ **with `s0+s1` add** | 4.9.0 | 2015-11-24 | `2755c5a1b1c` | ~49–70 | 2⁻⁵² | ⚠ nonlinear (z3) |
| 6 | xorshift128+ **single-word `s0>>12`** | 7.1.0 | 2018-09-24 | `ac66c97cfdd` | ~71–134 | 2⁻⁵² | ✅ linear (GF(2)) |
| 7 | xorshift128+ single-word, `>>11 / 2⁵³` | 13.5.0 | 2025-02-20 | `e0609ce60ac` | ~135–143 | 2⁻⁵³ | ✅ linear (GF(2)) |
| 8 | xorshift128+ **`s0+s1` add resurrected** | 14.4.0 | 2025-11-18 | `0596ead5b04` | ~144+ | 2⁻⁵³ | ⚠ nonlinear (z3) |

---

## Era 0 — host libc (Chrome 1, V8 ≤ 1.2.7)

No custom PRNG. `Runtime_Math_random` called the host C library twice and
normalized:

```cpp
double lo = static_cast<double>(random()) * (1.0 / (RAND_MAX + 1.0));
double hi = static_cast<double>(random());
// result = (hi + lo) / (RAND_MAX + 1.0)
```

Quality and grid are entirely the platform's `random()` / `rand()`. On Windows
the host RNG is MSVCRT's 15-bit LCG, giving a 2⁻³⁰ grid (`hi·2¹⁵ + lo`, first
call is the low part). Modelled in `src/engines/v8_libc.rs`.

## Era 1 — MWC1616 introduced (V8 1.2.8, `ce7cdbd7994`)

Commit titled *"Change the implementation of Math.random to use George
Marsaglia's multiply-with-carry instead of mixing the bits obtained from calling
the system random() twice."* Two 16-bit multiply-with-carry lanes:

```cpp
if (hi == 0) hi = random();          // seed drawn from libc random()
if (lo == 0) lo = random();
hi = 36969 * (hi & 0xFFFF) + (hi >> 16);
lo = 18273 * (lo & 0xFFFF) + (lo >> 16);
return (hi << 16) + (lo & 0xFFFF);   // <<16 combine, 36969 is the shifted lane
```

double = r / 2³². This is the `chrome10` sample era. Note the shifted (high)
lane here is the **36969** lane.

## 4-lane experiment (V8 3.4.9-dev, `03df9dd50bc`) — never shipped

For four days in the 3.4.9 development cycle, V8 ran a **four-lane** MWC and
introduced the `--random-seed` flag (deterministic seeding for tests):

```cpp
state[0] = 18273 * (state[0] & 0xFFFF) + (state[0] >> 16);
state[1] = 36969 * (state[1] & 0xFFFF) + (state[1] >> 16);
state[2] = 23208 * (state[2] & 0xFFFF) + (state[2] >> 16);
state[3] = 27753 * (state[3] & 0xFFFF) + (state[3] >> 16);
return ((state[2] ^ state[3]) << 16) + ((state[0] ^ state[1]) & 0xFFFF);
```

`23208` and `27753` are the **only** other MWC multipliers V8 ever used, and they
never reached a stable Chrome. Reverted 4 days later by `5f721c3f844`.

## Era 2 — MWC1616 `<<14` (V8 3.4.9, `5f721c3f844`)

*"Speed up V8 random number generator"* — back to two lanes, new combine:

```cpp
state[0] = 18273 * (state[0] & 0xFFFF) + (state[0] >> 16);
state[1] = 36969 * (state[1] & 0xFFFF) + (state[1] >> 16);
return (state[0] << 14) + (state[1] & 0x3FFFF);   // 18273 now the shifted lane
```

Still C++ (`V8::Random` in `src/v8.cc`). double = r / 2³². The shifted lane
flipped from the 36969 lane (Era 1) to the **18273** lane here. Samples:
`chrome20`, `chrome30`, `opera16`. (Modelled as `Combine::Shift14` in
`src/engines/v8_legacy.rs`.)

## Era 3 — MWC moved into pure JS (V8 3.23.11, `b6b84c02b24`)

*"Reland: Implement Math.random() purely in JavaScript."* (First landed at
3.23.10 `2b1da67263e`, reverted, relanded next day.) In `src/math.js`:

```js
function MathRandom() {
  var r0 = (MathImul(18273, rngstate[0] & 0xFFFF) + (rngstate[0] >>> 16)) | 0;
  rngstate[0] = r0;
  var r1 = (MathImul(36969, rngstate[1] & 0xFFFF) + (rngstate[1] >>> 16)) | 0;
  rngstate[1] = r1;
  var x = ((r0 << 16) + (r1 & 0xFFFF)) | 0;
  return (x < 0 ? (x + 0x100000000) : x) * 2.3283064365386962890625e-10;  // /2^32
}
```

The combine reverted to `<<16` (from Era 2's `<<14`) but kept **18273** as the
`r0` lane. Sample: `opera22`. (`Combine::Shift16` in the model.)

## Era 4 — the "Marsaglia effect in 3D" fix (V8 3.30.0, `8325bfbfbfc`)

Commit *"Avoid the Marsaglia effect in 3D"* changed only the `r0` multiplier:

```diff
-  var r0 = (MathImul(18273, rngstate[0] & 0xFFFF) + (rngstate[0] >>> 16)) | 0;
+  var r0 = (MathImul(18030, rngstate[0] & 0xFFFF) + (rngstate[0] >>> 16)) | 0;
```

`18030` is on Marsaglia's published list of safe multipliers (`a·2¹⁶−1` and
`a·2¹⁵−1` both prime). `r1` stayed `36969`. Combine and 2⁻³² grid unchanged.

## `%_ConstructDouble` refactor (V8 4.9-dev) — never shipped stable

Two dev-cycle commits in Nov 2015 changed only the double conversion while
keeping the 18030/36969 MWC:

- `5f4611bc953` *"Store RNG state on function context"* (2015-11-02): grid stays
  2⁻³², but the double is assembled with `%_ConstructDouble` mantissa-stuffing
  instead of `× 2⁻³²`.
- `623cbdc5432` *"Tweak RNG"* (2015-11-20): folds the two lanes with XOR before
  stuffing:

  ```js
  var r = r0 ^ r1;
  return %_ConstructDouble(0x3FF00000 | (r & 0x000FFFFF), r & 0xFFF00000) - 1;
  ```

Chrome 48 shipped Era 4; Chrome 49 shipped Era 5. This band lived only in
canary/dev. (The repo's `relab` z3 experiments call it "Stage A".)

## Era 5 — xorshift128+ with the `s0+s1` add (V8 4.9.0, `2755c5a1b1c`)

*"Implement xorshift128+ for Math.random."* The MWC is gone. Two 64-bit state
words, seeded via MurmurHash3 of a 64-bit seed:

```cpp
static inline void XorShift128(uint64_t* state0, uint64_t* state1) {
  uint64_t s1 = *state0;
  uint64_t s0 = *state1;
  *state0 = s0;
  s1 ^= s1 << 23;
  s1 ^= s1 >> 17;
  s1 ^= s0;
  s1 ^= s0 >> 26;
  *state1 = s1;
}
static inline double ToDouble(uint64_t state0, uint64_t state1) {
  uint64_t random = ((state0 + state1) & 0x000FFFFFFFFFFFFF) | 0x3FF0000000000000;
  return bit_cast<double>(random) - 1;   // 52-bit mantissa, [0,1)
}
```

**`ToDouble` uses the *sum* `state0 + state1`.** The carry chain makes the output
nonlinear over GF(2), so state recovery needs an SMT solver (z3), not linear
algebra. Shipped Chrome 49. (The repo notes further short-lived shuffle/ordering
variants across V8 5.1–5.3 before the cache stabilized.)

## Era 6 — single-word `s0>>12`, the long-lived linear form (V8 7.1.0, `ac66c97cfdd`)

*"Reland: Do not use FixedDoubleArray to store RNG state."* `XorShift128` was
refactored to return a single word and **the `+` add was dropped**:

```cpp
static inline double ToDouble(uint64_t state0) {
  uint64_t random = (state0 >> 12) | 0x3FF0000000000000;
  return bit_cast<double>(random) - 1;
}
```

With the add gone, each output is a **linear** function of the state bits, so the
generator is recoverable with plain GF(2) linear algebra — no z3. Outputs are
served from a per-context batch cache (`kCacheSize`, 64 entries) that is filled
and **drained in reverse**, so recovery must also search the batch offset. This
is the form the repo cracks and validates against `chrome77` / `chrome100` /
Edge / Brave / modern Opera. It shipped from **Chrome ~71** (V8 7.1, Dec 2018) —
earlier than the "Chrome 77" figure in the sample notes.

## Era 7 — better-distributed `ToDouble` (V8 13.5.0, `e0609ce60ac`)

*"[base] Make random ToDouble better distributed."* Still single-word (no add,
still linear), but the conversion changes from mantissa-stuffing (2⁻³² effective
spacing near the exponent boundary) to a clean 53-bit uniform:

```cpp
static inline double ToDouble(uint64_t random) {
  double random_0_to_2_53 = static_cast<double>(random >> 11);   // high 53 bits
  return random_0_to_2_53 / static_cast<double>(uint64_t{1} << 53);
}
```

Grid becomes 2⁻⁵³. GF(2) recovery still applies (the map is still linear in the
state; only the bit-selection changed from `>>12`-into-mantissa to `>>11`).

## Era 8 — the add is resurrected (V8 14.4.0, `0596ead5b04`)

*"[runtime] Resurrect add operation in xorshift128+ implementation."*
`XorShift128` now returns `s0 + s1` again:

```cpp
static inline uint64_t XorShift128(uint64_t* state0, uint64_t* state1) {
  uint64_t s1 = *state0;
  uint64_t s0 = *state1;
  *state0 = s0;
  s1 ^= s1 << 23;
  s1 ^= s1 >> 17;
  s1 ^= s0;
  s1 ^= s0 >> 26;
  *state1 = s1;
  return s0 + s1;                 // <-- add restored
}
// ToDouble((s0+s1)) = ((s0+s1) >> 11) / 2^53
```

The sum reintroduces carry nonlinearity, so **the newest V8 is z3-territory
again**, like Era 5 and like modern SpiderMonkey. Any Chrome built on V8 ≥ 14.4
(≈ Chrome 144, shipping late 2025 onward) is **not** covered by the repo's GF(2)
recovery and is an open target — see below.

---

## `30903` has never been used by V8 — not once, in any version

The MWC multiplier **`30903`** — Marsaglia's single most-copied constant, the one
most people reach for — **has never appeared in V8's `Math.random()`, in any
version, ever.** The complete set of MWC multipliers V8 has *ever* used is:

- **`36969`, `18273`, `18030`** — the shipped MWC1616 lanes (Eras 1–4 above), and
- **`23208`, `27753`** — only in the 4-day 2011 dev branch that never shipped.

`30903` is in none of them.

**Where the confusion comes from:** V8's own blog post,
[*"There's Math.random(), and then there's Math.random()"*](https://v8.dev/blog/math-random),
prints `30903` in its illustrative MWC1616 code:

```cpp
state1 = 30903 * (state1 & 0xFFFF) + (state1 >> 16);   // <-- V8 BLOG, NOT shipped code
```

but the shipped `src/js/math.js` used `36969` on that lane. The blog's snippet is
illustrative and does not match the source it describes. That is why `30903` gets
attached to "V8 4.x" in write-ups and gists — it propagates from the blog, never
from the engine.

**Verification (the number is provably absent from the RNG):**

```sh
cd ~/projects/v8
git grep -n 30903 -- '*.cc' '*.h' '*.js'        # any era; try HEAD or ac66c97cfdd, 8325bfbfbfc, ...
#   -> only coincidental digit substrings in gay-fixed.cc / dtoa.cc / bigint tests,
#      never in a Math.random / MWC / random-number-generator context.
git grep -n 36969                                # <-- the value V8 actually used
```

**General rule this illustrates:** for an algorithm's constants, trust the
engine's git tree, not the vendor's blog/docs snippets, gists, or third-party
reverse-engineering write-ups. Illustrative code drifts from shipped code.

---

## Recovery status implications for this repo

- **Eras 1–4 (MWC1616, 2⁻³²)** — cracked; `src/engines/v8_legacy.rs`
  (`Combine::Shift14` / `Shift16`, multiplier pairs 18273/18030/36969).
- **Era 0 (libc)** — cracked; `src/engines/v8_libc.rs`.
- **Era 6–7 (single-word xorshift128+, linear)** — cracked; GF(2) solver in
  `src/gf2.rs` + reversed-cache offset search in `src/prng/xorshift128plus.rs`.
- **Era 5 (2015 add) and Era 8 (2025 add)** — nonlinear; need z3, as modern
  SpiderMonkey already does. **Era 8 is a new open target** — no sample captured
  yet, and the GF(2) path does not apply.

### Reproduce these facts

```sh
cd ~/projects/v8
# The two "add" transitions:
git show ac66c97cfdd:src/base/utils/random-number-generator.h   # 7.1: add dropped -> s0>>12
git show 0596ead5b04                                            # 14.4: "Resurrect add operation"
# The MWC lineage:
git show ce7cdbd7994   # 1.2.8: MWC introduced (36969/18273, <<16)
git show 5f721c3f844   # 3.4.9: <<14 speed-up
git show 8325bfbfbfc   # 3.30.0: 18273 -> 18030
# 30903 appears nowhere in the RNG:
git grep -n 30903 ac66c97cfdd | grep -i random   # (no output)
```
