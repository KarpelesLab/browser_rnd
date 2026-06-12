# Captured samples (regression fixtures)

Each file here is a real `Math.random()` capture from `collector/index.html`,
saved verbatim. They are committed on purpose: they are the ground truth the
engine models and recovery code are tested against.

## Layout

One directory per **vendor**, files named `<browser><version>[-os].txt`. This
keeps each version-sweep together (handy for studying when an engine changed its
generator). The tests walk subdirectories recursively. Which generator each
vendor dir maps to (see the root README's status table for details):

| Dir | Engine | Generators across the versions here |
|---|---|---|
| `chrome/`  | V8 | libc `rand()`×2 (1) → MWC (10–46) → xorshift128+ (49+) |
| `opera/`   | Presto then V8 | SNOW 2.0 CSPRNG (≤12) → MWC (15–35) → xorshift128+ (40+) |
| `firefox/` | SpiderMonkey | drand48 (1–3) → xorshift128+ (≥49) |
| `ie/`      | JScript / Chakra | drand48 27+27 (all of 6–11) |
| `safari/`  | JavaScriptCore | GameRand (Safari ≤8) |
| `edge/`, `brave/`, `vivaldi/` | V8 | xorshift128+ |
| `mypal/`   | SpiderMonkey (Goanna) | xorshift128+ |

(The chrome 28–50 and firefox 24–50 captures bracket the MWC→xorshift and
drand48→xorshift transitions; opera 10.50/11.60 are later Presto.)

## How to add one

1. Open `collector/index.html` in the target browser.
2. Let it generate (bump the sample count for a longer run if you want).
3. Copy the whole textarea and save it here.
4. Run `cargo test` — the fixture tests pick it up automatically.

## What the tests check

- `tests/fixtures.rs` — every capture is well-formed: parses, the value count
  matches the `count:` header, and all values are in `[0, 1)`. It also prints
  each capture's fingerprint (grid / resolution + UA) as a diagnostic.
- `tests/recover.rs` — for each supported engine, recover the generator state
  from a real capture and assert it reproduces the **entire** sequence. This is
  the project's definition of "cracked": reproduced from data, not recalled.
