# Captured samples (regression fixtures)

Each file here is a real `Math.random()` capture from `collector/index.html`,
saved verbatim. They are committed on purpose: they are the ground truth the
engine models and recovery code are tested against.

## Naming / layout

Free-form, named after the browser + version (+ OS where it matters), e.g.
`firefox100.txt`, `chrome30.txt`, `ie10.txt`, `mypal68.txt`. Some are grouped
into family subdirectories (`ie/`, `v8/`, `spidermonkey/`, `presto/`); the tests
walk subdirectories, so either location is fine.

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
