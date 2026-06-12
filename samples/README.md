# Captured samples (regression fixtures)

Each file here is a real capture from the `collector/index.html` page, saved
verbatim. These are committed on purpose: they are the ground truth we test the
engine models and recovery code against.

## Naming

```
<engine>-<browser><version>-<os>.txt      e.g.  v8-chrome126-win.txt
                                                 spidermonkey-firefox127-linux.txt
                                                 jsc-safari17-macos.txt
                                                 jscript-msie6-winxp.txt
```

## How to add one

1. Open `collector/index.html` in the target browser.
2. Let it generate (bump the sample count if you want a longer run).
3. Copy the whole textarea and save it here under the naming scheme above.
4. Run `cargo test` — the fixture-driven tests will pick it up automatically.

## What the tests check

- The structural fingerprint (`mantissa_resolution`) matches the expected
  engine width (V8 → 52 bits, SpiderMonkey/JSC → 53, JScript → low).
- Where we can recover state, the model reproduces the captured sequence.
