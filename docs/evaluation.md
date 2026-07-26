# Evaluation

This page reports **measured** results from raon's self-contained evaluation. These are real
runs of the full pipeline (compile → coverage-guided fuzz → parse → triage → dedup), not
hand-picked or estimated numbers.

> **Scope / honesty note.** This is a self-contained micro-benchmark over small, bundled
> targets with deliberately planted bugs. It demonstrates that raon actually finds and correctly
> classifies these bug classes end to end. It is **not** a known-CVE reproduction study —
> that requires the Magma benchmark, which needs an x86_64 Linux host with Docker and is the
> next milestone (the adapter in `raon.bench` is ready; results will be added here when run).

## Self-contained evaluation

Each target is a libFuzzer harness with one planted bug (plus one safe target as a
false-positive check). raon compiles it under AddressSanitizer, fuzzes it, and triages the
crash into a normalized finding.

| Target | Bug class | Detected | Sanitizer error | Time to crash (s) |
|---|---|---|---|---|
| `heap_overflow.c` | memory | ✅ | heap-buffer-overflow | 0.04 |
| `use_after_free.c` | memory | ✅ | heap-use-after-free | 0.03 |
| `stack_overflow.c` | memory | ✅ | stack-buffer-overflow | 0.03 |
| `global_overflow.c` | memory | ✅ | global-buffer-overflow | 0.03 |
| `safe.c` | — (safe) | no crash ✓ | — | — |

**Detection rate:** 4/4 (100%) buggy targets · **unique bugs:** 4 · **false positives:** 0 ·
**median time-to-crash:** 0.03s

### Environment

- raon Docker image (`docker/Dockerfile`): Debian bookworm, clang/LLVM with the libFuzzer
  runtime and compiler-rt.
- Budget: up to 20 s of fuzzing per target (all crashes were found in well under 1 s).
- Date: 2026-07 · raon 0.2.0.

### Reproduce

```bash
docker build -f docker/Dockerfile -t raon:ci .
docker run --rm raon:ci python -m raon.bench.eval --time 20
```

Or, on a Linux host with clang (libFuzzer runtime available):

```bash
python -m raon.bench.eval --time 20 --json eval.json --md eval.md
```

The targets live in `src/raon/bench/eval_targets/`; the runner is `raon.bench.eval`.

## Single vs. multi-agent triage (orchestration value)

A recurring question for multi-agent designs is whether the orchestration earns its keep. This
experiment isolates one axis of it — **crash deduplication quality** — with real data and no
live LLM required.

The same bug produces different raw sanitizer output across runs (ASLR varies addresses) and
rebuilds (line numbers, build paths). A naive single-pass approach that dedups on the raw stack
text therefore reports the same bug many times. raon normalizes the stack (strips addresses,
line numbers, build paths) and merges via the Supervisor.

Each buggy target is run 3 times; ground truth is 1 bug per target (4 bugs, 12 crash reports):

| Approach | Unique bugs reported | Dedup F1 (vs gold) |
|---|---|---|
| Baseline (single, raw-stack dedup) | 12 | 0.00 |
| raon (normalized dedup + Supervisor) | 4 | 1.00 |

The naive baseline over-reports 4 bugs as 12 (3× inflation) and scores 0.00 pairwise F1; raon
recovers the exact ground-truth clustering (F1 1.00). This is the deduplication slice of the
broader single-vs-multi study (a full study also needs a live LLM and a known-bug set — Magma).

Reproduce (needs clang with ASan; runs on macOS or Linux):

```bash
python -m raon.bench.experiment
```

## Magma (real ground truth)

raon is an analysis layer, not a fuzzer, so it runs on top of Magma's stock fuzzers rather than
shipping its own. It reads Magma's canary `monitor` output as ground truth via `raon.bench`
(per-bug **reached** = the buggy code executed, **triggered** = the vulnerability condition was
actually satisfied). Magma requires an **x86_64 Linux host with Docker** (no arm64 support), so
these numbers come from the **Magma GitHub Actions workflow** (`.github/workflows/magma.yml`) on
an x86_64 runner.

Measured — libpng (`libpng_read_fuzzer`), stock libFuzzer, **10-minute** campaign:

| Metric | Value |
|---|---|
| Canary bugs reached | 6 — PNG001, PNG003, PNG004, PNG005, PNG006, PNG007 |
| Canary bugs triggered | 2 — PNG003 (15s), PNG006 (20s) |
| Time to first trigger | 15s |

This is a short smoke campaign (10 minutes); a longer run triggers more bugs. It confirms the
full pipeline end to end on real, front-ported CVEs: Magma's canaries → `raon.bench` ground-truth
metrics. Reproduce by dispatching the Magma workflow from the Actions tab (adjust `timeout` for a
longer campaign).
