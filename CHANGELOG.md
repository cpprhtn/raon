# Changelog

This project follows [Semantic Versioning](https://semver.org).

## [0.3.0] — 2026-07-26

Research: quantifies the orchestration value and sets up real Magma measurement.

### Added
- **Single vs. multi-agent triage experiment** (`raon.bench.experiment`,
  `python -m raon.bench.experiment`): measures crash-deduplication quality of a naive
  single-pass baseline vs raon's normalized dedup + Supervisor. Measured result: the baseline
  over-reports 4 bugs as 12 (raw stacks vary with ASLR; F1 0.00), while raon recovers the exact
  4 clusters (F1 1.00). See `docs/evaluation.md`.
- **Magma GitHub Actions workflow** (`.github/workflows/magma.yml`, `workflow_dispatch`): builds
  a Magma target and runs a bounded campaign on an x86_64 runner, then parses the canary ground
  truth with `raon.bench`. The honest path to real Magma numbers without an x86_64 host locally.
- Generic FILE_ARG driver so libFuzzer targets run under ASan-only (no libFuzzer runtime), which
  lets the orchestration experiment run on macOS as well as Linux.

## [0.2.0] — 2026-07-26

Adds real evidence, friendlier APIs, and stronger verification, addressing external README
review feedback.

### Added
- **Self-contained evaluation** (`raon.bench.eval`, `python -m raon.bench.eval`): a suite of
  planted-bug libFuzzer targets plus a safe target, run end to end. Measured results
  (Docker/Linux): 4/4 buggy targets detected, 0 false positives. See `docs/evaluation.md`.
- **Harness reach-verification** (`raon.fuzzing.coverage`): source-based coverage confirms a
  synthesized harness actually executes the target function; `HarnessSynthesizer(verify_reach=True)`
  feeds a reach-repair prompt when it doesn't. Graceful degradation without llvm coverage tools.
- **JSON domain pack** (`raon.knowledge.json_pack`) alongside PNG.
- **Magma integration** (`fuzzers/raon/`): the five-script contract to plug raon into Magma on
  an x86_64 Linux host (campaign run deferred to such a host).
- CI: a Docker container-integration job runs the full suite (clang + libFuzzer + coverage).

### Changed
- **Agents renamed to role-based names**: `AgentA → StaticAnalysisAgent`,
  `AgentB → CrashTriageAgent`, `AgentC → InterfaceInferenceAgent`; `SourceComponent` values are
  role-based too. Old names remain as `DeprecationWarning` aliases for one release.
- READMEs (en/ko/zh): narrowed the tagline (binary analysis marked experimental), added a
  platform-support matrix, a benchmarking section with the real eval table, an agents table,
  and version-pinning guidance.

### Deprecated
- `AgentA` / `AgentB` / `AgentC` — use the role-based names above.

## [0.1.0] — 2026-07-24

First working release. The core pipeline is covered by tests (120 tests, ruff + mypy strict
clean, full suite green in Docker/Linux including the libFuzzer path, ~90% coverage).

### Added — discovery pipeline
- Compile C/C++ targets with clang under ASan/UBSan and run inputs against them; capture
  crashes as normalized findings (`raon.fuzzing`).
- Parse ASan/UBSan/LSan/TSan reports into findings without a compiler (`raon.fuzzing.asan`).
- Coverage-guided fuzzing via libFuzzer harnesses (Linux/Docker).
- Auto-synthesize a fuzz harness from a function signature, with a self-repairing compile
  loop that feeds compiler errors back to the model (`raon.fuzzing.harness`).

### Added — triage & orchestration
- Crash deduplication with a stable normalized-stack key that survives rebuilds
  (`raon.triage.dedup`).
- Evidence-weighted conflict resolution and exploitability ranking (`raon.triage`).
- Static / dynamic / inference agents plus a Supervisor that dedups, resolves, and ranks
  findings (`raon.agents`).

### Added — platform
- Shared, concurrency-safe SQLite store for targets, corpora, and findings (`raon.store`).
- Claude integration with model tiering, prompt-hash response caching (reproducible reruns),
  and full JSONL logging for audit/cost (`raon.llm`).
- PNG domain knowledge pack — seeds and weak-interface hints (`raon.knowledge`).
- Magma benchmark ground-truth ingestion and core metrics: dedup accuracy, false-positive
  rate, time-to-first-crash, cost per unique bug (`raon.bench`).
- Crash-address grounding and LLM type recovery for source-less targets, experimental
  (`raon.binary`).
- `raon` CLI: `version` · `kb` · `triage` · `run` · `report`.

### Infra
- Pinned reproducible Docker environment (clang/llvm + compiler-rt), GitHub Actions CI
  (Python 3.10–3.12), security policy (`POLICY.md`), contributor guide, runnable demo.

### Notes
- macOS Apple clang has no libFuzzer runtime, so the file-input ASan mode is the default there;
  coverage-guided fuzzing runs on Linux/Docker.
- Running Magma's full benchmark suite requires an x86_64 Linux host with Docker.

## [0.0.0] — name reservation
- Placeholder release reserving the PyPI name.
