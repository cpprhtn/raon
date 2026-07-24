# raon

raon is a research framework for LLM-assisted vulnerability discovery. It compiles C/C++
targets, fuzzes them under sanitizers, and normalizes, deduplicates, and ranks the resulting
crashes into structured findings. Language models are used to synthesize fuzzing harnesses and
reason about findings, but never run inside the per-execution loop. raon orchestrates
established tools — clang/AddressSanitizer, libFuzzer, angr — rather than reimplementing them.

[![CI](https://github.com/cpprhtn/raon/actions/workflows/ci.yml/badge.svg)](https://github.com/cpprhtn/raon/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)

English | [한국어](README.ko.md) | [中文](README.zh.md)

## Status

raon is in early development (pre-alpha); its API may change without notice. It is intended for
security research, capture-the-flag exercises, and authorized testing only. Please read
[POLICY.md](POLICY.md) before use.

## Features

- Compiles C/C++ targets with clang under AddressSanitizer/UndefinedBehaviorSanitizer and runs
  inputs against them.
- Coverage-guided fuzzing through libFuzzer harnesses (on platforms where the libFuzzer runtime
  is available).
- Parses ASan, UBSan, LeakSanitizer, and ThreadSanitizer reports into normalized findings.
- Deduplicates crashes with a normalized-stack key that is stable across rebuilds, and ranks
  findings by exploitability.
- Synthesizes fuzzing harnesses from function signatures, with a self-repairing compile loop.
- Stores targets, corpora, and findings in a single, concurrency-safe SQLite store.
- Optional Claude integration with model tiering, response caching, and full request logging.

## Requirements

- Python 3.10 or newer
- clang with AddressSanitizer, to compile and fuzz targets
- Docker (optional), for a reproducible Linux environment that includes the libFuzzer runtime
- An Anthropic API key (optional), only for harness synthesis and LLM-based reasoning

## Installation

```bash
pip install raon                 # core
pip install 'raon[llm]'          # with the Claude provider
pip install 'raon[binary]'       # with angr/LIEF for source-less targets (experimental)
pip install 'raon[dev]'          # with development tools
```

## Usage

### Command line

```bash
# Compile a target, run inputs, triage crashes, then store and rank the findings
raon run mytarget.c --input seed.bin --input crash.bin --db raon.sqlite

# Parse a saved sanitizer crash report into a finding (no compiler required)
raon triage crash_report.txt --target-id my_target --db raon.sqlite

# Rank stored findings by exploitability, with duplicates collapsed
raon report --db raon.sqlite
```

### Python

```python
from raon.store import Blackboard
from raon.agents import AgentB, Supervisor

with Blackboard("raon.sqlite") as store:
    finding = AgentB().triage(open("crash.txt").read(),
                              target_id="my_target", reproducer="poc.bin")
    store.put_finding(finding)

    result = Supervisor().triage(store.list_findings())
    for f in result.representatives:
        print(f.category, f.exploitability, f.dedup_key[:12])
```

Harness synthesis and inference use Claude. Compose a provider once; responses are cached and
every request is logged:

```python
from raon.llm import build_provider, PromptCache, JsonlLogger
from raon.llm.anthropic_provider import AnthropicProvider

provider = build_provider(
    AnthropicProvider(),                    # reads ANTHROPIC_API_KEY
    cache=PromptCache(".raon/cache"),
    logger=JsonlLogger(".raon/llm.jsonl"),
)
```

Everything except harness synthesis and LLM-based reasoning works without an API key.

## Overview

raon runs the fuzzer as a native subprocess and calls a language model only at decision points
— writing a harness, summarizing a crash, proposing a fuzzing target. Components communicate
through a small set of shared record types on one store, so they remain independent and every
artifact a run produces can be inspected.

| Package | Description |
|---|---|
| `raon.fuzzing` | Compiles targets with clang and sanitizers, runs them, parses crash reports, synthesizes harnesses |
| `raon.agents` | Interprets crashes, static-analysis results, and weak-interface hypotheses into findings |
| `raon.triage` | Deduplicates crashes, weighs evidence, ranks by exploitability |
| `raon.store` | Shared SQLite store for targets, corpora, and findings |
| `raon.llm` | Claude integration with model tiering, response caching, and logging |
| `raon.knowledge` | Domain packs (for example, PNG) providing seeds and weak-interface hints |
| `raon.bench` | Reads Magma benchmark ground truth and computes metrics |
| `raon.binary` | Maps crash addresses to functions and recovers types for source-less targets (experimental) |
| `raon.contracts` | The shared record types every component reads and writes |

A crash is represented as a `Finding`: a category, its evidence, a confidence, an
exploitability score, and a `dedup_key`. The `dedup_key` is a normalized stack hash that omits
addresses, line numbers, and build paths, so the same bug maps to the same key across rebuilds.

## Documentation

- [CONTRIBUTING.md](CONTRIBUTING.md) — development setup and conventions
- [POLICY.md](POLICY.md) — authorized use, responsible disclosure, reproducibility
- [CHANGELOG.md](CHANGELOG.md) — release notes
- [examples/](examples/) — a runnable end-to-end demo

## Building and testing

```bash
pip install -e '.[dev,llm]'
ruff check src tests      # lint
mypy                      # static type checking
pytest -q                 # test suite (fuzzing tests run when clang is present)
pytest -q -m "not integration"   # unit tests only
```

To run the full suite in a reproducible Linux environment (with libFuzzer):

```bash
docker build -f docker/Dockerfile -t raon:ci .
docker run --rm raon:ci
```

## Contributing

Contributions are welcome. Please read [CONTRIBUTING.md](CONTRIBUTING.md) for the development
workflow, coding standards, and the checks that must pass before a pull request. All use of the
project must follow [POLICY.md](POLICY.md).

## License

Licensed under the [MIT License](LICENSE). Copyright © 2026 Junwon Lee.
