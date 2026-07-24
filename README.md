# raon

> **LLM-driven vulnerability discovery.** raon compiles your C/C++ target, fuzzes it under
> sanitizers, and turns every crash into a clean, deduplicated, ranked bug report — with an
> LLM in the loop to write harnesses and reason about findings, never in the hot path.

Point raon at a target and a few inputs; get back normalized `Finding`s ranked by
exploitability, with duplicate crashes collapsed. It orchestrates proven tools (clang/ASan,
libFuzzer, angr) rather than reinventing them, and keeps every crash, corpus, and finding on a
single shared store you can query.

**Languages:** English · [한국어](README.ko.md) · [中文](README.zh.md)

[![CI](https://github.com/cpprhtn/raon/actions/workflows/ci.yml/badge.svg)](https://github.com/cpprhtn/raon/actions/workflows/ci.yml)

> ⚠️ **Research pre-alpha.** The tool works end to end today for source-based C/C++ targets:
> compile → fuzz/run → parse crash → dedup → rank → report, plus LLM harness synthesis. It is
> for security research, CTFs, and authorized testing — see [POLICY.md](POLICY.md).

---

## Installation

```bash
pip install raon                 # core
pip install 'raon[llm]'          # + Claude provider (harness synthesis, triage summaries)
pip install 'raon[binary]'       # + angr/LIEF (source-less targets, experimental)
pip install 'raon[dev]'          # + dev tools (pytest/ruff/mypy)
```

You need **clang** (with AddressSanitizer) to compile and fuzz targets. On Linux, clang also
ships the libFuzzer runtime, so coverage-guided fuzzing works out of the box; the included
`docker/Dockerfile` gives you that environment on any host.

---

## What you can do today

- **Run a target and get ranked bug reports** — `raon run` compiles your C source under
  ASan/UBSan, executes your inputs, captures crashes, and reports them deduplicated and ranked.
- **Coverage-guided fuzzing** — build a libFuzzer harness and let raon drive it (Linux / Docker).
- **Turn an existing crash log into a finding** — `raon triage` parses an ASan/UBSan/LSan/TSan
  report into a normalized, deduplicated `Finding` (no compiler needed).
- **Auto-synthesize a fuzz harness** from a function signature, with a self-repairing
  compile loop (requires the `[llm]` extra + an API key).
- **Query and re-rank everything** — all findings live in a SQLite store; `raon report` ranks
  them by exploitability and collapses duplicates.

---

## Quickstart (CLI)

```bash
# Compile a target, run inputs, triage crashes, store + rank
raon run mytarget.c --input seed.bin --input crash.bin --db raon.sqlite

# Parse a saved sanitizer crash log into a Finding (no compiler needed)
raon triage crash_report.txt --target-id my_target --db raon.sqlite

# Rank all stored findings by exploitability (duplicates collapsed)
raon report --db raon.sqlite

# List built-in domain knowledge (seeds, weak-interface hints)
raon kb
```

Example `raon run` output:

```json
{
  "target": "tgt_cli",
  "inputs_run": 2,
  "crashes": 1,
  "unique_bugs": 1,
  "findings": [
    {"id": "find_00001", "category": "memory", "exploitability": 0.95, "dedup_key": "f2b5bb1c1021"}
  ]
}
```

## Quickstart (Python)

```python
from raon.store import Blackboard
from raon.agents import AgentB, Supervisor

with Blackboard("raon.sqlite") as store:
    # Parse a crash report into a normalized finding (high-confidence dynamic crash)
    finding = AgentB().triage(open("crash.txt").read(),
                              target_id="my_target", reproducer="poc.bin")
    store.put_finding(finding)

    # Deduplicate, resolve conflicting evidence, rank by exploitability
    result = Supervisor().triage(store.list_findings())
    for f in result.representatives:
        print(f.category, f.exploitability, f.dedup_key[:12])
```

### Enabling the LLM (optional)

Harness synthesis and inference use Claude. Compose a provider once; responses are cached
(so reruns are reproducible and cheap) and every call is logged for audit and cost tracking:

```python
from raon.llm import build_provider, PromptCache, JsonlLogger
from raon.llm.anthropic_provider import AnthropicProvider

provider = build_provider(
    AnthropicProvider(),                    # reads ANTHROPIC_API_KEY
    cache=PromptCache(".raon/cache"),       # same prompt -> same response
    logger=JsonlLogger(".raon/llm.jsonl"),  # audit / cost ledger
)
```

Everything except harness synthesis and LLM-based reasoning works without an API key.

---

## How it works

raon runs the fuzzer as a native subprocess for speed and calls the LLM only at decision
points (writing a harness, summarizing a crash, proposing a fuzzing target) — never inside the
per-execution loop. Each stage communicates through a small set of shared records on one
store, so the pieces stay independent and everything a run produces is inspectable.

| Component | What it does |
|---|---|
| [`raon.fuzzing`](src/raon/fuzzing) | Compiles targets with clang + sanitizers, runs them, parses crash reports, synthesizes harnesses |
| [`raon.agents`](src/raon/agents) | Interprets crashes, static-analysis results, and weak-interface hypotheses into findings |
| [`raon.triage`](src/raon/triage) | Deduplicates crashes, weighs evidence, ranks by exploitability |
| [`raon.store`](src/raon/store) | Shared SQLite store for targets, corpora, and findings (concurrency-safe) |
| [`raon.llm`](src/raon/llm) | Claude integration with model tiering, response caching, and full logging |
| [`raon.knowledge`](src/raon/knowledge) | Domain packs (e.g. PNG) providing seeds and weak-interface hints |
| [`raon.bench`](src/raon/bench) | Reads Magma benchmark ground truth and computes metrics |
| [`raon.binary`](src/raon/binary) | Maps crash addresses to functions and recovers types for source-less targets (experimental) |
| [`raon.contracts`](src/raon/contracts) | The shared record types every component reads and writes |

A crash is reported as a **`Finding`**: a category, the evidence (reproducer + sanitizer
report, or a static path), a confidence, an exploitability score, and a `dedup_key`. The
`dedup_key` is a normalized stack hash that strips addresses, line numbers, and build paths, so
the same bug maps to the same key even across rebuilds — that's what lets raon collapse
duplicate crashes reliably.

---

## Status

**Available now:** source-based C/C++ fuzzing and crash triage, harness auto-synthesis,
crash deduplication and exploitability ranking, a PNG knowledge pack, Magma metric ingestion,
and the CLI/Python API above.

**Experimental / in progress:** source-less (binary) targets via angr, coverage-guided
fuzzing at scale, additional domain knowledge packs, and larger evaluation studies. Running
Magma's full benchmark suite requires an x86_64 Linux host with Docker.

---

## Development

```bash
pip install -e '.[dev,llm]'
ruff check src tests      # lint
mypy                      # types (strict)
pytest -q                 # full suite (fuzzing tests auto-run when clang is present)
pytest -q -m "not integration"   # unit only, no clang

# full reproducible environment (Linux clang + libFuzzer):
docker build -f docker/Dockerfile -t raon:ci . && docker run --rm raon:ci
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for conventions and [examples/](examples/) for a
runnable end-to-end demo.

---

## Security & ethics

raon is a vulnerability-discovery tool for **authorized use only**. Read [POLICY.md](POLICY.md)
for authorized-use, responsible-disclosure, and reproducibility guidance before pointing it at
anything you don't own.

## License

[MIT](LICENSE) © 2026 Junwon Lee
