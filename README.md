# raon

> **LLM-driven vulnerability discovery** — don't ask the LLM to "find the bug";
> have it automatically build and operate the best testbed for finding one.

`raon` ties **fuzzing · multi-agent orchestration · binary analysis** into a single
closed feedback loop to automatically discover and triage software vulnerabilities. The three
components are not standalone tools — they are **one loop running on a shared data model
(shared contracts)**.

**Languages:** English · [한국어](README.ko.md) · [中文](README.zh.md)

[![CI](https://github.com/cpprhtn/raon/actions/workflows/ci.yml/badge.svg)](https://github.com/cpprhtn/raon/actions/workflows/ci.yml)

> ⚠️ **Status: research pre-alpha.** The core pipeline (shared contracts, blackboard, LLM
> strategy layer, fuzzing engine, harness auto-synthesis, multi-agent triage, metrics) **works
> and is covered by tests**. Large-scale Magma campaigns and the binary-analysis extension are
> on the roadmap.

---

## Installation

```bash
pip install raon                 # core
pip install 'raon[llm]'          # + Anthropic (Claude) provider
pip install 'raon[binary]'       # + angr/LIEF (P4 binary analysis)
pip install 'raon[dev]'          # + dev tools (pytest/ruff/mypy)
```

Fuzzing and integration tests require **clang** (with ASan). Linux clang also ships the
libFuzzer runtime, so coverage-guided fuzzing (LIBFUZZER mode) works inside the
`docker/Dockerfile` environment.

---

## Quickstart (CLI)

```bash
raon kb                                          # list built-in domain knowledge
raon triage crash_report.txt --target-id t --db raon.sqlite   # sanitizer report -> Finding (no clang)
raon run mytarget.c --input seed.bin --input crash.bin --db raon.sqlite   # compile+run+triage (needs clang)
raon report --db raon.sqlite                     # rank stored Findings by exploitability
```

`raon run` compiles the target with ASan, executes the inputs, then parses crashes into
normalized `Finding`s, stores them on the blackboard, and lets the Supervisor dedup and rank.

## Quickstart (Python)

```python
from raon.store import Blackboard
from raon.agents import AgentB, Supervisor
from raon.knowledge import register_builtins

with Blackboard("raon.sqlite") as bb:
    register_builtins(bb)                       # load PNG etc. domain knowledge

    finding = AgentB().triage(open("crash.txt").read(),
                              target_id="tgt_x", reproducer="poc.bin")
    bb.put_finding(finding)

    result = Supervisor().triage(bb.list_findings())   # dedup -> conflict -> rank
    for f in result.representatives:
        print(f.category, f.exploitability, f.dedup_key[:12])
```

To use the LLM strategy layer (harness synthesis, inference), compose a provider:

```python
from raon.llm import build_provider, PromptCache, JsonlLogger
from raon.llm.anthropic_provider import AnthropicProvider

provider = build_provider(
    AnthropicProvider(),                        # Claude (adaptive thinking + effort)
    cache=PromptCache(".raon/cache"),           # reproducibility: same prompt -> same response
    logger=JsonlLogger(".raon/llm.jsonl"),      # audit / cost ledger
)
```

---

## Design principles

1. **LLM stays in the strategy layer (never the hot loop).** The fuzzer runs thousands–millions
   of execs/sec; the LLM runs ~1 call/sec. The fuzzer runs as a native subprocess; the LLM
   (`raon.llm`) intervenes only in *where / what / how* to hit, on event triggers.
2. **Don't reimplement existing infrastructure.** ASan/UBSan, AFL++/libFuzzer, angr, Ghidra are
   proven. raon *assembles, interprets, and connects* them. Novelty is in orchestration/
   reasoning, not wrapping.
3. **Vertical slice first.** Thread one target → one harness → one crash → one triage through all
   three components to prove organic coupling before deepening any tower (see `raon run`, proven
   by the integration test).

---

## Architecture

Every component talks only through the **shared contracts** on the blackboard
(KnowledgeBase · TargetStore · Corpus · FindingStore, SQLite WAL). This keeps them loosely
coupled: `fuzzing` never imports `agents` — it speaks only `contracts`/`store`.

| Package | Role |
|---|---|
| [`raon.contracts`](src/raon/contracts) | 4 shared contracts (TargetDescriptor · Corpus · Finding · KnowledgeBase), Pydantic, `schema_version` |
| [`raon.store`](src/raon/store) | Blackboard — SQLite WAL + thread-local connections (many readers / single writer) |
| [`raon.llm`](src/raon/llm) | Strategy layer — Provider abstraction, model tiering (Haiku/Opus), prompt-hash cache, JSONL logging |
| [`raon.fuzzing`](src/raon/fuzzing) | Engine (clang+ASan subprocess), sanitizer parser, harness auto-synthesis (self-repair) |
| [`raon.triage`](src/raon/triage) | dedup normalization/clustering, evidence-weighted conflict resolution, exploitability ranking |
| [`raon.agents`](src/raon/agents) | Agent A (static) / B (dynamic) / C (inference) + **Supervisor** (orchestration) |
| [`raon.knowledge`](src/raon/knowledge) | Domain knowledge (PNG, …) — seeds/grammar + Agent C grounds |
| [`raon.bench`](src/raon/bench) | Magma canary-monitor adapter + core metrics |
| [`raon.binary`](src/raon/binary) | (P4) crash grounding + LLM type re-recovery |

**Data flow (one cycle):** Ingest → Plan (priority, harness synth, seed select) → Explore
(coverage-guided fuzzing → Corpus + dynamic Finding) → Ground (crash addr → function context,
when no source) → Reason (static/inference Findings) → Triage (dedup → conflict → exploitability)
→ Feedback (update priorities, request harnesses, refine seeds) → back to Plan.

---

## Shared contracts

Everything that makes the three components couple organically comes from here:

| Contract | Meaning |
|---|---|
| `TargetDescriptor` | *what* to test (signature · entry path · domain tags · priority) |
| `Corpus` | *how far* exploration got (seeds · edge coverage · stuck_branches) |
| `Finding` | one bug candidate (normalized unit; compares heterogeneous evidence in one table) |
| `KnowledgeBase` | domain dictionary (grammar · seeds · invariants · weak interfaces) |

`Finding.dedup_key = sha1(normalized_stack + category)` — the normalization spec lives in
[`raon.triage.dedup`](src/raon/triage/dedup.py) and strips address/line/build-path noise so the
key is stable across rebuilds.

---

## Development

```bash
pip install -e '.[dev,llm]'
ruff check src tests      # lint (auto-fix: ruff check --fix)
mypy                      # types (strict)
pytest -q                 # full suite (integration tests auto-run when clang is present)
pytest -q -m "not integration"   # unit only, no clang
```

Run the full reproducible environment in Docker (Linux clang exercises the libFuzzer path):

```bash
docker build -f docker/Dockerfile -t raon:ci . && docker run --rm raon:ci
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for conventions and [examples/](examples/) for a runnable
end-to-end demo.

---

## Roadmap

| Phase | Status | Content |
|---|---|---|
| **P0** contracts + bench | ✅ | 4 schemas · blackboard · LLM abstraction · Magma monitor adapter |
| **P1** vertical slice v0 | ✅ | compile → crash → parse → Finding → store → rank (real clang e2e) |
| **P2** fuzzing depth | 🚧 | harness auto-synth + self-repair ✅ · seed priming / stuck-escape ⏳ |
| **P3** orchestration depth | 🚧 | dedup2 · conflict resolution · ranking ✅ · single-vs-multi experiment ⏳ |
| **P4** binary extension | 🚧 | grounding · LLM re-typing ✅ · Ghidra · self-benchmark ⏳ |

---

## Security & ethics

raon is a vulnerability-discovery tool. See [POLICY.md](POLICY.md) for authorized-use,
responsible-disclosure, and reproducibility policy.

## License

[MIT](LICENSE) © 2026 Junwon Lee
