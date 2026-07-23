# raon

> **LLM 驱动的漏洞发现** —— 不让 LLM 去"找 bug"，
> 而是让它自动构建并运行"最适合找出 bug 的测试平台"。

`raon` 将**模糊测试 · 多智能体编排 · 二进制分析**整合为一个闭环反馈循环，用于自动发现并
triage 软件漏洞。这三个组件并非独立工具，而是**运行在共享数据模型（共享契约）之上的单一循环**。

**语言:** [English](README.md) · [한국어](README.ko.md) · 中文

[![CI](https://github.com/cpprhtn/raon/actions/workflows/ci.yml/badge.svg)](https://github.com/cpprhtn/raon/actions/workflows/ci.yml)

> ⚠️ **状态：研究性 pre-alpha。** 核心流水线（共享契约、黑板、LLM 策略层、模糊测试引擎、
> harness 自动合成、多智能体 triage、指标）**已可运行并有测试覆盖**。大规模 Magma 活动与
> 二进制分析扩展见路线图。

---

## 安装

```bash
pip install raon                 # 核心
pip install 'raon[llm]'          # + Anthropic (Claude) provider
pip install 'raon[binary]'       # + angr/LIEF（P4 二进制分析）
pip install 'raon[dev]'          # + 开发工具（pytest/ruff/mypy）
```

模糊测试与集成测试需要 **clang**（含 ASan）。Linux 版 clang 还自带 libFuzzer 运行时，因此在
`docker/Dockerfile` 环境中也能运行覆盖率引导的模糊测试（LIBFUZZER 模式）。

---

## 快速开始（CLI）

```bash
raon kb                                          # 列出内置领域知识
raon triage crash_report.txt --target-id t --db raon.sqlite   # sanitizer 报告 → Finding（无需 clang）
raon run mytarget.c --input seed.bin --input crash.bin --db raon.sqlite   # 编译+运行+triage（需要 clang）
raon report --db raon.sqlite                     # 按 exploitability 对已存 Finding 排序
```

`raon run` 会用 ASan 编译目标、执行输入，然后把崩溃解析成规范化的 `Finding`，存入黑板，
再由 Supervisor 去重并排序。

## 快速开始（Python）

```python
from raon.store import Blackboard
from raon.agents import AgentB, Supervisor
from raon.knowledge import register_builtins

with Blackboard("raon.sqlite") as bb:
    register_builtins(bb)                       # 加载 PNG 等领域知识

    finding = AgentB().triage(open("crash.txt").read(),
                              target_id="tgt_x", reproducer="poc.bin")
    bb.put_finding(finding)

    result = Supervisor().triage(bb.list_findings())   # 去重 → 冲突消解 → 排序
    for f in result.representatives:
        print(f.category, f.exploitability, f.dedup_key[:12])
```

若要使用 LLM 策略层（harness 合成、推理），组合一个 provider：

```python
from raon.llm import build_provider, PromptCache, JsonlLogger
from raon.llm.anthropic_provider import AnthropicProvider

provider = build_provider(
    AnthropicProvider(),                        # Claude（adaptive thinking + effort）
    cache=PromptCache(".raon/cache"),           # 可复现性：相同 prompt → 相同响应
    logger=JsonlLogger(".raon/llm.jsonl"),      # 审计 / 成本账本
)
```

---

## 设计原则

1. **LLM 只待在策略层（绝不进热循环）。** 模糊器每秒执行数千至数百万次，LLM 每秒约 1 次调用。
   模糊器作为原生子进程运行；LLM（`raon.llm`）仅在*打哪里、用什么、怎么打*的层面按事件触发介入。
2. **不重新实现已有基础设施。** ASan/UBSan、AFL++/libFuzzer、angr、Ghidra 都已成熟。raon
   *组装、解释、连接*它们。创新在于编排/推理，而非封装。
3. **先做垂直切片。** 让一个目标 → 一个 harness → 一个崩溃 → 一次 triage 贯穿全部三个组件，
   先证明有机耦合再深化任一支柱。（见 `raon run`，由集成测试验证）

---

## 架构

所有组件仅通过黑板上的**共享契约**（KnowledgeBase · TargetStore · Corpus · FindingStore，
SQLite WAL）通信，因此彼此松耦合：`fuzzing` 从不 import `agents`，只用 `contracts`/`store`。

| 包 | 职责 |
|---|---|
| [`raon.contracts`](src/raon/contracts) | 4 个共享契约（TargetDescriptor · Corpus · Finding · KnowledgeBase），Pydantic，`schema_version` |
| [`raon.store`](src/raon/store) | 黑板 —— SQLite WAL + 线程本地连接（多读者 / 单写者） |
| [`raon.llm`](src/raon/llm) | 策略层 —— Provider 抽象、模型分级（Haiku/Opus）、prompt 哈希缓存、JSONL 日志 |
| [`raon.fuzzing`](src/raon/fuzzing) | 引擎（clang+ASan 子进程）、sanitizer 解析器、harness 自动合成（self-repair） |
| [`raon.triage`](src/raon/triage) | 去重规范化/聚类、证据加权冲突消解、exploitability 排序 |
| [`raon.agents`](src/raon/agents) | Agent A（静态）/ B（动态）/ C（推理）+ **Supervisor**（编排） |
| [`raon.knowledge`](src/raon/knowledge) | 领域知识（PNG 等）—— 种子/文法 + Agent C 依据 |
| [`raon.bench`](src/raon/bench) | Magma canary monitor 适配器 + 核心指标 |
| [`raon.binary`](src/raon/binary) | （P4）崩溃 grounding + LLM 类型再恢复 |

**数据流（一个周期）：** Ingest → Plan（优先级、harness 合成、种子选择）→ Explore（覆盖率
引导模糊 → Corpus + 动态 Finding）→ Ground（崩溃地址 → 函数上下文，无源码时）→
Reason（静态/推理 Finding）→ Triage（去重 → 冲突消解 → exploitability）→ Feedback（更新
优先级、请求 harness、精炼种子）→ 回到 Plan。

---

## 共享契约

三个组件之所以能有机耦合，全部源自于此：

| 契约 | 含义 |
|---|---|
| `TargetDescriptor` | 测试*什么*（签名 · 入口路径 · 领域标签 · 优先级） |
| `Corpus` | 探索到了*多远*（种子 · 边覆盖 · stuck_branches） |
| `Finding` | 一个漏洞候选（规范化单元；在同一张表里比较异构证据） |
| `KnowledgeBase` | 领域词典（文法 · 种子 · 不变式 · 脆弱接口） |

`Finding.dedup_key = sha1(normalized_stack + category)` —— 规范化规约见
[`raon.triage.dedup`](src/raon/triage/dedup.py)，它会去除地址/行号/构建路径噪声，使 key 在
重新构建后保持稳定。

---

## 开发

```bash
pip install -e '.[dev,llm]'
ruff check src tests      # lint（自动修复：ruff check --fix）
mypy                      # 类型（strict）
pytest -q                 # 完整测试（存在 clang 时自动运行集成测试）
pytest -q -m "not integration"   # 仅单元测试，无需 clang
```

用 Docker 运行完整可复现环境（Linux clang 会执行 libFuzzer 路径）：

```bash
docker build -f docker/Dockerfile -t raon:ci . && docker run --rm raon:ci
```

约定见 [CONTRIBUTING.md](CONTRIBUTING.md)，可运行的端到端示例见 [examples/](examples/)。

---

## 路线图

| 阶段 | 状态 | 内容 |
|---|---|---|
| **P0** 契约 + 基准 | ✅ | 4 个 schema · 黑板 · LLM 抽象 · Magma monitor 适配器 |
| **P1** 垂直切片 v0 | ✅ | 编译 → 崩溃 → 解析 → Finding → 存储 → 排序（真实 clang e2e） |
| **P2** 模糊测试深化 | 🚧 | harness 自动合成 + self-repair ✅ · 种子引导 / stuck-escape ⏳ |
| **P3** 编排深化 | 🚧 | 二次去重 · 冲突消解 · 排序 ✅ · 单体 vs 多智能体实验 ⏳ |
| **P4** 二进制扩展 | 🚧 | grounding · LLM 重定类型 ✅ · Ghidra · 自建基准 ⏳ |

---

## 安全与伦理

raon 是漏洞发现工具。授权使用、负责任披露与可复现性策略见 [POLICY.md](POLICY.md)。

## 许可证

[MIT](LICENSE) © 2026 Junwon Lee
