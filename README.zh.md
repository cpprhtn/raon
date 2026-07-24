# raon

> **LLM 驱动的漏洞发现工具。** raon 编译你的 C/C++ 目标，在 sanitizer 下进行模糊测试，并把
> 每个崩溃转化为干净、去重、排序后的漏洞报告。LLM 用于编写 harness、对 Finding 进行推理，
> **绝不进入热路径。**

给 raon 一个目标和几个输入，就能拿回按 exploitability 排序、重复崩溃已合并的规范化 `Finding`。
它编排成熟工具（clang/ASan、libFuzzer、angr）而非重新造轮子，并将所有崩溃、语料、Finding 保存
在一个可查询的共享存储中。

**语言:** [English](README.md) · [한국어](README.ko.md) · 中文

[![CI](https://github.com/cpprhtn/raon/actions/workflows/ci.yml/badge.svg)](https://github.com/cpprhtn/raon/actions/workflows/ci.yml)

> ⚠️ **研究性 pre-alpha。** 对有源码的 C/C++ 目标，今天即可端到端运行：编译 → 模糊/执行 →
> 解析崩溃 → 去重 → 排序 → 报告，外加 LLM harness 合成。用于安全研究、CTF 和**经授权的**
> 测试 —— 见 [POLICY.md](POLICY.md)。

---

## 安装

```bash
pip install raon                 # 核心
pip install 'raon[llm]'          # + Claude provider（harness 合成、triage 摘要）
pip install 'raon[binary]'       # + angr/LIEF（无源码目标，实验性）
pip install 'raon[dev]'          # + 开发工具（pytest/ruff/mypy）
```

编译和模糊目标需要 **clang**（含 AddressSanitizer）。Linux 版 clang 还自带 libFuzzer 运行时，
因此覆盖率引导的模糊测试开箱即用；随附的 `docker/Dockerfile` 可在任意主机上提供该环境。

---

## 现在能做什么

- **运行目标并获得排序后的漏洞报告** —— `raon run` 用 ASan/UBSan 编译你的 C 源码、执行输入、
  捕获崩溃，并去重、排序后报告。
- **覆盖率引导的模糊测试** —— 构建 libFuzzer harness，由 raon 驱动（Linux / Docker）。
- **将已有崩溃日志转成 Finding** —— `raon triage` 把 ASan/UBSan/LSan/TSan 报告解析为规范化、
  去重的 `Finding`（无需编译器）。
- **从函数签名自动合成 fuzz harness** —— 带有自我修复的编译循环（需 `[llm]` extra + API key）。
- **查询并重新排序全部结果** —— 所有 Finding 存于 SQLite；`raon report` 按 exploitability 排序
  并合并重复项。

---

## 快速开始（CLI）

```bash
# 编译目标、执行输入、triage 崩溃、存储 + 排序
raon run mytarget.c --input seed.bin --input crash.bin --db raon.sqlite

# 把已保存的 sanitizer 崩溃日志解析为 Finding（无需编译器）
raon triage crash_report.txt --target-id my_target --db raon.sqlite

# 按 exploitability 对已存 Finding 排序（合并重复项）
raon report --db raon.sqlite

# 列出内置领域知识（种子、脆弱接口提示）
raon kb
```

`raon run` 输出示例：

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

## 快速开始（Python）

```python
from raon.store import Blackboard
from raon.agents import AgentB, Supervisor

with Blackboard("raon.sqlite") as store:
    # 把崩溃报告解析为规范化 Finding（动态崩溃，高置信度）
    finding = AgentB().triage(open("crash.txt").read(),
                              target_id="my_target", reproducer="poc.bin")
    store.put_finding(finding)

    # 去重 → 异构证据冲突消解 → 按 exploitability 排序
    result = Supervisor().triage(store.list_findings())
    for f in result.representatives:
        print(f.category, f.exploitability, f.dedup_key[:12])
```

### 启用 LLM（可选）

harness 合成与推理使用 Claude。组合一次 provider 即可：响应会被缓存（重跑可复现且便宜），
每次调用都会记录以便审计和成本追踪：

```python
from raon.llm import build_provider, PromptCache, JsonlLogger
from raon.llm.anthropic_provider import AnthropicProvider

provider = build_provider(
    AnthropicProvider(),                    # 读取 ANTHROPIC_API_KEY
    cache=PromptCache(".raon/cache"),       # 相同 prompt → 相同响应
    logger=JsonlLogger(".raon/llm.jsonl"),  # 审计 / 成本账本
)
```

除 harness 合成和基于 LLM 的推理外，其余功能无需 API key 即可运行。

---

## 工作原理

raon 将模糊器作为原生子进程运行以保证速度，仅在决策点（编写 harness、总结崩溃、提出模糊目标）
调用 LLM —— 绝不放进逐次执行的循环里。每个阶段通过同一存储上的一小组共享记录通信，因此各部分
彼此独立，运行产生的一切都可检视。

| 组件 | 职责 |
|---|---|
| [`raon.fuzzing`](src/raon/fuzzing) | 用 clang + sanitizer 编译/运行目标、解析崩溃报告、合成 harness |
| [`raon.agents`](src/raon/agents) | 将崩溃、静态分析结果、脆弱接口假设解释为 Finding |
| [`raon.triage`](src/raon/triage) | 崩溃去重、证据加权、按 exploitability 排序 |
| [`raon.store`](src/raon/store) | 目标/语料/Finding 的共享 SQLite 存储（并发安全） |
| [`raon.llm`](src/raon/llm) | 带模型分级、响应缓存与完整日志的 Claude 集成 |
| [`raon.knowledge`](src/raon/knowledge) | 领域包（如 PNG）—— 提供种子与脆弱接口提示 |
| [`raon.bench`](src/raon/bench) | 读取 Magma 基准 ground truth 并计算指标 |
| [`raon.binary`](src/raon/binary) | 为无源码目标做崩溃地址→函数映射与类型恢复（实验性） |
| [`raon.contracts`](src/raon/contracts) | 所有组件读写的共享记录类型 |

崩溃以 **`Finding`** 形式报告：类别、证据（复现物 + sanitizer 报告，或静态路径）、置信度、
exploitability 分数，以及 `dedup_key`。`dedup_key` 是去除地址、行号和构建路径后的规范化栈哈希，
因此同一 bug 在重新构建后仍映射到同一 key —— 这正是 raon 能可靠合并重复崩溃的原因。

---

## 状态

**现已可用：** 基于源码的 C/C++ 模糊测试与崩溃 triage、harness 自动合成、崩溃去重与
exploitability 排序、PNG 知识包、Magma 指标读取，以及上述 CLI/Python API。

**实验性 / 进行中：** 通过 angr 的无源码（二进制）目标、大规模覆盖率引导模糊测试、更多领域知识包，
以及更大规模的评估研究。运行 Magma 完整基准套件需要 x86_64 Linux 主机 + Docker。

---

## 开发

```bash
pip install -e '.[dev,llm]'
ruff check src tests      # lint
mypy                      # 类型（strict）
pytest -q                 # 完整测试（存在 clang 时自动运行模糊测试）
pytest -q -m "not integration"   # 仅单元测试，无需 clang

# 完整可复现环境（Linux clang + libFuzzer）：
docker build -f docker/Dockerfile -t raon:ci . && docker run --rm raon:ci
```

约定见 [CONTRIBUTING.md](CONTRIBUTING.md)，可运行的端到端示例见 [examples/](examples/)。

---

## 安全与伦理

raon 是仅供**授权使用**的漏洞发现工具。在将其指向任何非你所有的对象之前，请阅读
[POLICY.md](POLICY.md) 中关于授权使用、负责任披露与可复现性的指引。

## 许可证

[MIT](LICENSE) © 2026 Junwon Lee
