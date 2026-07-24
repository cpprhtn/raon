# raon

raon 是一个用于 LLM 辅助漏洞发现的研究框架。它编译 C/C++ 目标，在 sanitizer 下进行模糊测试，
并将由此产生的崩溃规范化、去重并排序为结构化的 finding。语言模型用于合成模糊测试 harness 以及
对 finding 进行推理，但绝不运行于逐次执行的循环之内。raon 编排成熟工具（clang/AddressSanitizer、
libFuzzer、angr），而非重新实现它们。

[![CI](https://github.com/cpprhtn/raon/actions/workflows/ci.yml/badge.svg)](https://github.com/cpprhtn/raon/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)

[English](README.md) | [한국어](README.ko.md) | 中文

## 状态

raon 处于早期开发阶段（pre-alpha），其 API 可能在没有通知的情况下变更。仅供安全研究、
夺旗赛（CTF）和经授权的测试使用。使用前请阅读 [POLICY.md](POLICY.md)。

## 功能

- 使用 clang 在 AddressSanitizer/UndefinedBehaviorSanitizer 下编译 C/C++ 目标并执行输入。
- 通过 libFuzzer harness 进行覆盖率引导的模糊测试（在具备 libFuzzer 运行时的平台上）。
- 将 ASan、UBSan、LeakSanitizer、ThreadSanitizer 报告解析为规范化的 finding。
- 使用在重新构建后仍保持稳定的规范化栈键去重崩溃，并按 exploitability 对 finding 排序。
- 从函数签名合成模糊测试 harness，并带有自我修复的编译循环。
- 将目标、语料和 finding 保存在同一个并发安全的 SQLite 存储中。
- 可选的 Claude 集成——模型分级、响应缓存与完整的请求日志。

## 环境要求

- Python 3.10 或更高版本
- 含 AddressSanitizer 的 clang，用于编译和模糊测试目标
- Docker（可选），用于提供含 libFuzzer 运行时的可复现 Linux 环境
- Anthropic API key（可选），仅用于 harness 合成和基于 LLM 的推理

## 安装

```bash
pip install raon                 # 核心
pip install 'raon[llm]'          # 含 Claude provider
pip install 'raon[binary]'       # 含用于无源码目标的 angr/LIEF（实验性）
pip install 'raon[dev]'          # 含开发工具
```

## 使用

### 命令行

```bash
# 编译目标、执行输入、triage 崩溃，然后存储并排序 finding
raon run mytarget.c --input seed.bin --input crash.bin --db raon.sqlite

# 将已保存的 sanitizer 崩溃报告解析为 finding（无需编译器）
raon triage crash_report.txt --target-id my_target --db raon.sqlite

# 按 exploitability 对已存 finding 排序（合并重复项）
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

harness 合成与推理使用 Claude。组合一次 provider 即可：响应会被缓存，每次请求都会被记录：

```python
from raon.llm import build_provider, PromptCache, JsonlLogger
from raon.llm.anthropic_provider import AnthropicProvider

provider = build_provider(
    AnthropicProvider(),                    # 读取 ANTHROPIC_API_KEY
    cache=PromptCache(".raon/cache"),
    logger=JsonlLogger(".raon/llm.jsonl"),
)
```

除 harness 合成和基于 LLM 的推理外，其余功能无需 API key 即可运行。

## 概述

raon 将模糊器作为原生子进程运行，仅在决策点（编写 harness、总结崩溃、提出模糊目标）调用语言
模型。各组件通过同一存储上的一小组共享记录类型通信，因此彼此独立，运行产生的每个产物都可检视。

| 包 | 说明 |
|---|---|
| `raon.fuzzing` | 用 clang 与 sanitizer 编译/运行目标、解析崩溃报告、合成 harness |
| `raon.agents` | 将崩溃、静态分析结果、脆弱接口假设解释为 finding |
| `raon.triage` | 崩溃去重、证据加权、按 exploitability 排序 |
| `raon.store` | 目标/语料/finding 的共享 SQLite 存储 |
| `raon.llm` | 带模型分级、响应缓存与日志的 Claude 集成 |
| `raon.knowledge` | 领域包（例如 PNG）——提供种子与脆弱接口提示 |
| `raon.bench` | 读取 Magma 基准 ground truth 并计算指标 |
| `raon.binary` | 为无源码目标做崩溃地址→函数映射与类型恢复（实验性） |
| `raon.contracts` | 所有组件读写的共享记录类型 |

崩溃以 `Finding` 表示：类别、证据、置信度、exploitability 分数，以及 `dedup_key`。`dedup_key`
是省略了地址、行号和构建路径的规范化栈哈希，因此同一 bug 在重新构建后仍映射到同一键。

## 文档

- [CONTRIBUTING.md](CONTRIBUTING.md) —— 开发环境设置与约定
- [POLICY.md](POLICY.md) —— 授权使用、负责任披露、可复现性
- [CHANGELOG.md](CHANGELOG.md) —— 发布说明
- [examples/](examples/) —— 可运行的端到端示例

## 构建与测试

```bash
pip install -e '.[dev,llm]'
ruff check src tests      # lint
mypy                      # 静态类型检查
pytest -q                 # 测试套件（存在 clang 时运行模糊测试）
pytest -q -m "not integration"   # 仅单元测试
```

在可复现的 Linux 环境（含 libFuzzer）中运行完整套件：

```bash
docker build -f docker/Dockerfile -t raon:ci .
docker run --rm raon:ci
```

## 贡献

欢迎贡献。开发流程、编码规范以及提交 PR 前需通过的检查见 [CONTRIBUTING.md](CONTRIBUTING.md)。
本项目的所有使用都必须遵循 [POLICY.md](POLICY.md)。

## 许可证

以 [MIT License](LICENSE) 发布。Copyright © 2026 Junwon Lee。
