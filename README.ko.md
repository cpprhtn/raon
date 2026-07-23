# raon

> **LLM 기반 취약점 발견** — LLM에게 "버그를 찾게" 하지 않고,
> "버그를 찾아낼 최고의 테스트베드를 자동 생성·운영"하게 한다.

`raon`은 **퍼징 · 멀티에이전트 오케스트레이션 · 바이너리 분석**을 하나의 닫힌 피드백 루프로
묶어 소프트웨어 취약점을 자동으로 발견·트리아지하는 연구용 프레임워크입니다. 세 컴포넌트는
독립 도구가 아니라 **같은 데이터 모델(공유 계약) 위에서 도는 하나의 루프**입니다.

**언어:** [English](README.md) · 한국어 · [中文](README.zh.md)

[![CI](https://github.com/cpprhtn/raon/actions/workflows/ci.yml/badge.svg)](https://github.com/cpprhtn/raon/actions/workflows/ci.yml)

> ⚠️ **상태: 연구용 pre-alpha.** 코어 파이프라인(공유 계약 · 블랙보드 · LLM 전략층 · 퍼징
> 엔진 · 하네스 자동합성 · 멀티에이전트 트리아지 · 지표)은 **동작하며 테스트로 검증**됩니다.
> Magma 대규모 캠페인·바이너리 확장은 로드맵 참조.

---

## 설치

```bash
pip install raon                 # 코어
pip install 'raon[llm]'          # + Anthropic(Claude) 프로바이더
pip install 'raon[binary]'       # + angr/LIEF (P4 바이너리 분석)
pip install 'raon[dev]'          # + 개발 도구(pytest/ruff/mypy)
```

퍼징·통합 테스트에는 **clang**(ASan 포함)이 필요합니다. Linux clang은 libFuzzer 런타임까지
포함하므로 `docker/Dockerfile` 환경에서 커버리지 유도 퍼징(LIBFUZZER 모드)도 동작합니다.

---

## 빠른 시작 (CLI)

```bash
raon kb                                          # 내장 도메인 지식 확인
raon triage crash_report.txt --target-id t --db raon.sqlite   # sanitizer 리포트 → Finding (clang 불필요)
raon run mytarget.c --input seed.bin --input crash.bin --db raon.sqlite   # 컴파일·실행·트리아지 (clang 필요)
raon report --db raon.sqlite                     # 저장된 Finding을 exploitability로 랭킹
```

`raon run`은 타겟을 ASan으로 컴파일하고 입력들을 실행해, 크래시를 파싱→`Finding`으로
정규화→블랙보드에 저장→Supervisor가 dedup·랭킹한 결과를 냅니다.

## 빠른 시작 (Python)

```python
from raon.store import Blackboard
from raon.agents import AgentB, Supervisor
from raon.knowledge import register_builtins

with Blackboard("raon.sqlite") as bb:
    register_builtins(bb)                       # PNG 등 도메인 지식 적재

    finding = AgentB().triage(open("crash.txt").read(),
                              target_id="tgt_x", reproducer="poc.bin")
    bb.put_finding(finding)

    result = Supervisor().triage(bb.list_findings())   # dedup → 충돌해소 → 랭킹
    for f in result.representatives:
        print(f.category, f.exploitability, f.dedup_key[:12])
```

LLM 전략층(하네스 합성·추론)을 쓰려면 프로바이더를 조립합니다:

```python
from raon.llm import build_provider, PromptCache, JsonlLogger
from raon.llm.anthropic_provider import AnthropicProvider

provider = build_provider(
    AnthropicProvider(),                        # Claude (adaptive thinking + effort)
    cache=PromptCache(".raon/cache"),           # 재현성: 동일 프롬프트→동일 응답
    logger=JsonlLogger(".raon/llm.jsonl"),      # 감사/비용 원장
)
```

---

## 설계 원칙

1. **LLM은 전략층에만 (hot loop 금지).** 퍼저는 초당 수천~수백만 exec, LLM은 초당 ~1 call.
   퍼저는 네이티브 subprocess로 돌고, LLM(`raon.llm`)은 *어디를·무엇으로·어떻게* 칠지 정하는
   층에만 이벤트 트리거로 개입한다.
2. **기존 인프라를 재구현하지 않는다.** ASan/UBSan, AFL++/libFuzzer, angr, Ghidra는 이미 검증됨.
   raon은 이걸 *조립·해석·연결*한다. 새로움은 래핑이 아니라 오케스트레이션/추론에 있다.
3. **수직 슬라이스 먼저.** 한 타겟 → 한 하네스 → 한 크래시 → 한 트리아지를 3개 컴포넌트에
   관통시켜 유기적 결합을 먼저 증명한다. (→ `raon run`, 통합 테스트로 실증)

---

## 아키텍처

모든 컴포넌트는 블랙보드 위의 **공유 계약**(KnowledgeBase · TargetStore · Corpus ·
FindingStore, SQLite WAL)으로만 대화합니다. 덕분에 느슨하게 결합됩니다: `fuzzing`은 `agents`를
import하지 않고 오직 `contracts`/`store`로만 대화합니다.

| 패키지 | 역할 |
|---|---|
| [`raon.contracts`](src/raon/contracts) | 공유 계약 4종(TargetDescriptor · Corpus · Finding · KnowledgeBase), Pydantic, `schema_version` |
| [`raon.store`](src/raon/store) | 블랙보드 — SQLite WAL + thread-local 연결(다중 리더/단일 라이터) |
| [`raon.llm`](src/raon/llm) | 전략층 — Provider 추상화, 모델 티어링(Haiku/Opus), 프롬프트 해시 캐싱, JSONL 로깅 |
| [`raon.fuzzing`](src/raon/fuzzing) | 엔진(clang+ASan subprocess), sanitizer 파서, 하네스 자동합성(self-repair) |
| [`raon.triage`](src/raon/triage) | dedup 정규화·클러스터링, 증거 가중 충돌해소, exploitability 랭킹 |
| [`raon.agents`](src/raon/agents) | Agent A(정적)/B(동적)/C(추론) + **Supervisor**(오케스트레이션) |
| [`raon.knowledge`](src/raon/knowledge) | 도메인 지식(PNG 등) — 시드/문법 + Agent C 근거 |
| [`raon.bench`](src/raon/bench) | Magma canary monitor 어댑터 + 핵심 지표 |
| [`raon.binary`](src/raon/binary) | (P4) 크래시 grounding + LLM 타입 재복원 |

**데이터 흐름(한 사이클):** Ingest → Plan(우선순위·하네스 합성·시드 선택) → Explore(커버리지
유도 퍼징 → Corpus + 동적 Finding) → Ground(크래시 주소 → 함수 문맥, 소스 없을 때) →
Reason(정적/추론 Finding) → Triage(dedup → 충돌해소 → exploitability) → Feedback(우선순위 갱신·
하네스 요청·시드 정제) → Plan으로 복귀.

---

## 공유 계약

3개 컴포넌트가 유기적으로 붙는 이유는 전부 여기서 나옵니다:

| 계약 | 의미 |
|---|---|
| `TargetDescriptor` | 무엇을 테스트하는가(시그니처 · 진입 경로 · 도메인 태그 · 우선순위) |
| `Corpus` | 탐색이 어디까지 갔나(시드 · edge coverage · stuck_branches) |
| `Finding` | 버그 후보 하나(정규화 단위; 이종 증거를 한 테이블에서 비교) |
| `KnowledgeBase` | 도메인 사전(문법 · 시드 · 불변식 · 취약 인터페이스) |

`Finding.dedup_key = sha1(normalized_stack + category)` — 정규화 규약은
[`raon.triage.dedup`](src/raon/triage/dedup.py)에 명세되어 있고, 주소/라인/빌드경로 노이즈를
제거해 리빌드에도 안정적입니다.

---

## 개발

```bash
pip install -e '.[dev,llm]'
ruff check src tests      # 린트 (자동수정: ruff check --fix)
mypy                      # 타입(strict)
pytest -q                 # 전체 (통합 테스트는 clang 있으면 자동 실행)
pytest -q -m "not integration"   # clang 없이 유닛만
```

Docker로 재현 환경 전체 실행(Linux clang이 libFuzzer 경로까지 실행):

```bash
docker build -f docker/Dockerfile -t raon:ci . && docker run --rm raon:ci
```

기여 규약은 [CONTRIBUTING.md](CONTRIBUTING.md), 실행 가능한 end-to-end 데모는
[examples/](examples/)를 참고하세요.

---

## 로드맵

| Phase | 상태 | 내용 |
|---|---|---|
| **P0** 공유 계약 + 벤치 | ✅ | 스키마 4종 · 블랙보드 · LLM 추상화 · Magma monitor 어댑터 |
| **P1** 수직 슬라이스 v0 | ✅ | 컴파일→크래시→파싱→Finding→저장→랭킹 (실 clang e2e) |
| **P2** 퍼징 심화 | 🚧 | 하네스 자동합성+self-repair ✅ · 시드 프라이밍/stuck-escape ⏳ |
| **P3** 오케스트레이션 심화 | 🚧 | dedup2·충돌해소·랭킹 ✅ · 단일 vs 멀티 실험 ⏳ |
| **P4** 바이너리 확장 | 🚧 | grounding·LLM 재타이핑 ✅ · Ghidra·자체 벤치 ⏳ |

---

## 보안·윤리

raon은 취약점 발견 도구입니다. **권한 있는 사용·책임 있는 공개·재현성** 규약은
[POLICY.md](POLICY.md)를 참고하세요.

## 라이선스

[MIT](LICENSE) © 2026 Junwon Lee
