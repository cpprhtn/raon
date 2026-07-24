# raon

> **LLM 기반 취약점 발견 도구.** raon은 C/C++ 타겟을 컴파일해 sanitizer 아래에서 퍼징하고,
> 모든 크래시를 깔끔하게 중복제거·랭킹된 버그 리포트로 바꿔줍니다. LLM은 하네스를 작성하고
> Finding을 추론하는 데 쓰이며, **hot path에는 절대 들어가지 않습니다.**

타겟과 입력 몇 개만 주면, exploitability로 랭킹되고 중복 크래시가 합쳐진 정규화 `Finding`을
돌려받습니다. 검증된 도구(clang/ASan, libFuzzer, angr)를 새로 만들지 않고 오케스트레이션하며,
모든 크래시·코퍼스·Finding을 조회 가능한 단일 저장소에 보관합니다.

**언어:** [English](README.md) · 한국어 · [中文](README.zh.md)

[![CI](https://github.com/cpprhtn/raon/actions/workflows/ci.yml/badge.svg)](https://github.com/cpprhtn/raon/actions/workflows/ci.yml)

> ⚠️ **연구용 pre-alpha.** 소스 있는 C/C++ 타겟에 대해 오늘 end-to-end로 동작합니다:
> 컴파일 → 퍼징/실행 → 크래시 파싱 → 중복제거 → 랭킹 → 리포트, 그리고 LLM 하네스 합성.
> 보안 연구·CTF·**권한 있는** 테스트 용도입니다 — [POLICY.md](POLICY.md) 참고.

---

## 설치

```bash
pip install raon                 # 코어
pip install 'raon[llm]'          # + Claude 프로바이더 (하네스 합성, 트리아지 요약)
pip install 'raon[binary]'       # + angr/LIEF (소스 없는 타겟, 실험적)
pip install 'raon[dev]'          # + 개발 도구 (pytest/ruff/mypy)
```

타겟을 컴파일·퍼징하려면 **clang**(AddressSanitizer 포함)이 필요합니다. Linux clang은 libFuzzer
런타임까지 포함하므로 커버리지 유도 퍼징이 바로 동작합니다. 포함된 `docker/Dockerfile`로 어떤
호스트에서든 이 환경을 얻을 수 있습니다.

---

## 지금 할 수 있는 것

- **타겟을 돌려 랭킹된 버그 리포트 받기** — `raon run`이 C 소스를 ASan/UBSan으로 컴파일하고
  입력을 실행해 크래시를 잡고, 중복제거·랭킹해서 리포트합니다.
- **커버리지 유도 퍼징** — libFuzzer 하네스를 빌드해 raon이 구동합니다 (Linux / Docker).
- **기존 크래시 로그를 Finding으로 변환** — `raon triage`가 ASan/UBSan/LSan/TSan 리포트를
  정규화·중복제거된 `Finding`으로 파싱합니다 (컴파일러 불필요).
- **함수 시그니처로부터 퍼즈 하네스 자동합성** — 컴파일 실패를 스스로 고치는 self-repair 루프
  포함 (`[llm]` extra + API 키 필요).
- **전부 조회·재랭킹** — 모든 Finding이 SQLite 저장소에 있고, `raon report`가 exploitability로
  랭킹하며 중복을 합칩니다.

---

## 빠른 시작 (CLI)

```bash
# 타겟 컴파일, 입력 실행, 크래시 트리아지, 저장 + 랭킹
raon run mytarget.c --input seed.bin --input crash.bin --db raon.sqlite

# 저장된 sanitizer 크래시 로그를 Finding으로 파싱 (컴파일러 불필요)
raon triage crash_report.txt --target-id my_target --db raon.sqlite

# 저장된 Finding을 exploitability로 랭킹 (중복 합침)
raon report --db raon.sqlite

# 내장 도메인 지식(시드, 취약 인터페이스 힌트) 확인
raon kb
```

`raon run` 출력 예시:

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

## 빠른 시작 (Python)

```python
from raon.store import Blackboard
from raon.agents import AgentB, Supervisor

with Blackboard("raon.sqlite") as store:
    # 크래시 리포트를 정규화 Finding으로 (동적 크래시, 높은 confidence)
    finding = AgentB().triage(open("crash.txt").read(),
                              target_id="my_target", reproducer="poc.bin")
    store.put_finding(finding)

    # 중복제거 → 이종 증거 충돌해소 → exploitability 랭킹
    result = Supervisor().triage(store.list_findings())
    for f in result.representatives:
        print(f.category, f.exploitability, f.dedup_key[:12])
```

### LLM 활성화 (선택)

하네스 합성과 추론은 Claude를 씁니다. 프로바이더를 한 번 조립하면 응답이 캐싱되어(재실행이
재현 가능하고 저렴함) 모든 호출이 감사·비용 추적용으로 로깅됩니다:

```python
from raon.llm import build_provider, PromptCache, JsonlLogger
from raon.llm.anthropic_provider import AnthropicProvider

provider = build_provider(
    AnthropicProvider(),                    # ANTHROPIC_API_KEY 사용
    cache=PromptCache(".raon/cache"),       # 동일 프롬프트 → 동일 응답
    logger=JsonlLogger(".raon/llm.jsonl"),  # 감사 / 비용 원장
)
```

하네스 합성과 LLM 기반 추론을 제외하면 API 키 없이도 모두 동작합니다.

---

## 동작 방식

raon은 속도를 위해 퍼저를 네이티브 subprocess로 돌리고, LLM은 결정 지점(하네스 작성, 크래시
요약, 퍼징 타겟 제안)에서만 호출합니다 — 매 실행 루프 안에는 절대 넣지 않습니다. 각 단계는
하나의 저장소 위 소수의 공유 레코드로 소통하므로, 조각들이 서로 독립적이고 실행이 만든 모든
것을 들여다볼 수 있습니다.

| 컴포넌트 | 하는 일 |
|---|---|
| [`raon.fuzzing`](src/raon/fuzzing) | clang + sanitizer로 타겟 컴파일·실행, 크래시 리포트 파싱, 하네스 합성 |
| [`raon.agents`](src/raon/agents) | 크래시·정적분석 결과·취약 인터페이스 가설을 Finding으로 해석 |
| [`raon.triage`](src/raon/triage) | 크래시 중복제거, 증거 가중, exploitability 랭킹 |
| [`raon.store`](src/raon/store) | 타겟·코퍼스·Finding 공유 SQLite 저장소 (동시성 안전) |
| [`raon.llm`](src/raon/llm) | 모델 티어링·응답 캐싱·전량 로깅을 갖춘 Claude 연동 |
| [`raon.knowledge`](src/raon/knowledge) | 도메인 팩(예: PNG) — 시드와 취약 인터페이스 힌트 제공 |
| [`raon.bench`](src/raon/bench) | Magma 벤치마크 ground truth 읽기 + 지표 계산 |
| [`raon.binary`](src/raon/binary) | 소스 없는 타겟에서 크래시 주소→함수 매핑, 타입 복원 (실험적) |
| [`raon.contracts`](src/raon/contracts) | 모든 컴포넌트가 읽고 쓰는 공유 레코드 타입 |

크래시는 **`Finding`**으로 리포트됩니다: 카테고리, 증거(재현물 + sanitizer 리포트, 또는 정적
경로), confidence, exploitability 점수, 그리고 `dedup_key`. `dedup_key`는 주소·라인 번호·빌드
경로를 제거한 정규화 스택 해시라, 같은 버그가 리빌드 후에도 같은 key로 매핑됩니다 — 이것이
raon이 중복 크래시를 안정적으로 합칠 수 있는 이유입니다.

---

## 상태

**지금 사용 가능:** 소스 기반 C/C++ 퍼징·크래시 트리아지, 하네스 자동합성, 크래시 중복제거와
exploitability 랭킹, PNG 지식 팩, Magma 지표 수집, 위의 CLI/Python API.

**실험적 / 진행 중:** angr 기반 소스 없는(바이너리) 타겟, 대규모 커버리지 유도 퍼징, 추가 도메인
지식 팩, 대규모 평가 연구. Magma 전체 벤치마크 실행에는 x86_64 Linux 호스트 + Docker가 필요합니다.

---

## 개발

```bash
pip install -e '.[dev,llm]'
ruff check src tests      # 린트
mypy                      # 타입(strict)
pytest -q                 # 전체 (퍼징 테스트는 clang 있으면 자동 실행)
pytest -q -m "not integration"   # clang 없이 유닛만

# 재현 환경 전체 (Linux clang + libFuzzer):
docker build -f docker/Dockerfile -t raon:ci . && docker run --rm raon:ci
```

기여 규약은 [CONTRIBUTING.md](CONTRIBUTING.md), 실행 가능한 end-to-end 데모는
[examples/](examples/)를 참고하세요.

---

## 보안·윤리

raon은 **권한 있는 사용만**을 위한 취약점 발견 도구입니다. 소유하지 않은 대상에 사용하기 전에
[POLICY.md](POLICY.md)의 권한 있는 사용·책임 있는 공개·재현성 지침을 읽어주세요.

## 라이선스

[MIT](LICENSE) © 2026 Junwon Lee
