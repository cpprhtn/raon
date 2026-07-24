# raon

raon은 LLM을 활용한 취약점 발견 연구 프레임워크입니다. C/C++ 타겟을 컴파일해 sanitizer 아래에서
퍼징하고, 그 결과로 나온 크래시를 정규화·중복제거·랭킹하여 구조화된 finding으로 만듭니다. 언어
모델은 퍼징 하네스를 합성하고 finding을 추론하는 데 쓰이며, 매 실행 루프 안에는 절대 들어가지
않습니다. raon은 검증된 도구(clang/AddressSanitizer, libFuzzer, angr)를 새로 구현하지 않고
오케스트레이션합니다.

[![CI](https://github.com/cpprhtn/raon/actions/workflows/ci.yml/badge.svg)](https://github.com/cpprhtn/raon/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)

[English](README.md) | 한국어 | [中文](README.zh.md)

## 상태

raon은 초기 개발 단계(pre-alpha)이며 API가 예고 없이 바뀔 수 있습니다. 보안 연구, CTF, 권한 있는
테스트 용도로만 사용하십시오. 사용 전 [POLICY.md](POLICY.md)를 읽어주세요.

## 기능

- clang으로 C/C++ 타겟을 AddressSanitizer/UndefinedBehaviorSanitizer 아래에서 컴파일하고 입력을
  실행합니다.
- libFuzzer 하네스를 통한 커버리지 유도 퍼징 (libFuzzer 런타임이 있는 플랫폼).
- ASan, UBSan, LeakSanitizer, ThreadSanitizer 리포트를 정규화된 finding으로 파싱합니다.
- 리빌드에도 안정적인 정규화 스택 키로 크래시를 중복제거하고, finding을 exploitability로 랭킹합니다.
- 함수 시그니처로부터 퍼징 하네스를 합성하며, 컴파일 실패를 스스로 고치는 루프를 갖습니다.
- 타겟·코퍼스·finding을 하나의 동시성 안전 SQLite 저장소에 보관합니다.
- 선택적 Claude 연동 — 모델 티어링, 응답 캐싱, 전량 요청 로깅.

## 요구사항

- Python 3.10 이상
- 타겟을 컴파일·퍼징하기 위한 AddressSanitizer 포함 clang
- (선택) libFuzzer 런타임을 포함하는 재현 가능한 Linux 환경을 위한 Docker
- (선택) 하네스 합성과 LLM 기반 추론에만 필요한 Anthropic API 키

## 설치

```bash
pip install raon                 # 코어
pip install 'raon[llm]'          # Claude 프로바이더 포함
pip install 'raon[binary]'       # 소스 없는 타겟용 angr/LIEF 포함 (실험적)
pip install 'raon[dev]'          # 개발 도구 포함
```

## 사용법

### 명령줄

```bash
# 타겟 컴파일, 입력 실행, 크래시 트리아지 후 finding 저장·랭킹
raon run mytarget.c --input seed.bin --input crash.bin --db raon.sqlite

# 저장된 sanitizer 크래시 리포트를 finding으로 파싱 (컴파일러 불필요)
raon triage crash_report.txt --target-id my_target --db raon.sqlite

# 저장된 finding을 exploitability로 랭킹 (중복 합침)
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

하네스 합성과 추론은 Claude를 사용합니다. 프로바이더를 한 번 조립하면 응답이 캐싱되고 모든 요청이
로깅됩니다:

```python
from raon.llm import build_provider, PromptCache, JsonlLogger
from raon.llm.anthropic_provider import AnthropicProvider

provider = build_provider(
    AnthropicProvider(),                    # ANTHROPIC_API_KEY 사용
    cache=PromptCache(".raon/cache"),
    logger=JsonlLogger(".raon/llm.jsonl"),
)
```

하네스 합성과 LLM 기반 추론을 제외하면 API 키 없이도 모두 동작합니다.

## 개요

raon은 퍼저를 네이티브 subprocess로 실행하고, 언어 모델은 결정 지점(하네스 작성, 크래시 요약,
퍼징 타겟 제안)에서만 호출합니다. 각 컴포넌트는 하나의 저장소 위 소수의 공유 레코드 타입으로
소통하므로 서로 독립적이며, 실행이 만든 모든 산출물을 들여다볼 수 있습니다.

| 패키지 | 설명 |
|---|---|
| `raon.fuzzing` | clang과 sanitizer로 타겟 컴파일·실행, 크래시 리포트 파싱, 하네스 합성 |
| `raon.agents` | 크래시·정적분석 결과·취약 인터페이스 가설을 finding으로 해석 |
| `raon.triage` | 크래시 중복제거, 증거 가중, exploitability 랭킹 |
| `raon.store` | 타겟·코퍼스·finding 공유 SQLite 저장소 |
| `raon.llm` | 모델 티어링·응답 캐싱·로깅을 갖춘 Claude 연동 |
| `raon.knowledge` | 도메인 팩(예: PNG) — 시드와 취약 인터페이스 힌트 제공 |
| `raon.bench` | Magma 벤치마크 ground truth 읽기 및 지표 계산 |
| `raon.binary` | 소스 없는 타겟의 크래시 주소→함수 매핑 및 타입 복원 (실험적) |
| `raon.contracts` | 모든 컴포넌트가 읽고 쓰는 공유 레코드 타입 |

크래시는 `Finding`으로 표현됩니다: 카테고리, 증거, confidence, exploitability 점수, 그리고
`dedup_key`. `dedup_key`는 주소·라인 번호·빌드 경로를 생략한 정규화 스택 해시라, 같은 버그가
리빌드 후에도 같은 키로 매핑됩니다.

## 문서

- [CONTRIBUTING.md](CONTRIBUTING.md) — 개발 환경 설정과 규약
- [POLICY.md](POLICY.md) — 권한 있는 사용, 책임 있는 공개, 재현성
- [CHANGELOG.md](CHANGELOG.md) — 릴리스 노트
- [examples/](examples/) — 실행 가능한 end-to-end 데모

## 빌드 및 테스트

```bash
pip install -e '.[dev,llm]'
ruff check src tests      # 린트
mypy                      # 정적 타입 검사
pytest -q                 # 테스트 (clang 있으면 퍼징 테스트 실행)
pytest -q -m "not integration"   # 유닛 테스트만
```

재현 가능한 Linux 환경(libFuzzer 포함)에서 전체 스위트 실행:

```bash
docker build -f docker/Dockerfile -t raon:ci .
docker run --rm raon:ci
```

## 기여

기여를 환영합니다. 개발 워크플로·코딩 표준·PR 전 통과해야 하는 검사는
[CONTRIBUTING.md](CONTRIBUTING.md)를 참고하세요. 이 프로젝트의 모든 사용은
[POLICY.md](POLICY.md)를 따라야 합니다.

## 라이선스

[MIT License](LICENSE)로 배포됩니다. Copyright © 2026 Junwon Lee.
