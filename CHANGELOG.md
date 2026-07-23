# Changelog

이 프로젝트는 [Semantic Versioning](https://semver.org)을 따릅니다.

## [Unreleased] — 0.1.0 준비

첫 동작 프레임워크. 코어 파이프라인이 테스트로 검증됩니다(120 tests, ruff+mypy strict clean,
Docker/Linux에서 libFuzzer 경로 포함 통과, 커버리지 ~90%).

### Added — 공유 계약 & 저장소 (P0)
- `raon.contracts`: TargetDescriptor · Corpus · Finding · KnowledgeBase (Pydantic,
  `schema_version`), enum 타입, 증거 정합성 검증.
- `raon.triage.dedup`: `normalized_stack` 규약 + `dedup_key`(주소/라인/빌드경로 노이즈 제거,
  리빌드 안정).
- `raon.store.Blackboard`: SQLite WAL + thread-local 연결(다중 리더/단일 라이터), dedup 쿼리.
- `raon.llm`: Provider 추상화, 모델 티어링(Haiku/Opus), 프롬프트 해시 캐싱, JSONL 로깅,
  MockProvider, AnthropicProvider(adaptive thinking + effort, temperature 미사용).

### Added — 퍼징 & 에이전트 (P1–P3)
- `raon.fuzzing.engine`: clang subprocess 어댑터(FILE_ARG ASan / LIBFUZZER 모드), 크래시
  탐지, 컴파일 게이트.
- `raon.fuzzing.asan`: ASan/UBSan/LSan/TSan 파서 → 정규화 Finding.
- `raon.fuzzing.harness`: 하네스 자동합성 + **self-repair 루프**(컴파일 실패→에러 피드백→재합성).
- `raon.agents`: Agent A(정적/Semgrep) · B(동적/sanitizer) · C(추론/KB) + **Supervisor**
  (dedup·증거 가중 충돌해소·exploitability 랭킹·우선순위 스케줄링).
- `raon.knowledge`: PNG 도메인 지식 + 실 PNG 시드 생성.

### Added — 평가 & 도구 (P0-7, P4)
- `raon.bench`: Magma canary monitor CSV 어댑터(ground-truth), 핵심 지표(dedup 정확도·FP율·
  time-to-first-crash·비용/버그).
- `raon.binary`: 크래시 grounding(포함검증) + LLM 타입 재복원(P4 스트레치, guarded angr).
- `raon` CLI: `version|kb|triage|run|report`.

### Infra
- `docker/Dockerfile`(고정 clang/llvm + compiler-rt), GitHub Actions CI(3.10–3.12),
  `POLICY.md`(권한·책임공개·재현성), `CONTRIBUTING.md`, 데모 예제.

### Notes
- macOS Apple clang은 libFuzzer 런타임이 없어 FILE_ARG(ASan) 모드가 기본. libFuzzer 커버리지
  유도 퍼징은 Linux/컨테이너에서 동작.
- Magma 대규모 캠페인은 x86_64 Linux + Docker 필요(어댑터는 monitor 산출물을 소비).

## [0.0.0] — 이름 선점
- PyPI 이름 선점용 플레이스홀더.
