# Contributing to raon

기여를 환영합니다. raon은 연구용 프레임워크이며 아래 규약을 따릅니다.

## 개발 환경

```bash
git clone https://github.com/cpprhtn/raon
cd raon
python -m venv .venv && source .venv/bin/activate
pip install -e '.[dev,llm]'
```

퍼징·통합 테스트에는 **clang**(ASan 포함)이 필요합니다. libFuzzer 모드까지 검증하려면
Linux clang 또는 컨테이너를 쓰세요:

```bash
docker build -f docker/Dockerfile -t raon:ci . && docker run --rm raon:ci
```

## 품질 게이트 (PR 전 필수)

```bash
ruff check src tests      # 린트 (자동수정: ruff check --fix)
mypy                      # 타입 (strict)
pytest -q                 # 전체 테스트
```

세 게이트가 모두 통과해야 합니다. CI가 Python 3.10/3.11/3.12에서 동일 검사를 돌립니다.

## 설계 원칙 (기여 시 지켜주세요)

1. **LLM은 전략층에만.** 퍼저 hot loop나 초당 다회 실행 경로에 LLM을 넣지 마세요.
   `raon.llm`을 이벤트 트리거(plateau·크래시·stuck)에서만 호출합니다.
2. **기존 인프라 재구현 금지.** sanitizer·퍼저·디컴파일러를 다시 만들지 말고 어댑터로 감싸세요.
3. **모듈 경계 = 공유 계약.** 컴포넌트는 `raon.contracts`/`raon.store`로만 대화합니다.
   `fuzzing`이 `agents`를 import하는 식의 결합을 만들지 마세요.

## 테스트 규약

- 새 로직에는 테스트를 추가합니다. **순수 로직은 외부 도구 없이** 검증되도록 설계하세요
  (예: dedup 정규화, grounding 포함검증은 fixture로).
- LLM 의존 코드는 `MockProvider`로 결정적으로 테스트합니다(네트워크·키 불필요).
- clang/외부 도구가 필요한 테스트는 `@pytest.mark.integration` + 가용성 skip을 답니다.

## 커밋 / PR

- 커밋 메시지는 무엇을·왜를 명확히 적어주세요.
- 보안 도구 특성상 [POLICY.md](POLICY.md)의 권한·공개 규약을 준수하세요.

## 취약점 신고

raon **자체**의 보안 이슈는 공개 이슈 대신 메인테이너에게 비공개로 알려주세요.
