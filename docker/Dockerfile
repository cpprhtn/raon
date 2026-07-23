# raon 재현 환경 (P-1-1, D4/D13)
# Linux clang은 libFuzzer 런타임을 포함하므로 LIBFUZZER 모드도 여기서 동작한다
# (macOS Apple clang과 달리). 툴체인 버전을 고정해 실험 재현성을 확보한다.
FROM python:3.11-slim-bookworm

# clang/llvm(ASan·UBSan·libFuzzer·SanitizerCoverage) + 심볼라이저
# ‼️ libclang-rt-*-dev가 compiler-rt 런타임 정적 라이브러리
# (libclang_rt.asan/fuzzer)를 제공한다. Debian arm64 clang 메타패키지는 이걸 빼므로
# 명시 설치해야 ASan/libFuzzer 링크가 된다(x86_64는 대개 포함).
RUN apt-get update && apt-get install -y --no-install-recommends \
        clang \
        llvm \
        libclang-rt-14-dev \
        make \
        git \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# 재현성: ASan 심볼라이즈 결정적, 리크 탐지 끔(하네스 수명 짧음)
ENV ASAN_OPTIONS=abort_on_error=0:detect_leaks=0 \
    UBSAN_OPTIONS=print_stacktrace=1:halt_on_error=0 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# 의존성 먼저(레이어 캐시)
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
RUN pip install --upgrade pip && pip install -e ".[dev,llm]"

COPY tests ./tests

# 기본: 전체 테스트(통합 포함 — 컨테이너엔 clang이 있으므로)
CMD ["pytest", "-q"]
