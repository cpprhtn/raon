"""퍼징 엔진 어댑터 (P1-1, 01 §3).

원칙 1·2: 퍼저/새니타이저를 재구현하지 않고 **subprocess로 감싼다**. LLM은 여기 없다.
엔진층은 네이티브 바이너리로 돌아 hot loop 속도를 유지한다.

## 두 모드
- **FILE_ARG**: `main(argc, argv)`가 `argv[1]`을 입력 파일로 읽는 하네스. clang + ASan만
  있으면 어디서나 동작(재현·검증·데모용). macOS Apple clang은 libFuzzer 런타임이 없어
  이 모드가 기본이다.
- **LIBFUZZER**: `LLVMFuzzerTestOneInput` 하네스를 `-fsanitize=fuzzer`로 빌드해 커버리지
  유도 퍼징. libFuzzer 런타임이 있을 때만.

크래시 탐지는 종료코드가 아니라 **stderr의 sanitizer 리포트 시그니처**로 한다(플랫폼 견고).
"""

from __future__ import annotations

import functools
import os
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

from .asan import parse_report

_SAN_SIGNATURES = (
    "AddressSanitizer:",
    "UndefinedBehaviorSanitizer:",
    "LeakSanitizer:",
    "ThreadSanitizer:",
    "runtime error:",
)


class HarnessMode(str, Enum):
    FILE_ARG = "file_arg"
    LIBFUZZER = "libfuzzer"


class CompileError(RuntimeError):
    """하네스 컴파일 실패."""


@dataclass
class CompiledHarness:
    """컴파일된 하네스 바이너리."""

    binary: Path
    mode: HarnessMode
    sources: list[str] = field(default_factory=list)


@dataclass
class CrashResult:
    """단일 입력 실행 결과."""

    crashed: bool
    returncode: int
    sanitizer_output: str
    reproducer: str | None = None

    @property
    def error_type(self) -> str | None:
        parsed = parse_report(self.sanitizer_output)
        return parsed.error_type if parsed else None


@dataclass
class FuzzResult:
    """퍼징 캠페인 결과."""

    crashed: bool
    reproducer: str | None
    sanitizer_output: str
    stdout: str = ""


@functools.lru_cache(maxsize=1)
def clang_path() -> str | None:
    """clang 실행 경로(없으면 None). CC 환경변수 우선."""
    return os.environ.get("CC") or shutil.which("clang")


@functools.lru_cache(maxsize=1)
def libfuzzer_available() -> bool:
    """`-fsanitize=fuzzer` 링크가 되는지 실제 컴파일로 1회 프로브."""
    cc = clang_path()
    if cc is None:
        return False
    with tempfile.TemporaryDirectory() as d:
        src = Path(d) / "probe.c"
        src.write_text(
            "#include <stdint.h>\n#include <stddef.h>\n"
            "int LLVMFuzzerTestOneInput(const uint8_t*data,size_t size){return 0;}\n"
        )
        out = Path(d) / "probe"
        proc = subprocess.run(
            [cc, "-fsanitize=fuzzer,address", str(src), "-o", str(out)],
            capture_output=True,
            text=True,
            check=False,
        )
        return proc.returncode == 0


def compile_harness(
    sources: list[str | Path],
    out: str | Path,
    *,
    mode: HarnessMode = HarnessMode.FILE_ARG,
    sanitizers: tuple[str, ...] = ("address", "undefined"),
    coverage: bool = True,
    opt: str = "-O1",
    extra_flags: tuple[str, ...] = (),
    timeout: int = 120,
) -> CompiledHarness:
    """소스들을 하네스 바이너리로 컴파일. 실패 시 CompileError.

    LIBFUZZER 모드는 `-fsanitize=fuzzer`를 추가한다(런타임 필요). FILE_ARG는 순수 ASan.
    """
    cc = clang_path()
    if cc is None:
        raise CompileError("clang not found (set CC or install clang)")

    san = list(sanitizers)
    if mode == HarnessMode.LIBFUZZER:
        san = ["fuzzer", *san]

    cmd = [cc, "-g", opt, "-fno-omit-frame-pointer"]
    if san:
        cmd.append("-fsanitize=" + ",".join(san))
    if coverage and mode != HarnessMode.LIBFUZZER:
        # libFuzzer는 커버리지를 자동 추가하므로 중복 지정하지 않는다.
        cmd.append("-fsanitize-coverage=trace-pc-guard")
    cmd += [*extra_flags, *(str(s) for s in sources), "-o", str(out)]

    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)
    if proc.returncode != 0:
        raise CompileError(f"compile failed:\n{proc.stderr}")
    return CompiledHarness(binary=Path(out), mode=mode, sources=[str(s) for s in sources])


def _is_crash(output: str) -> bool:
    return any(sig in output for sig in _SAN_SIGNATURES)


def _san_env() -> dict[str, str]:
    env = dict(os.environ)
    # 리포트는 내되 abort 대신 종료. 심볼라이즈 켬.
    env.setdefault("ASAN_OPTIONS", "abort_on_error=0:exitcode=1:detect_leaks=0")
    env.setdefault("UBSAN_OPTIONS", "print_stacktrace=1:halt_on_error=0")
    return env


def run_input(
    harness: CompiledHarness,
    input_path: str | Path,
    *,
    timeout: int = 30,
) -> CrashResult:
    """FILE_ARG 하네스를 입력 파일 하나로 실행하고 크래시 여부를 판정."""
    if harness.mode != HarnessMode.FILE_ARG:
        raise ValueError("run_input requires FILE_ARG harness")
    try:
        proc = subprocess.run(
            [str(harness.binary), str(input_path)],
            capture_output=True,
            text=True,
            timeout=timeout,
            env=_san_env(),
            check=False,
        )
    except subprocess.TimeoutExpired as e:
        return CrashResult(crashed=True, returncode=-1, sanitizer_output=f"TIMEOUT: {e}")
    output = (proc.stderr or "") + (proc.stdout or "")
    crashed = _is_crash(output)
    return CrashResult(
        crashed=crashed,
        returncode=proc.returncode,
        sanitizer_output=output,
        reproducer=str(input_path) if crashed else None,
    )


def fuzz(
    harness: CompiledHarness,
    corpus_dir: str | Path,
    artifact_dir: str | Path,
    *,
    max_total_time: int = 30,
    max_len: int = 4096,
    timeout: int = 60,
) -> FuzzResult:
    """LIBFUZZER 하네스로 커버리지 유도 퍼징. 첫 크래시 재현물을 반환.

    libFuzzer는 크래시 시 `crash-<sha1>` 파일을 artifact_dir에 쓰고 비정상 종료한다.
    """
    if harness.mode != HarnessMode.LIBFUZZER:
        raise ValueError("fuzz requires LIBFUZZER harness")
    artifact = Path(artifact_dir)
    artifact.mkdir(parents=True, exist_ok=True)
    corpus = Path(corpus_dir)
    corpus.mkdir(parents=True, exist_ok=True)

    cmd = [
        str(harness.binary),
        f"-max_total_time={max_total_time}",
        f"-max_len={max_len}",
        f"-artifact_prefix={artifact}/",
        str(corpus),
    ]
    proc = subprocess.run(
        cmd, capture_output=True, text=True, timeout=timeout, env=_san_env(), check=False
    )
    output = (proc.stderr or "") + (proc.stdout or "")
    crashed = _is_crash(output)
    reproducer = None
    if crashed:
        crashes = sorted(artifact.glob("crash-*"))
        if crashes:
            reproducer = str(crashes[0])
    return FuzzResult(
        crashed=crashed, reproducer=reproducer, sanitizer_output=output, stdout=proc.stdout or ""
    )
