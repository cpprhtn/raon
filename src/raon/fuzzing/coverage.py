"""하네스 도달 검증 (0.2.0, 01 §4.1 self-repair 강화).

합성된 하네스가 컴파일은 되지만 **실제로 타겟 함수를 실행하지 않으면** 그 하네스로 얻은
결과는 무의미하다(가짜 셋업). 여기서는 source-based coverage(clang `-fcoverage-mapping`)로
"양성 시드 하나가 타겟 함수를 실행하는가"를 검증한다.

llvm-profdata/llvm-cov가 필요하다(Linux clang·Docker엔 있음, macOS는 xcrun로 시도). 없으면
`reached=None`(판정 불가)으로 우아하게 후퇴한다 — 검증을 강제하지 않는다.

‼️ 도달 검증에는 **크래시하지 않는** 시드를 써야 한다. sanitizer가 에러로 죽으면 프로파일이
기록되지 않기 때문(타겟 도달 여부와 무관하게). 목적은 "하네스가 타겟을 부르긴 하는가"다.
"""

from __future__ import annotations

import functools
import json
import os
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .engine import CompiledHarness, CompileError, HarnessMode, clang_path


@functools.lru_cache(maxsize=8)
def _tool(name: str) -> str | None:
    """PATH 또는 xcrun에서 llvm 도구 경로를 찾는다."""
    found = shutil.which(name)
    if found:
        return found
    try:
        r = subprocess.run(
            ["xcrun", "--find", name], capture_output=True, text=True, check=False
        )
        if r.returncode == 0 and r.stdout.strip():
            return r.stdout.strip()
    except OSError:
        pass
    return None


def coverage_available() -> bool:
    """llvm-profdata + llvm-cov 가 모두 있으면 도달 검증 가능."""
    return _tool("llvm-profdata") is not None and _tool("llvm-cov") is not None


@dataclass
class ReachResult:
    """도달 검증 결과. reached=None 은 판정 불가(도구 없음/파싱 실패)."""

    function: str
    reached: bool | None
    count: int = 0


def compile_with_coverage(
    sources: list[str | Path],
    out: str | Path,
    *,
    sanitizers: tuple[str, ...] = ("address",),
    timeout: int = 120,
) -> CompiledHarness:
    """source-based coverage 계측을 켜서 FILE_ARG 하네스를 컴파일한다."""
    cc = clang_path()
    if cc is None:
        raise CompileError("clang not found (set CC or install clang)")
    cmd = [
        cc,
        "-g",
        "-O0",
        "-fno-omit-frame-pointer",
        "-fprofile-instr-generate",
        "-fcoverage-mapping",
    ]
    if sanitizers:
        cmd.append("-fsanitize=" + ",".join(sanitizers))
    cmd += [*(str(s) for s in sources), "-o", str(out)]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)
    if proc.returncode != 0:
        raise CompileError(f"coverage compile failed:\n{proc.stderr}")
    return CompiledHarness(
        binary=Path(out), mode=HarnessMode.FILE_ARG, sources=[str(s) for s in sources]
    )


def _function_count(export: dict[str, Any], function: str) -> int:
    """llvm-cov export JSON에서 function 이름과 매칭되는 함수의 실행 카운트."""
    best = 0
    for datum in export.get("data", []):
        for fn in datum.get("functions", []):
            name = str(fn.get("name", ""))
            if function == name or function in name:
                best = max(best, int(fn.get("count", 0)))
    return best


def function_reached(
    harness: CompiledHarness,
    input_path: str | Path,
    function: str,
    *,
    timeout: int = 30,
) -> ReachResult:
    """coverage-계측 FILE_ARG 하네스를 양성 시드로 실행해 target 함수 도달 여부를 판정."""
    if not coverage_available():
        return ReachResult(function=function, reached=None)
    profdata_tool = _tool("llvm-profdata")
    cov_tool = _tool("llvm-cov")
    assert profdata_tool and cov_tool  # coverage_available() 보장

    with tempfile.TemporaryDirectory() as d:
        raw = Path(d) / "p.profraw"
        merged = Path(d) / "p.profdata"
        env = dict(os.environ)
        env["LLVM_PROFILE_FILE"] = str(raw)
        env.setdefault("ASAN_OPTIONS", "abort_on_error=0:detect_leaks=0")
        try:
            subprocess.run(
                [str(harness.binary), str(input_path)],
                capture_output=True,
                timeout=timeout,
                env=env,
                check=False,
            )
        except subprocess.TimeoutExpired:
            return ReachResult(function=function, reached=None)
        if not raw.exists():
            # 프로파일 미기록(시드가 크래시를 냈을 가능성) → 판정 불가
            return ReachResult(function=function, reached=None)
        subprocess.run(
            [profdata_tool, "merge", "-sparse", str(raw), "-o", str(merged)],
            capture_output=True,
            check=False,
        )
        r = subprocess.run(
            [cov_tool, "export", str(harness.binary), f"-instr-profile={merged}", "--format=text"],
            capture_output=True,
            text=True,
            check=False,
        )
        try:
            export = json.loads(r.stdout or "{}")
        except json.JSONDecodeError:
            return ReachResult(function=function, reached=None)
        count = _function_count(export, function)
        return ReachResult(function=function, reached=count > 0, count=count)
