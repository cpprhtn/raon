"""엔진 유닛 테스트 (clang 불필요): 크래시 탐지·모드 가드."""

from __future__ import annotations

from pathlib import Path

import pytest

from raon.fuzzing.engine import (
    CompiledHarness,
    HarnessMode,
    _is_crash,
    fuzz,
    run_input,
)


def test_crash_signature_detection() -> None:
    assert _is_crash("==1==ERROR: AddressSanitizer: heap-buffer-overflow")
    assert _is_crash("foo.c:1:2: runtime error: signed integer overflow")
    assert not _is_crash("all good, no crash here")


def test_run_input_rejects_wrong_mode() -> None:
    h = CompiledHarness(binary=Path("/nonexistent"), mode=HarnessMode.LIBFUZZER)
    with pytest.raises(ValueError, match="FILE_ARG"):
        run_input(h, "x")


def test_fuzz_rejects_wrong_mode(tmp_path: Path) -> None:
    h = CompiledHarness(binary=Path("/nonexistent"), mode=HarnessMode.FILE_ARG)
    with pytest.raises(ValueError, match="LIBFUZZER"):
        fuzz(h, tmp_path / "c", tmp_path / "a")
