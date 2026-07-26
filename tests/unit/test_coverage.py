"""도달 검증 테스트: export 파싱(유닛) + 실제 coverage 도달(통합)."""

from __future__ import annotations

from pathlib import Path

import pytest

from raon.contracts import Signature, TargetDescriptor, TargetKind
from raon.fuzzing.coverage import (
    _function_count,
    compile_with_coverage,
    coverage_available,
    function_reached,
)
from raon.fuzzing.engine import clang_path
from raon.fuzzing.harness import HarnessSynthesizer
from raon.llm import LLMRequest, MockProvider

TARGET_LIB = Path(__file__).parent.parent / "fixtures" / "targets" / "decode_lib.c"

CALLING_DRIVER = """
#include <stdio.h>
#include <stdlib.h>
extern int decode(const unsigned char *data, size_t size);
int main(int argc, char **argv) {
    if (argc < 2) return 0;
    FILE *f = fopen(argv[1], "rb");
    if (!f) return 0;
    unsigned char b[65536];
    size_t n = fread(b, 1, sizeof b, f);
    fclose(f);
    return decode(b, n);
}
"""

# compiles + links (decode is defined in target) but never calls decode
NONCALLING_DRIVER = """
#include <stdio.h>
#include <stdlib.h>
extern int decode(const unsigned char *data, size_t size);
int main(int argc, char **argv) {
    if (argc < 2) return 0;
    FILE *f = fopen(argv[1], "rb");
    if (f) fclose(f);
    return 0;  /* never calls decode */
}
"""


# ---- unit ------------------------------------------------------------------
def test_function_count_parsing() -> None:
    export = {"data": [{"functions": [{"name": "decode", "count": 3}, {"name": "main", "count": 1}]}]}
    assert _function_count(export, "decode") == 3
    assert _function_count(export, "main") == 1
    assert _function_count(export, "missing") == 0


def test_coverage_available_is_bool() -> None:
    assert isinstance(coverage_available(), bool)


# ---- integration (needs clang + llvm coverage tools) -----------------------
requires_cov = pytest.mark.skipif(
    clang_path() is None or not coverage_available(),
    reason="clang + llvm-profdata/llvm-cov required",
)


@requires_cov
@pytest.mark.integration
def test_reached_true_when_target_called(tmp_path: Path) -> None:
    driver = tmp_path / "drv.c"
    driver.write_text(CALLING_DRIVER)
    harness = compile_with_coverage([driver, TARGET_LIB], tmp_path / "h")
    seed = tmp_path / "s.bin"
    seed.write_bytes(b"\x00\x00\x00\x00")  # size 4 <= 8, benign, reaches decode
    assert function_reached(harness, seed, "decode").reached is True


@requires_cov
@pytest.mark.integration
def test_reached_false_when_target_not_called(tmp_path: Path) -> None:
    driver = tmp_path / "drv.c"
    driver.write_text(NONCALLING_DRIVER)
    harness = compile_with_coverage([driver, TARGET_LIB], tmp_path / "h")
    seed = tmp_path / "s.bin"
    seed.write_bytes(b"\x00\x00\x00\x00")
    assert function_reached(harness, seed, "decode").reached is False


@requires_cov
@pytest.mark.integration
def test_synthesizer_reach_repair(tmp_path: Path) -> None:
    """★ 컴파일은 되나 미도달 → reach-repair → 도달하는 하네스로 회복."""

    def responder(req: LLMRequest) -> str:
        prompt = req.messages[-1]["content"]
        # reach-repair 프롬프트면 호출하는 드라이버, 아니면 미호출 드라이버
        return CALLING_DRIVER if "실행되지 않았다" in prompt else NONCALLING_DRIVER

    synth = HarnessSynthesizer(MockProvider(responder=responder), max_repairs=2)
    t = TargetDescriptor(
        kind=TargetKind.SOURCE_FN, location="decode", signature=Signature(returns="int")
    )
    result = synth.synthesize(t, TARGET_LIB, out=tmp_path / "h", verify_reach=True)
    assert result.ok
    assert result.repair_count == 1
    assert result.attempts[0].reached is False
    assert result.attempts[1].reached is True
