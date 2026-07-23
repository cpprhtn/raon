"""하네스 합성 유닛 + 통합 테스트 (P2-1): 코드 추출·self-repair 루프."""

from __future__ import annotations

from pathlib import Path

import pytest

from raon.contracts import Signature, TargetDescriptor, TargetKind
from raon.fuzzing.engine import clang_path, run_input
from raon.fuzzing.harness import (
    HarnessSynthesizer,
    _entry_name,  # noqa: PLC2701 (내부 검증)
    extract_code,
)
from raon.llm import LLMRequest, MockProvider

TARGET_LIB = Path(__file__).parent.parent / "fixtures" / "targets" / "decode_lib.c"

VALID_DRIVER = """
#include <stdlib.h>
#include <stdio.h>
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

BROKEN_DRIVER = """
int main(int argc, char **argv) {
    definitely_not_a_type x = 0;   // compile error: unknown type
    return x;
}
"""


# ---- unit (clang 불필요) ----------------------------------------------------
def test_extract_code_from_fence() -> None:
    text = "설명\n```c\nint main(){return 0;}\n```\n끝"
    assert extract_code(text) == "int main(){return 0;}"


def test_extract_code_no_fence() -> None:
    assert extract_code("int x;") == "int x;"


def test_entry_name_from_function() -> None:
    t = TargetDescriptor(kind=TargetKind.SOURCE_FN, location="decode")
    assert _entry_name(t) == "decode"


def test_entry_name_from_path() -> None:
    t = TargetDescriptor(kind=TargetKind.SOURCE_FN, location="src/decode.c:8")
    assert _entry_name(t) == "decode"


def test_synth_prompts_differ() -> None:
    """초기/repair 프롬프트가 구분되는지(mock 분기 근거)."""
    provider = MockProvider(default_text=VALID_DRIVER)
    synth = HarnessSynthesizer(provider)
    t = TargetDescriptor(kind=TargetKind.SOURCE_FN, location="decode")
    init = synth._initial_prompt(t)  # noqa: SLF001
    rep = synth._repair_prompt("code", "error")  # noqa: SLF001
    assert "타겟 시그니처" in init
    assert "컴파일러 에러" in rep


# ---- integration (real clang) ----------------------------------------------
requires_clang = pytest.mark.skipif(clang_path() is None, reason="clang not available")


@requires_clang
@pytest.mark.integration
def test_synthesize_valid_first_try(tmp_path: Path) -> None:
    provider = MockProvider(default_text=VALID_DRIVER)
    synth = HarnessSynthesizer(provider)
    t = TargetDescriptor(kind=TargetKind.SOURCE_FN, location="decode")
    result = synth.synthesize(t, TARGET_LIB, out=tmp_path / "h")
    assert result.ok
    assert result.repair_count == 0
    assert result.harness is not None
    # 합성 하네스로 실제 크래시 재현
    bad = tmp_path / "bad.bin"
    bad.write_bytes(b"A" * 32)
    assert run_input(result.harness, bad).crashed


@requires_clang
@pytest.mark.integration
def test_self_repair_recovers(tmp_path: Path) -> None:
    """★ self-repair: 첫 합성 컴파일 실패 → 에러 피드백 → 재합성 성공."""

    def responder(req: LLMRequest) -> str:
        prompt = req.messages[-1]["content"]
        # repair 프롬프트면 고친 코드, 아니면 깨진 코드
        return VALID_DRIVER if "컴파일러 에러" in prompt else BROKEN_DRIVER

    provider = MockProvider(responder=responder)
    synth = HarnessSynthesizer(provider, max_repairs=2)
    t = TargetDescriptor(
        kind=TargetKind.SOURCE_FN,
        location="decode",
        signature=Signature(returns="int"),
    )
    result = synth.synthesize(t, TARGET_LIB, out=tmp_path / "h")
    assert result.ok
    assert result.repair_count == 1  # 한 번 고쳐서 성공
    assert result.attempts[0].compiled is False
    assert result.attempts[1].compiled is True


@requires_clang
@pytest.mark.integration
def test_self_repair_gives_up(tmp_path: Path) -> None:
    """계속 깨진 코드만 나오면 max_repairs 후 실패로 종료."""
    provider = MockProvider(default_text=BROKEN_DRIVER)
    synth = HarnessSynthesizer(provider, max_repairs=1)
    t = TargetDescriptor(kind=TargetKind.SOURCE_FN, location="decode")
    result = synth.synthesize(t, TARGET_LIB, out=tmp_path / "h")
    assert not result.ok
    assert len(result.attempts) == 2  # 초기 + 1 repair, 둘 다 실패
