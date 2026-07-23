"""dedup 정규화 규약 테스트 (P0-2 DoD): 동일 root → 동일 key, 다른 버그 → 다른 key."""

from __future__ import annotations

from raon.contracts.enums import FindingCategory
from raon.triage.dedup import (
    Frame,
    dedup_key,
    dedup_key_from_functions,
    normalize_frame,
    normalize_stack,
)


def test_addresses_stripped_from_function() -> None:
    assert normalize_frame(Frame(function="png_read_idat 0x55a3f2e1")) == "png_read_idat"
    assert normalize_frame(Frame(function="decode+0x1a2b")) == "decode"


def test_file_basename_and_linecol_stripped() -> None:
    assert normalize_frame(Frame(file="/home/u/magma/targets/libpng/src/png.c:1234:5")) == "png.c"
    assert normalize_frame(Frame(file="src/decode.c:210")) == "decode.c"


def test_function_preferred_over_file() -> None:
    fr = Frame(function="png_handle_iCCP", file="/build/png.c:99")
    assert normalize_frame(fr) == "png_handle_iCCP"


def test_unsymbolized_frame_falls_back_to_file() -> None:
    # 함수가 순수 주소면 파일로 폴백
    fr = Frame(function="0xdeadbeef", file="/build/pngrutil.c:100")
    assert normalize_frame(fr) == "pngrutil.c"


def test_noise_only_frame_is_none() -> None:
    assert normalize_frame(Frame(function="0xdeadbeef", file=None)) is None
    assert normalize_frame(Frame()) is None


def test_top_n_truncation() -> None:
    frames = [Frame(function=f"f{i}") for i in range(10)]
    assert normalize_stack(frames, top_n=3) == ["f0", "f1", "f2"]


def test_noise_frames_skipped_not_counted() -> None:
    frames = [
        Frame(function="0xaaaa"),  # noise, skipped
        Frame(function="real_a"),
        Frame(function="real_b"),
    ]
    assert normalize_stack(frames, top_n=2) == ["real_a", "real_b"]


def test_same_root_different_addresses_same_key() -> None:
    """리빌드로 주소/라인이 달라져도 같은 함수 스택이면 같은 key (under-dedup 방지)."""
    stack_a = [
        Frame(function="png_read_idat 0x1111", file="/build-a/png.c:100:2"),
        Frame(function="png_read 0x2222", file="/build-a/png.c:50:1"),
    ]
    stack_b = [
        Frame(function="png_read_idat 0x9999", file="/build-b/png.c:104:2"),
        Frame(function="png_read 0x8888", file="/build-b/png.c:52:1"),
    ]
    cat = FindingCategory.MEMORY
    assert dedup_key(stack_a, cat) == dedup_key(stack_b, cat)


def test_different_category_different_key() -> None:
    frames = [Frame(function="f")]
    assert dedup_key(frames, FindingCategory.MEMORY) != dedup_key(
        frames, FindingCategory.LOGIC
    )


def test_different_stack_different_key() -> None:
    a = [Frame(function="foo"), Frame(function="bar")]
    b = [Frame(function="foo"), Frame(function="baz")]
    assert dedup_key(a, FindingCategory.MEMORY) != dedup_key(b, FindingCategory.MEMORY)


def test_category_accepts_str_or_enum() -> None:
    frames = [Frame(function="f")]
    assert dedup_key(frames, FindingCategory.MEMORY) == dedup_key(frames, "memory")


def test_empty_stack_uses_category_only() -> None:
    # 심볼 전무여도 카테고리 단위 클러스터링은 유지
    k1 = dedup_key([], FindingCategory.MEMORY)
    k2 = dedup_key([Frame()], FindingCategory.MEMORY)
    assert k1 == k2
    assert k1 != dedup_key([], FindingCategory.LOGIC)


def test_dedup_key_is_sha1_hex() -> None:
    k = dedup_key([Frame(function="f")], FindingCategory.MEMORY)
    assert len(k) == 40
    int(k, 16)  # valid hex


def test_from_functions_helper_matches() -> None:
    k1 = dedup_key_from_functions(["a", "b"], FindingCategory.MEMORY)
    k2 = dedup_key([Frame(function="a"), Frame(function="b")], FindingCategory.MEMORY)
    assert k1 == k2
