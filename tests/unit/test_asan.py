"""Sanitizer 파서 테스트 (P1-3 DoD): 리포트 → 유효 Finding, dedup_key 일치."""

from __future__ import annotations

from pathlib import Path

from raon.contracts import EvidenceKind, FindingCategory, SourceComponent
from raon.fuzzing.asan import finding_from_report, parse_report
from raon.triage.dedup import Frame, dedup_key

FIXTURES = Path(__file__).parent.parent / "fixtures" / "sanitizer"


def _load(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8")


def test_parse_heap_buffer_overflow() -> None:
    report = parse_report(_load("heap_buffer_overflow.txt"))
    assert report is not None
    assert report.error_type == "heap-buffer-overflow"
    assert report.category == FindingCategory.MEMORY
    # 상위 프레임 함수명이 잡혀야
    funcs = [f.function for f in report.frames if f.function]
    assert "png_read_idat" in funcs
    assert "png_read_row" in funcs


def test_parse_use_after_free() -> None:
    report = parse_report(_load("use_after_free.txt"))
    assert report is not None
    assert report.error_type == "heap-use-after-free"
    assert report.category == FindingCategory.MEMORY


def test_parse_ubsan() -> None:
    report = parse_report(_load("ubsan_signed_overflow.txt"))
    assert report is not None
    assert report.category == FindingCategory.UNDEFINED_BEHAVIOR
    assert "signed integer overflow" in report.error_type


def test_unsymbolized_frame_parsed() -> None:
    report = parse_report(_load("heap_buffer_overflow.txt"))
    assert report is not None
    # __libc_start_main 프레임의 모듈 경로가 파일로 잡힘
    files = [f.file for f in report.frames if f.file]
    assert any("libc.so.6" in f for f in files)


def test_finding_from_report_dynamic_crash() -> None:
    text = _load("heap_buffer_overflow.txt")
    finding = finding_from_report(
        text,
        target_id="tgt_libpng",
        reproducer="crashes/poc_0001.bin",
        finding_id="find_1",
    )
    assert finding is not None
    assert finding.category == FindingCategory.MEMORY
    assert finding.evidence.kind == EvidenceKind.DYNAMIC_CRASH
    assert finding.evidence.reproducer == "crashes/poc_0001.bin"
    assert finding.evidence.sanitizer_report == text
    assert finding.source_component == SourceComponent.FUZZER
    assert finding.confidence == 0.95


def test_dedup_key_matches_manual_computation() -> None:
    """파서가 만든 dedup_key가 수동 계산과 일치(재현성)."""
    text = _load("heap_buffer_overflow.txt")
    finding = finding_from_report(text, target_id="t", reproducer="r.bin")
    assert finding is not None
    # 상위 프레임(top-5)을 손으로 정규화
    expected = dedup_key(
        [
            Frame(function="png_read_idat", file="/src/libpng/pngrutil.c:1234:45"),
            Frame(function="png_read_row", file="/src/libpng/pngread.c:456:9"),
            Frame(function="png_read_image", file="/src/libpng/pngread.c:678"),
            Frame(function="LLVMFuzzerTestOneInput", file="/src/harness/libpng_read_fuzzer.cc:90:3"),
            Frame(function="__libc_start_main", file="(/lib/x86_64-linux-gnu/libc.so.6+0x21b96)"),
        ],
        FindingCategory.MEMORY,
    )
    assert finding.dedup_key == expected


def test_same_crash_different_addresses_same_dedup_key() -> None:
    """주소만 다른 두 리포트는 같은 dedup_key (under-dedup 방지)."""
    a = _load("heap_buffer_overflow.txt")
    b = a.replace("0x4a1b2c", "0x9999aa").replace("0x60200000eff0", "0x60200000bbbb")
    fa = finding_from_report(a, target_id="t", reproducer="a.bin")
    fb = finding_from_report(b, target_id="t", reproducer="b.bin")
    assert fa is not None and fb is not None
    assert fa.dedup_key == fb.dedup_key


def test_unrecognized_text_returns_none() -> None:
    assert parse_report("just some random text, not a crash") is None
    assert finding_from_report("nope", target_id="t", reproducer="x") is None
