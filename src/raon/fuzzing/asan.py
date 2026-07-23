"""Sanitizer 리포트 파서 (P1-3, 01 §5, 02 §3 Agent B).

ASan/UBSan/LSan/TSan 출력을 파싱해 구조화하고 `Finding`으로 정규화한다.
‼️ 새니타이저 로직을 재구현하지 않는다(원칙 2) — *출력을 해석*할 뿐이다.

파서는 순수 텍스트 처리라 fixture로 독립 검증된다(웨이브 1 병렬 후보).
스택 프레임은 `raon.triage.dedup.Frame`으로 넘겨 dedup_key를 만든다.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from raon.contracts import Evidence, EvidenceKind, Finding, FindingCategory, SourceComponent
from raon.triage.dedup import Frame, dedup_key

# ==== 에러 종류 → 카테고리 매핑 ==========================================
# ASan 메모리 에러들 → memory
_MEMORY_ERRORS = {
    "heap-buffer-overflow",
    "stack-buffer-overflow",
    "global-buffer-overflow",
    "heap-use-after-free",
    "stack-use-after-return",
    "stack-use-after-scope",
    "use-after-poison",
    "double-free",
    "bad-free",
    "alloc-dealloc-mismatch",
    "memcpy-param-overlap",
    "negative-size-param",
    "SEGV",
    "stack-overflow",
    "detected-memory-leaks",  # LeakSanitizer
}

# ASan 에러 종류를 잡는 정규식 (`AddressSanitizer: <type>`)
_ASAN_RE = re.compile(r"(?:AddressSanitizer|ERROR):\s*(?:AddressSanitizer:\s*)?([a-zA-Z-]+)")
_ASAN_SUMMARY_RE = re.compile(r"SUMMARY:\s*AddressSanitizer:\s*([a-zA-Z-]+)")
_LEAK_RE = re.compile(r"LeakSanitizer:\s*detected memory leaks")
_UBSAN_RE = re.compile(r"runtime error:\s*(.+)")
_TSAN_RE = re.compile(r"ThreadSanitizer:\s*([a-z ]+)")

# 스택 프레임: `    #0 0x... in <rest>`
_FRAME_RE = re.compile(r"^\s*#(\d+)\s+0x[0-9a-fA-F]+\s+in\s+(?P<rest>.+?)\s*$")
# `    #2 0x... (/lib/libc.so.6+0x1234)` — 심볼 없는 프레임
_FRAME_NOSYM_RE = re.compile(r"^\s*#(\d+)\s+0x[0-9a-fA-F]+\s+(?P<mod>\(.+\))\s*$")

_LOCATION_HINT = re.compile(r"[/\\]|:\d+|^\(")


@dataclass
class ParsedReport:
    """파싱된 새니타이저 리포트."""

    error_type: str
    category: FindingCategory
    frames: list[Frame] = field(default_factory=list)
    raw: str = ""


def _looks_like_location(token: str) -> bool:
    return bool(_LOCATION_HINT.search(token))


def _parse_frame(line: str) -> Frame | None:
    """한 줄에서 스택 프레임을 파싱. 프레임이 아니면 None."""
    nosym = _FRAME_NOSYM_RE.match(line)
    if nosym:
        return Frame(function=None, file=nosym.group("mod").strip("()"))

    m = _FRAME_RE.match(line)
    if not m:
        return None
    rest = m.group("rest").strip()
    if rest.startswith("("):
        return Frame(function=None, file=rest.strip("()"))
    # "func_name /path/file.c:line:col" 를 함수와 위치로 분리
    parts = rest.rsplit(" ", 1)
    if len(parts) == 2 and _looks_like_location(parts[1]):
        return Frame(function=parts[0].strip(), file=parts[1].strip())
    return Frame(function=rest, file=None)


def _classify(text: str) -> tuple[str, FindingCategory] | None:
    """리포트 텍스트에서 (error_type, category)를 판정."""
    # UBSan
    ub = _UBSAN_RE.search(text)
    if ub:
        # "signed integer overflow: ..." → 첫 구절을 타입으로
        detail = ub.group(1).strip()
        etype = detail.split(":")[0].strip()
        return etype, FindingCategory.UNDEFINED_BEHAVIOR

    # LeakSanitizer
    if _LEAK_RE.search(text):
        return "detected-memory-leaks", FindingCategory.MEMORY

    # ThreadSanitizer (data race 등은 C/C++에서 UB)
    ts = _TSAN_RE.search(text)
    if ts:
        return ts.group(1).strip().replace(" ", "-"), FindingCategory.UNDEFINED_BEHAVIOR

    # AddressSanitizer — SUMMARY 우선(가장 신뢰), 없으면 ERROR 라인
    summ = _ASAN_SUMMARY_RE.search(text)
    etype = None
    if summ:
        etype = summ.group(1)
    else:
        m = re.search(r"AddressSanitizer:\s*([a-zA-Z-]+)", text)
        if m:
            etype = m.group(1)
    if etype:
        category = (
            FindingCategory.MEMORY
            if etype in _MEMORY_ERRORS
            else FindingCategory.UNDEFINED_BEHAVIOR
        )
        return etype, category
    return None


def parse_report(text: str) -> ParsedReport | None:
    """새니타이저 리포트 텍스트 → ParsedReport. 인식 실패 시 None."""
    classified = _classify(text)
    if classified is None:
        return None
    error_type, category = classified

    frames: list[Frame] = []
    for line in text.splitlines():
        fr = _parse_frame(line)
        if fr is not None:
            frames.append(fr)

    return ParsedReport(error_type=error_type, category=category, frames=frames, raw=text)


def finding_from_report(
    text: str,
    *,
    target_id: str,
    reproducer: str,
    source_component: SourceComponent = SourceComponent.FUZZER,
    confidence: float = 0.95,
    coverage_context: str | None = None,
    finding_id: str | None = None,
) -> Finding | None:
    """새니타이저 리포트 → 정규화된 Finding(동적 크래시).

    동적 재현자가 있으므로 confidence를 높게 둔다(02 §4.2 증거 가중: dynamic_crash=1.0).
    dedup_key는 정규화 스택 + 카테고리로 계산.
    """
    parsed = parse_report(text)
    if parsed is None:
        return None

    key = dedup_key(parsed.frames, parsed.category)
    evidence = Evidence(
        kind=EvidenceKind.DYNAMIC_CRASH,
        reproducer=reproducer,
        sanitizer_report=text,
    )
    kwargs = {
        "target_id": target_id,
        "category": parsed.category,
        "evidence": evidence,
        "confidence": confidence,
        "source_component": source_component,
        "dedup_key": key,
        "coverage_context": coverage_context,
    }
    if finding_id is not None:
        kwargs["id"] = finding_id
    return Finding(**kwargs)
