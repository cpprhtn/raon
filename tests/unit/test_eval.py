"""자체 평가 벤치 테스트: 요약/표 로직(유닛) + 실제 퍼징(통합)."""

from __future__ import annotations

import pytest

from raon.bench.eval import (
    EVAL_MANIFEST,
    EvalResult,
    run_eval,
    summarize,
    targets_dir,
    to_markdown,
)
from raon.fuzzing.engine import libfuzzer_available


def _r(name, is_buggy, crashed, category, seconds, dedup_key, detected, fp) -> EvalResult:
    return EvalResult(
        name=name, is_buggy=is_buggy, crashed=crashed, error_type="heap-buffer-overflow",
        category=category, seconds=seconds, dedup_key=dedup_key,
        detected=detected, false_positive=fp,
    )


# ---- unit (no clang) -------------------------------------------------------
def test_manifest_targets_exist() -> None:
    for fname, _ in EVAL_MANIFEST:
        assert (targets_dir() / fname).exists(), fname


def test_summarize_counts() -> None:
    results = [
        _r("a.c", True, True, "memory", 1.0, "k1", True, False),
        _r("b.c", True, True, "memory", 3.0, "k2", True, False),
        _r("c.c", True, False, None, None, None, False, False),  # missed
        _r("safe.c", False, False, None, None, None, False, False),
    ]
    s = summarize(results)
    assert s.buggy_targets == 3
    assert s.detected == 2
    assert s.detection_rate == round(2 / 3, 3)
    assert s.unique_bugs == 2
    assert s.false_positives == 0
    assert s.median_seconds == 2.0


def test_summarize_flags_false_positive() -> None:
    results = [_r("safe.c", False, True, "memory", 1.0, "k", False, True)]
    assert summarize(results).false_positives == 1


def test_to_markdown_renders() -> None:
    results = [
        _r("heap_overflow.c", True, True, "memory", 1.2, "k1", True, False),
        _r("safe.c", False, False, None, None, None, False, False),
    ]
    md = to_markdown(results, summarize(results))
    assert "| Target |" in md
    assert "heap_overflow.c" in md
    assert "no crash" in md  # safe target line
    assert "Detection rate" in md


# ---- integration (libFuzzer, Linux/Docker) ---------------------------------
@pytest.mark.integration
@pytest.mark.skipif(not libfuzzer_available(), reason="libFuzzer runtime unavailable")
def test_run_eval_finds_bugs(tmp_path) -> None:
    results = run_eval(max_time_per_target=15, workdir=tmp_path)
    summ = summarize(results)
    # 모든 버그 타겟을 잡아야(4개), safe는 오탐 없어야
    assert summ.detected == summ.buggy_targets == 4
    assert summ.false_positives == 0
    assert summ.unique_bugs >= 3  # 대부분 서로 다른 스택
