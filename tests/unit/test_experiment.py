"""단일 vs 멀티에이전트 트리아지 델타 실험 테스트."""

from __future__ import annotations

import pytest

from raon.bench.experiment import ExperimentResult, _baseline_key, run_experiment
from raon.bench.metrics import ClusterEval
from raon.fuzzing.engine import clang_path


# ---- unit ------------------------------------------------------------------
def test_baseline_key_sensitive_to_addresses() -> None:
    a = "ERROR: heap-buffer-overflow ... 0xAAAA in f /x.c:1"
    b = "ERROR: heap-buffer-overflow ... 0xBBBB in f /x.c:1"
    # 원문 전체 해시라 주소만 달라도 다른 키(=baseline이 과다계수하는 이유)
    assert _baseline_key(a) != _baseline_key(b)
    assert _baseline_key(a) == _baseline_key(a)


def test_result_markdown_renders() -> None:
    r = ExperimentResult(
        gold_unique=4, baseline_unique=12, raon_unique=4,
        baseline_eval=ClusterEval(0.0, 0.0, 0.0),
        raon_eval=ClusterEval(1.0, 1.0, 1.0),
        total_findings=12,
    )
    md = r.to_markdown()
    assert "Baseline" in md and "raon" in md
    assert "Ground truth: 4 unique bugs" in md


# ---- integration (clang + ASan; runs on macOS too) -------------------------
@pytest.mark.integration
@pytest.mark.skipif(clang_path() is None, reason="clang required")
def test_experiment_orchestration_beats_baseline(tmp_path) -> None:
    r = run_experiment(workdir=tmp_path)
    # raon은 gold와 정확히 일치해야
    assert r.gold_unique == 4
    assert r.raon_unique == r.gold_unique
    assert r.raon_eval.f1 == 1.0
    # baseline은 과다계수(또는 최소한 raon보다 나쁘지 않게) — 정규화의 가치
    assert r.baseline_unique >= r.raon_unique
    assert r.baseline_eval.f1 <= r.raon_eval.f1
