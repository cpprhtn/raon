"""벤치 지표 테스트 (P0-7 DoD): Magma monitor 파싱 + 핵심 지표."""

from __future__ import annotations

from pathlib import Path

from raon.bench import (
    cost_per_unique_bug,
    dedup_accuracy,
    false_positive_rate,
    parse_monitor_dir,
    parse_monitor_row,
    time_to_first_trigger,
    unique_bug_count,
)
from raon.contracts import (
    Evidence,
    EvidenceKind,
    Finding,
    FindingCategory,
    SourceComponent,
)

MONITOR_DIR = Path(__file__).parent.parent / "fixtures" / "magma_monitor"


# ---- Magma monitor ---------------------------------------------------------
def test_parse_monitor_row() -> None:
    row = "PNG001_R,PNG001_T\n3,1\n"
    assert parse_monitor_row(row) == {"PNG001_R": 3, "PNG001_T": 1}


def test_parse_monitor_row_empty() -> None:
    assert parse_monitor_row("only_header\n") == {}


def test_parse_monitor_dir_time_series() -> None:
    campaign = parse_monitor_dir(MONITOR_DIR)
    # PNG001: reached@5, triggered@10 ; PNG002: reached@10, never triggered
    assert campaign.reached == {"PNG001": 5.0, "PNG002": 10.0}
    assert campaign.triggered == {"PNG001": 10.0}
    assert campaign.bugs_reached == 2
    assert campaign.bugs_triggered == 1
    assert time_to_first_trigger(campaign) == 10.0


# ---- dedup accuracy --------------------------------------------------------
def test_dedup_accuracy_perfect() -> None:
    gold = [["a", "b"], ["c"]]
    pred = [["a", "b"], ["c"]]
    ev = dedup_accuracy(pred, gold)
    assert ev.precision == 1.0 and ev.recall == 1.0 and ev.f1 == 1.0


def test_dedup_accuracy_under_merge() -> None:
    # 정답은 a,b 한 클러스터인데 예측이 분리 → recall 저하
    gold = [["a", "b"]]
    pred = [["a"], ["b"]]
    ev = dedup_accuracy(pred, gold)
    assert ev.recall == 0.0  # (a,b) 쌍을 못 묶음


def test_dedup_accuracy_over_merge() -> None:
    # 정답은 분리인데 예측이 병합 → precision 저하
    gold = [["a"], ["b"]]
    pred = [["a", "b"]]
    ev = dedup_accuracy(pred, gold)
    assert ev.precision == 0.0


def test_dedup_accuracy_all_singletons() -> None:
    ev = dedup_accuracy([["a"], ["b"]], [["a"], ["b"]])
    assert ev.f1 == 1.0


# ---- FP rate & counts ------------------------------------------------------
def test_false_positive_rate() -> None:
    reported = ["k1", "k2", "k3"]
    true = {"k1", "k2"}
    assert false_positive_rate(reported, true) == round(1 / 3, 4)


def test_false_positive_rate_empty() -> None:
    assert false_positive_rate([], {"k"}) == 0.0


def _f(dedup_key: str) -> Finding:
    return Finding(
        target_id="t",
        category=FindingCategory.MEMORY,
        evidence=Evidence(kind=EvidenceKind.DYNAMIC_CRASH, reproducer="p"),
        source_component=SourceComponent.FUZZER,
        dedup_key=dedup_key,
    )


def test_unique_bug_count() -> None:
    assert unique_bug_count([_f("x"), _f("x"), _f("y")]) == 2


def test_cost_per_unique_bug() -> None:
    assert cost_per_unique_bug(1.50, 3) == 0.5
    assert cost_per_unique_bug(1.0, 0) == 0.0
