"""핵심 평가 지표 (P0-7, 00 §8).

time-to-first-crash · unique bugs · triage FP율 · dedup 정확도 · 비용/버그.
단일 vs 멀티 델타(02 §7)를 재는 도구이기도 하다.

dedup 정확도는 **pairwise 합의**로 측정한다(정답 클러스터 대비): 같은 클러스터에 있어야 할
쌍을 얼마나 맞췄나(recall)와 묶은 쌍이 실제로 같은가(precision)의 F1.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from itertools import combinations

from raon.contracts import Finding

from .magma import MagmaCampaign


@dataclass
class ClusterEval:
    """dedup(클러스터링) 정확도 평가."""

    precision: float
    recall: float
    f1: float


def _pair_set(clusters: Sequence[Sequence[str]]) -> set[frozenset[str]]:
    """클러스터들 → 같은 클러스터에 속한 원소 쌍들의 집합."""
    pairs: set[frozenset[str]] = set()
    for cluster in clusters:
        for a, b in combinations(sorted(set(cluster)), 2):
            pairs.add(frozenset((a, b)))
    return pairs


def dedup_accuracy(
    predicted: Sequence[Sequence[str]],
    gold: Sequence[Sequence[str]],
) -> ClusterEval:
    """예측 클러스터 vs 정답 클러스터의 pairwise precision/recall/F1.

    각 클러스터는 원소 id들의 시퀀스. 모두 singleton이면(쌍 없음) 완벽 일치로 본다.
    """
    pred_pairs = _pair_set(predicted)
    gold_pairs = _pair_set(gold)

    if not pred_pairs and not gold_pairs:
        return ClusterEval(precision=1.0, recall=1.0, f1=1.0)

    tp = len(pred_pairs & gold_pairs)
    precision = tp / len(pred_pairs) if pred_pairs else (1.0 if not gold_pairs else 0.0)
    recall = tp / len(gold_pairs) if gold_pairs else (1.0 if not pred_pairs else 0.0)
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    return ClusterEval(precision=round(precision, 4), recall=round(recall, 4), f1=round(f1, 4))


def false_positive_rate(reported_keys: Sequence[str], true_keys: set[str]) -> float:
    """보고된 unique key 중 정답이 아닌 비율(triage FP율).

    reported_keys는 dedup_key 등 unique 식별자. true_keys는 ground-truth 집합.
    """
    reported = list(dict.fromkeys(reported_keys))  # 중복 제거, 순서 보존
    if not reported:
        return 0.0
    fp = sum(1 for k in reported if k not in true_keys)
    return round(fp / len(reported), 4)


def unique_bug_count(findings: Sequence[Finding]) -> int:
    """서로 다른 dedup_key 수 = unique bug 근사."""
    return len({f.dedup_key for f in findings})


def cost_per_unique_bug(total_cost_usd: float, unique_bugs: int) -> float:
    """비용/버그(달러 per unique bug). unique_bugs=0이면 0."""
    if unique_bugs <= 0:
        return 0.0
    return round(total_cost_usd / unique_bugs, 6)


def time_to_first_trigger(campaign: MagmaCampaign) -> float | None:
    """Magma 캠페인의 time-to-first-crash(첫 triggered 시각)."""
    return campaign.time_to_first_trigger()
