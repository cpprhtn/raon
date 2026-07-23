"""벤치마크 & 평가 (00 §8, 05 P0-5/P0-7).

Magma canary monitor를 ground-truth 지표원으로 소비(재구현 금지, 원칙 2 연장).
핵심 지표: time-to-first-crash · unique bugs · triage FP율 · dedup 정확도 · 비용/버그.
"""

from __future__ import annotations

from .magma import MagmaCampaign, parse_monitor_dir, parse_monitor_row
from .metrics import (
    ClusterEval,
    cost_per_unique_bug,
    dedup_accuracy,
    false_positive_rate,
    time_to_first_trigger,
    unique_bug_count,
)

__all__ = [
    "MagmaCampaign",
    "parse_monitor_dir",
    "parse_monitor_row",
    "ClusterEval",
    "dedup_accuracy",
    "false_positive_rate",
    "time_to_first_trigger",
    "unique_bug_count",
    "cost_per_unique_bug",
]
