"""Magma canary monitor 어댑터 (P0-6/P0-7, D2).

Magma는 실제 CVE를 재주입하고 canary로 **reached/triggered**를 측정한다. 우리는 이 측정을
재구현하지 않고(원칙 2), monitor가 남긴 CSV 스냅샷을 **ground-truth 지표원**으로 소비한다.

## monitor 출력 형식 (research 기준)
캠페인 동안 `$SHARED/monitor/<elapsed_seconds>` 파일들이 쌓인다. 각 파일은 row-format CSV:
- 헤더: `BUG1_R,BUG1_T,BUG2_R,BUG2_T,...`  (bug별 reached/triggered 카운터)
- 데이터: 한 줄의 정수 카운트

`exp2json.py`처럼 스냅샷들을 시간순으로 훑어 bug별 **time-to-reach**(첫 R>0)와
**time-to-trigger**(첫 T>0)를 산출한다. reached = 실행 도달, triggered = 취약 조건 성립.
"""

from __future__ import annotations

import csv
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class MagmaCampaign:
    """한 캠페인의 ground-truth 시계열 요약."""

    reached: dict[str, float] = field(default_factory=dict)  # bug_id → 초 (None 대신 미포함)
    triggered: dict[str, float] = field(default_factory=dict)

    @property
    def bugs_reached(self) -> int:
        return len(self.reached)

    @property
    def bugs_triggered(self) -> int:
        return len(self.triggered)

    def time_to_first_trigger(self) -> float | None:
        """어떤 bug든 최초로 triggered된 시각(time-to-first-crash 근사, 00 §8)."""
        return min(self.triggered.values()) if self.triggered else None


def parse_monitor_row(text: str) -> dict[str, int]:
    """monitor row-format CSV(헤더 + 1 데이터행) → {counter_name: count}."""
    rows = list(csv.reader(text.strip().splitlines()))
    if len(rows) < 2:
        return {}
    header, data = rows[0], rows[1]
    out: dict[str, int] = {}
    for name, value in zip(header, data, strict=False):
        name = name.strip()
        try:
            out[name] = int(value.strip())
        except (ValueError, AttributeError):
            out[name] = 0
    return out


def _bug_and_kind(counter: str) -> tuple[str, str] | None:
    """`PNG001_R` → ('PNG001', 'R'). 형식 안 맞으면 None."""
    if counter.endswith("_R"):
        return counter[:-2], "R"
    if counter.endswith("_T"):
        return counter[:-2], "T"
    return None


def parse_monitor_dir(monitor_dir: str | Path) -> MagmaCampaign:
    """monitor 스냅샷 디렉토리 → MagmaCampaign(bug별 time-to-reach/trigger).

    파일명은 경과 초(정수). 파일 내용은 row-format CSV. 시간순으로 훑어 각 bug의
    R>0 / T>0 최초 시각을 기록한다.
    """
    d = Path(monitor_dir)
    snapshots: list[tuple[int, Path]] = []
    for p in d.iterdir():
        if p.is_file() and p.name.isdigit():
            snapshots.append((int(p.name), p))
    snapshots.sort(key=lambda x: x[0])

    reached: dict[str, float] = {}
    triggered: dict[str, float] = {}
    for elapsed, path in snapshots:
        counts = parse_monitor_row(path.read_text(encoding="utf-8"))
        for counter, count in counts.items():
            if count <= 0:
                continue
            bk = _bug_and_kind(counter)
            if bk is None:
                continue
            bug, kind = bk
            if kind == "R" and bug not in reached:
                reached[bug] = float(elapsed)
            elif kind == "T" and bug not in triggered:
                triggered[bug] = float(elapsed)
    return MagmaCampaign(reached=reached, triggered=triggered)
