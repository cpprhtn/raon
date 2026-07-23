"""중복제거 (02 §4.1).

- **1차**: `dedup_key`(정규화 스택 + 카테고리) 기준 클러스터링 — 결정적, LLM 불필요.
- **2차**: 스택은 다르지만 같은 root cause인 클러스터를 LLM 의미 클러스터링으로 병합.

2차는 선택적이며 LLM 실패/미사용 시 1차 결과로 안전하게 후퇴한다(느슨한 결합).
"""

from __future__ import annotations

import json
import re

from raon.contracts import Finding
from raon.llm import LLMRequest, Message, ModelTier, Provider

_JSON_ARRAY_RE = re.compile(r"\[.*\]", re.DOTALL)


def cluster_by_key(findings: list[Finding]) -> dict[str, list[Finding]]:
    """1차 클러스터링: dedup_key → Finding[]. 삽입 순서 보존."""
    clusters: dict[str, list[Finding]] = {}
    for f in findings:
        clusters.setdefault(f.dedup_key, []).append(f)
    return clusters


def _representatives(clusters: dict[str, list[Finding]]) -> list[tuple[str, Finding]]:
    """각 클러스터의 대표(첫 Finding)와 그 key."""
    return [(key, group[0]) for key, group in clusters.items()]


def _build_merge_prompt(reps: list[tuple[str, Finding]]) -> str:
    lines = [
        "다음은 서로 다른 크래시 클러스터의 대표들이다. 스택은 다르지만 **같은 근본 원인**",
        "(root cause)인 클러스터끼리 묶어라. 각 항목은 [index] category / sanitizer 요약이다.",
        "",
    ]
    for i, (_key, f) in enumerate(reps):
        report = (f.evidence.sanitizer_report or "").strip().splitlines()
        summary = report[0] if report else f.category.value
        lines.append(f"[{i}] {f.category.value} :: {summary[:200]}")
    lines += [
        "",
        "출력: 같은 root cause 인덱스들을 묶은 JSON 2차원 배열만. 예: [[0,2],[1]]",
        "확신이 없으면 각자 단독 그룹으로 두라(과병합 금지).",
    ]
    return "\n".join(lines)


def _parse_groups(text: str, n: int) -> list[list[int]] | None:
    """LLM 응답에서 JSON 2차원 배열을 추출·검증. 실패 시 None."""
    m = _JSON_ARRAY_RE.search(text)
    if not m:
        return None
    try:
        groups = json.loads(m.group(0))
    except json.JSONDecodeError:
        return None
    if not isinstance(groups, list):
        return None
    seen: set[int] = set()
    norm: list[list[int]] = []
    for g in groups:
        if not isinstance(g, list):
            return None
        idxs = [i for i in g if isinstance(i, int) and 0 <= i < n]
        if not idxs:
            continue
        if seen & set(idxs):  # 인덱스 중복 → 신뢰 불가
            return None
        seen.update(idxs)
        norm.append(idxs)
    # 누락된 인덱스는 단독 그룹으로 보강(정보 손실 방지)
    for i in range(n):
        if i not in seen:
            norm.append([i])
    return norm


def semantic_merge(
    clusters: dict[str, list[Finding]],
    provider: Provider,
    *,
    tier: ModelTier = ModelTier.PREMIUM,
) -> dict[str, list[Finding]]:
    """2차 의미 병합. LLM이 같은 root cause 클러스터를 묶는다.

    반환은 병합된 클러스터(대표 클러스터의 key 유지). LLM 응답이 파싱 불가하면
    1차 클러스터를 그대로 반환(안전 후퇴).
    """
    if len(clusters) <= 1:
        return clusters

    reps = _representatives(clusters)
    prompt = _build_merge_prompt(reps)
    messages: list[Message] = [{"role": "user", "content": prompt}]
    resp = provider.complete(
        LLMRequest(messages=messages, tier=tier, purpose="semantic_dedup", effort="high")
    )
    groups = _parse_groups(resp.text, len(reps))
    if groups is None:
        return clusters  # 후퇴

    merged: dict[str, list[Finding]] = {}
    for group in groups:
        canonical_key = reps[group[0]][0]
        combined: list[Finding] = []
        for idx in group:
            key = reps[idx][0]
            combined.extend(clusters[key])
        merged[canonical_key] = combined
    return merged
