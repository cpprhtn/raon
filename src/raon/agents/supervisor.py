"""Supervisor (Orchestrator) — 진짜 기여 (02 §2, §4).

타겟 우선순위 스케줄링 + 충돌해소 · dedup · exploitability 랭킹.
이게 논문의 심장: "잘 프롬프트된 단일 에이전트를 멀티+오케스트레이션이 이기는가"를
증명하는 지점(02 §7 베이스라인 실험의 B 조건).

Supervisor는 규칙 기반으로 시작하고(결정적, 재현 가능), LLM 심판(semantic dedup)은
provider가 있을 때만 승격 적용한다(느슨한 결합).
"""

from __future__ import annotations

from dataclasses import dataclass, field

from raon.contracts import Finding, KnowledgeBase, TargetDescriptor
from raon.llm import Provider
from raon.triage.cluster import cluster_by_key, semantic_merge
from raon.triage.exploitability import rank_findings
from raon.triage.weighting import resolve_cluster


@dataclass
class TriageResult:
    """트리아지 산출: 랭킹된 대표 Finding들 + 클러스터 맵."""

    representatives: list[Finding] = field(default_factory=list)
    clusters: dict[str, list[Finding]] = field(default_factory=dict)

    @property
    def unique_count(self) -> int:
        return len(self.clusters)


class Supervisor:
    """오케스트레이션: dedup → 충돌해소 → exploitability 랭킹 → 우선순위 스케줄링."""

    def __init__(self, provider: Provider | None = None):
        self._provider = provider

    def triage(
        self,
        findings: list[Finding],
        *,
        targets: dict[str, TargetDescriptor] | None = None,
        semantic: bool = True,
    ) -> TriageResult:
        """이종 Finding들을 병합·충돌해소·랭킹한다.

        1) dedup 1차(dedup_key) → 2) (선택) LLM 의미 병합 →
        3) 클러스터별 대표 선택(증거 가중) → 4) exploitability 랭킹.
        """
        if not findings:
            return TriageResult()

        clusters = cluster_by_key(findings)
        if semantic and self._provider is not None and len(clusters) > 1:
            clusters = semantic_merge(clusters, self._provider)

        reps = [resolve_cluster(members) for members in clusters.values()]
        ranked = rank_findings(reps, targets)
        return TriageResult(representatives=ranked, clusters=clusters)

    def schedule(
        self,
        targets: list[TargetDescriptor],
        *,
        knowledge_bases: list[KnowledgeBase] | None = None,
    ) -> dict[str, float]:
        """타겟별 priority_score(0~1) 산출(규칙 기반 초안).

        - side_effects(heap_alloc/file_write 등)가 있으면 가산 — 메모리 버그 표면.
        - domain_tags가 취약 인터페이스를 가진 KB와 매칭되면 가산(Agent C 신호).
        - 진입 경로가 짧으면 가산(공격면 근접).
        """
        kbs = knowledge_bases or []
        weak_domains = {kb.domain for kb in kbs if kb.known_weak_interfaces}

        scores: dict[str, float] = {}
        for tgt in targets:
            score = 0.5
            if tgt.signature.side_effects:
                score += 0.2
            if any(
                any(tag in kb_domain or kb_domain in tag for kb_domain in weak_domains)
                for tag in tgt.domain_tags
            ):
                score += 0.2
            if tgt.reachability:
                hops = tgt.reachability[0].count("→") + 1
                if hops <= 2:
                    score += 0.1
            scores[tgt.id] = round(min(1.0, score), 4)
        return scores
