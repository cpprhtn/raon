"""이종 증거 병합 — 충돌해소 (02 §4.2).

동적 크래시(재현 가능=최강) vs 정적 추론(가설)을 어떤 가중치로 합치나?
`weight = base_by_kind(evidence.kind) × confidence`. 동적 재현자가 있으면 다른 의견을 압도.

이건 논문의 심장 중 하나(00 §10.2 열린 질문). 가중치 상수는 P3에서 Magma canary로 튜닝한다(D6).
"""

from __future__ import annotations

from raon.contracts import EvidenceKind, Finding

# 증거 종류별 기본 가중치 (02 §4.2 초안).
BASE_BY_KIND: dict[EvidenceKind, float] = {
    EvidenceKind.DYNAMIC_CRASH: 1.0,  # 재현 가능 = 최강
    EvidenceKind.STATIC_PATH: 0.6,
    EvidenceKind.AGENT_INFERENCE: 0.3,  # 가설
}


def evidence_weight(finding: Finding) -> float:
    """Finding의 병합 가중치. base_by_kind × confidence."""
    base = BASE_BY_KIND.get(finding.evidence.kind, 0.3)
    return base * finding.confidence


def resolve_cluster(findings: list[Finding]) -> Finding:
    """한 클러스터(같은 버그로 판단된 Finding들)에서 대표 하나를 선택.

    가중치 최대를 대표로. 동적 재현자가 있으면 사실상 항상 그것이 이긴다
    (base 1.0 × 높은 confidence). 빈 리스트는 호출자가 막아야 한다.
    """
    if not findings:
        raise ValueError("cannot resolve an empty cluster")
    return max(findings, key=evidence_weight)


def has_dynamic_evidence(findings: list[Finding]) -> bool:
    """클러스터에 동적 크래시 증거가 있는가 (추론 승격 판단에 사용, D10)."""
    return any(f.evidence.kind == EvidenceKind.DYNAMIC_CRASH for f in findings)
