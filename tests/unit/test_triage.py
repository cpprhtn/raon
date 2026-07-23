"""트리아지 로직 테스트 (02 §4): 증거 가중·충돌해소·exploitability·클러스터링."""

from __future__ import annotations

from raon.contracts import (
    Evidence,
    EvidenceKind,
    Finding,
    FindingCategory,
    SourceComponent,
    TargetDescriptor,
    TargetKind,
)
from raon.llm import MockProvider
from raon.triage.cluster import cluster_by_key, semantic_merge
from raon.triage.exploitability import exploitability_score, rank_findings
from raon.triage.weighting import BASE_BY_KIND, evidence_weight, resolve_cluster


def _finding(
    kind: EvidenceKind,
    category: FindingCategory = FindingCategory.MEMORY,
    confidence: float = 0.9,
    dedup_key: str = "k",
    fid: str = "f",
    reproducer: str | None = None,
    static_path: list[str] | None = None,
) -> Finding:
    if kind == EvidenceKind.DYNAMIC_CRASH:
        ev = Evidence(kind=kind, reproducer=reproducer or "poc.bin")
        src = SourceComponent.FUZZER
    elif kind == EvidenceKind.STATIC_PATH:
        ev = Evidence(kind=kind, static_path=static_path or ["rule", "loc"])
        src = SourceComponent.AGENT_A
    else:
        ev = Evidence(kind=kind)
        src = SourceComponent.AGENT_C
    return Finding(
        id=fid,
        target_id="t",
        category=category,
        evidence=ev,
        confidence=confidence,
        source_component=src,
        dedup_key=dedup_key,
    )


def test_evidence_weight_ordering() -> None:
    dyn = _finding(EvidenceKind.DYNAMIC_CRASH, confidence=1.0)
    stat = _finding(EvidenceKind.STATIC_PATH, confidence=1.0)
    inf = _finding(EvidenceKind.AGENT_INFERENCE, confidence=1.0)
    assert evidence_weight(dyn) == BASE_BY_KIND[EvidenceKind.DYNAMIC_CRASH]
    assert evidence_weight(dyn) > evidence_weight(stat) > evidence_weight(inf)


def test_resolve_cluster_dynamic_dominates() -> None:
    # 동적(낮은 confidence 0.7)이 추론(높은 confidence 0.9)을 여전히 이긴다
    dyn = _finding(EvidenceKind.DYNAMIC_CRASH, confidence=0.7, fid="dyn")
    inf = _finding(EvidenceKind.AGENT_INFERENCE, confidence=0.9, fid="inf")
    assert resolve_cluster([inf, dyn]).id == "dyn"


def test_resolve_empty_raises() -> None:
    import pytest

    with pytest.raises(ValueError, match="empty cluster"):
        resolve_cluster([])


def test_exploitability_memory_gt_logic() -> None:
    mem = _finding(EvidenceKind.DYNAMIC_CRASH, FindingCategory.MEMORY)
    logic = _finding(EvidenceKind.STATIC_PATH, FindingCategory.LOGIC)
    assert exploitability_score(mem) > exploitability_score(logic)


def test_exploitability_reachability_bonus() -> None:
    f = _finding(EvidenceKind.STATIC_PATH, FindingCategory.LOGIC)
    short = TargetDescriptor(id="t", kind=TargetKind.SOURCE_FN, location="x", reachability=["main → f"])
    long = TargetDescriptor(
        id="t", kind=TargetKind.SOURCE_FN, location="x",
        reachability=["a → b → c → d → e → f → g"],
    )
    assert exploitability_score(f, short) > exploitability_score(f, long)


def test_rank_findings_sorts_and_fills() -> None:
    mem = _finding(EvidenceKind.DYNAMIC_CRASH, FindingCategory.MEMORY, dedup_key="m", fid="mem")
    logic = _finding(EvidenceKind.STATIC_PATH, FindingCategory.LOGIC, dedup_key="l", fid="log")
    ranked = rank_findings([logic, mem])
    assert [f.id for f in ranked] == ["mem", "log"]
    assert all(f.exploitability is not None for f in ranked)
    # 원본은 불변
    assert mem.exploitability is None


def test_cluster_by_key_groups() -> None:
    a = _finding(EvidenceKind.DYNAMIC_CRASH, dedup_key="x", fid="a")
    b = _finding(EvidenceKind.DYNAMIC_CRASH, dedup_key="x", fid="b")
    c = _finding(EvidenceKind.DYNAMIC_CRASH, dedup_key="y", fid="c")
    clusters = cluster_by_key([a, b, c])
    assert set(clusters) == {"x", "y"}
    assert len(clusters["x"]) == 2


def test_semantic_merge_combines() -> None:
    # 두 클러스터를 LLM이 하나로 묶음
    a = _finding(EvidenceKind.DYNAMIC_CRASH, dedup_key="k1", fid="a")
    b = _finding(EvidenceKind.DYNAMIC_CRASH, dedup_key="k2", fid="b")
    clusters = cluster_by_key([a, b])
    provider = MockProvider(default_text="[[0,1]]")
    merged = semantic_merge(clusters, provider)
    assert len(merged) == 1
    (members,) = merged.values()
    assert {f.id for f in members} == {"a", "b"}


def test_semantic_merge_fallback_on_garbage() -> None:
    a = _finding(EvidenceKind.DYNAMIC_CRASH, dedup_key="k1", fid="a")
    b = _finding(EvidenceKind.DYNAMIC_CRASH, dedup_key="k2", fid="b")
    clusters = cluster_by_key([a, b])
    provider = MockProvider(default_text="not json at all")
    merged = semantic_merge(clusters, provider)
    assert len(merged) == 2  # 안전 후퇴: 1차 유지


def test_semantic_merge_recovers_missing_indices() -> None:
    a = _finding(EvidenceKind.DYNAMIC_CRASH, dedup_key="k1", fid="a")
    b = _finding(EvidenceKind.DYNAMIC_CRASH, dedup_key="k2", fid="b")
    clusters = cluster_by_key([a, b])
    # LLM이 인덱스 1을 빠뜨림 → 단독 그룹으로 보강
    provider = MockProvider(default_text="[[0]]")
    merged = semantic_merge(clusters, provider)
    assert len(merged) == 2
