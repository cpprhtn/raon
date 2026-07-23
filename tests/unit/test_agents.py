"""에이전트 + Supervisor 테스트 (02): A/B/C 생산 + 오케스트레이션."""

from __future__ import annotations

from pathlib import Path

from raon.agents import AgentA, AgentB, AgentC, Supervisor
from raon.contracts import (
    EvidenceKind,
    FindingCategory,
    Signature,
    SourceComponent,
    TargetDescriptor,
    TargetKind,
)
from raon.knowledge import png_knowledge_base
from raon.llm import MockProvider

FIXTURES = Path(__file__).parent.parent / "fixtures" / "sanitizer"


# ---- Agent B ---------------------------------------------------------------
def test_agent_b_triage_produces_finding() -> None:
    report = (FIXTURES / "heap_buffer_overflow.txt").read_text(encoding="utf-8")
    b = AgentB()
    finding = b.triage(report, target_id="tgt_libpng", reproducer="poc.bin")
    assert finding is not None
    assert finding.source_component == SourceComponent.AGENT_B
    assert finding.category == FindingCategory.MEMORY
    assert finding.confidence == 0.95


def test_agent_b_root_cause_summary() -> None:
    report = (FIXTURES / "heap_buffer_overflow.txt").read_text(encoding="utf-8")
    provider = MockProvider(default_text="png_read_idat에서 힙 경계 초과 읽기")
    b = AgentB(provider)
    summary = b.root_cause_summary(report)
    assert summary is not None and "png_read_idat" in summary


def test_agent_b_no_provider_no_summary() -> None:
    report = (FIXTURES / "heap_buffer_overflow.txt").read_text(encoding="utf-8")
    assert AgentB().root_cause_summary(report) is None


# ---- Agent C ---------------------------------------------------------------
def _png_target() -> TargetDescriptor:
    return TargetDescriptor(
        id="tgt_png",
        kind=TargetKind.SOURCE_FN,
        location="png_read_idat",
        signature=Signature(returns="void", side_effects=["heap_alloc"]),
        domain_tags=["image", "png"],
    )


def test_agent_c_hypotheses_without_provider() -> None:
    kb = png_knowledge_base()
    c = AgentC()
    findings = c.hypothesize(_png_target(), kb)
    # KB의 모든 취약 인터페이스에 대해 낮은 confidence 가설
    assert len(findings) == len(kb.known_weak_interfaces)
    assert all(f.evidence.kind == EvidenceKind.AGENT_INFERENCE for f in findings)
    assert all(f.confidence == 0.3 for f in findings)


def test_agent_c_llm_filters_none() -> None:
    kb = png_knowledge_base()
    provider = MockProvider(default_text="NONE")
    c = AgentC(provider)
    findings = c.hypothesize(_png_target(), kb)
    assert findings == []  # LLM이 전부 무관하다고 판정


def test_agent_c_llm_accepts() -> None:
    kb = png_knowledge_base()
    provider = MockProvider(default_text="이 함수는 idat 경계를 다뤄 위험하다")
    c = AgentC(provider)
    findings = c.hypothesize(_png_target(), kb)
    assert len(findings) == len(kb.known_weak_interfaces)


# ---- Agent A ---------------------------------------------------------------
def test_agent_a_with_injected_semgrep() -> None:
    def fake_runner(path: str) -> list[dict]:
        return [
            {
                "check_id": "c.buffer-overflow",
                "path": "src/decode.c",
                "start": {"line": 42},
                "extra": {"message": "possible buffer overflow", "severity": "ERROR"},
            }
        ]

    a = AgentA(semgrep_runner=fake_runner)
    findings = a.analyze("src/decode.c", target_id="tgt_x")
    assert len(findings) == 1
    f = findings[0]
    assert f.source_component == SourceComponent.AGENT_A
    assert f.evidence.kind == EvidenceKind.STATIC_PATH
    assert f.category == FindingCategory.MEMORY  # 'buffer'/'overflow' 힌트


def test_agent_a_empty_when_no_results() -> None:
    a = AgentA(semgrep_runner=lambda p: [])
    assert a.analyze("x", target_id="t") == []


# ---- Supervisor ------------------------------------------------------------
def test_supervisor_triage_ranks_dynamic_first() -> None:
    report = (FIXTURES / "heap_buffer_overflow.txt").read_text(encoding="utf-8")
    b = AgentB()
    dyn = b.triage(report, target_id="t", reproducer="poc.bin", finding_id="dyn")
    assert dyn is not None

    a = AgentA(semgrep_runner=lambda p: [
        {"check_id": "logic.x", "path": "a.c", "start": {"line": 1}, "extra": {"message": "logic bug"}}
    ])
    static = a.analyze("a.c", target_id="t")

    sup = Supervisor()  # provider 없음 → 규칙 기반(결정적)
    result = sup.triage([*static, dyn])
    assert result.unique_count == 2
    # 동적 메모리 크래시가 최상위(exploitability + 가중치)
    assert result.representatives[0].id == "dyn"
    assert result.representatives[0].exploitability is not None


def test_supervisor_dedup_collapses_duplicates() -> None:
    report = (FIXTURES / "heap_buffer_overflow.txt").read_text(encoding="utf-8")
    b = AgentB()
    f1 = b.triage(report, target_id="t", reproducer="a.bin", finding_id="f1")
    f2 = b.triage(report, target_id="t", reproducer="b.bin", finding_id="f2")
    assert f1 is not None and f2 is not None
    sup = Supervisor()
    result = sup.triage([f1, f2])
    # 같은 크래시 → 한 클러스터
    assert result.unique_count == 1
    assert len(result.representatives) == 1


def test_supervisor_schedule_priority() -> None:
    kb = png_knowledge_base()
    heavy = TargetDescriptor(
        id="heavy", kind=TargetKind.SOURCE_FN, location="x",
        signature=Signature(side_effects=["heap_alloc"]),
        domain_tags=["png"], reachability=["main → decode"],
    )
    light = TargetDescriptor(id="light", kind=TargetKind.MODULE, location="y")
    scores = Supervisor().schedule([heavy, light], knowledge_bases=[kb])
    assert scores["heavy"] > scores["light"]
    assert 0.0 <= scores["light"] <= 1.0
