"""공유 계약 4종의 왕복 직렬화·검증 테스트 (P0-1 DoD)."""

from __future__ import annotations

import json

import pytest
from pydantic import ValidationError

from raon.contracts import (
    SCHEMA_VERSION,
    Corpus,
    Coverage,
    Evidence,
    EvidenceKind,
    Finding,
    FindingCategory,
    KnowledgeBase,
    Param,
    Signature,
    SourceComponent,
    StuckBranch,
    TargetDescriptor,
    TargetKind,
)


def _roundtrip(model: object) -> None:
    """model → JSON → model 이 동일 데이터를 복원하는지."""
    cls = type(model)
    dumped = model.model_dump_json()  # type: ignore[attr-defined]
    restored = cls.model_validate_json(dumped)  # type: ignore[attr-defined]
    assert restored == model


def test_target_descriptor_roundtrip() -> None:
    tgt = TargetDescriptor(
        kind=TargetKind.SOURCE_FN,
        location="src/decode.c:142",
        signature=Signature(
            params=[Param(name="buf", type="uint8_t*"), Param(name="len", type="size_t")],
            returns="int",
            side_effects=["heap_alloc", "file_write"],
        ),
        reachability=["main → parse_header → decode"],
        domain_tags=["image", "file_parser"],
    )
    assert tgt.id.startswith("tgt_")
    assert tgt.priority_score == 0.0
    assert tgt.schema_version == SCHEMA_VERSION
    _roundtrip(tgt)


def test_corpus_roundtrip() -> None:
    corpus = Corpus(
        target_id="tgt_00123",
        seeds=["corpus/seed_0001.bin"],
        coverage=Coverage(edges_hit=8123, frontier=["e8124", "e8125"]),
        stuck_branches=[StuckBranch(loc="decode.c:210", reason="magic_bytes_check")],
    )
    _roundtrip(corpus)


def test_finding_dynamic_crash_roundtrip() -> None:
    f = Finding(
        target_id="tgt_00123",
        category=FindingCategory.MEMORY,
        evidence=Evidence(
            kind=EvidenceKind.DYNAMIC_CRASH,
            reproducer="crashes/poc_0007.bin",
            sanitizer_report="AddressSanitizer: heap-buffer-overflow ...",
        ),
        coverage_context="tgt_00123 @ edge 8102",
        confidence=0.95,
        source_component=SourceComponent.FUZZER,
        dedup_key="deadbeef",
    )
    assert f.exploitability is None
    _roundtrip(f)


def test_knowledgebase_roundtrip() -> None:
    kb = KnowledgeBase(
        domain="image/png",
        grammar="png.g4",
        seed_templates=["templates/min.png"],
        invariants=["chunk_len ≤ remaining_bytes", "CRC matches"],
        known_weak_interfaces=["idat inflate 경계"],
    )
    _roundtrip(kb)


def test_evidence_dynamic_crash_requires_reproducer() -> None:
    with pytest.raises(ValidationError):
        Evidence(kind=EvidenceKind.DYNAMIC_CRASH)  # reproducer 없음


def test_evidence_static_path_requires_path() -> None:
    with pytest.raises(ValidationError):
        Evidence(kind=EvidenceKind.STATIC_PATH)  # static_path 비어 있음


def test_extra_fields_forbidden() -> None:
    with pytest.raises(ValidationError):
        KnowledgeBase(domain="x", bogus_field=1)  # type: ignore[call-arg]


def test_priority_score_bounds() -> None:
    with pytest.raises(ValidationError):
        TargetDescriptor(kind=TargetKind.MODULE, location="x", priority_score=1.5)


def test_confidence_bounds() -> None:
    with pytest.raises(ValidationError):
        Finding(
            target_id="t",
            category=FindingCategory.LOGIC,
            evidence=Evidence(kind=EvidenceKind.AGENT_INFERENCE),
            confidence=2.0,
            source_component=SourceComponent.INTERFACE_INFERENCE,
            dedup_key="k",
        )


def test_enum_values_serialize_as_strings() -> None:
    f = Finding(
        target_id="t",
        category=FindingCategory.UNDEFINED_BEHAVIOR,
        evidence=Evidence(kind=EvidenceKind.AGENT_INFERENCE),
        source_component=SourceComponent.INTERFACE_INFERENCE,
        dedup_key="k",
    )
    data = json.loads(f.model_dump_json())
    assert data["category"] == "undefined_behavior"
    assert data["evidence"]["kind"] == "agent_inference"
    assert data["source_component"] == "interface_inference"


def test_validate_assignment() -> None:
    tgt = TargetDescriptor(kind=TargetKind.MODULE, location="x")
    with pytest.raises(ValidationError):
        tgt.priority_score = 5.0  # 대입도 검증
