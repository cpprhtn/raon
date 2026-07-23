"""블랙보드 저장소 테스트 (P0-3 DoD): CRUD, dedup 쿼리, 동시성."""

from __future__ import annotations

import threading
from pathlib import Path

from raon.contracts import (
    Corpus,
    Coverage,
    Evidence,
    EvidenceKind,
    Finding,
    FindingCategory,
    KnowledgeBase,
    SourceComponent,
    TargetDescriptor,
    TargetKind,
)
from raon.store import Blackboard
from raon.triage.dedup import Frame, dedup_key


def _crash_finding(target_id: str, funcs: list[str], fid: str) -> Finding:
    frames = [Frame(function=f) for f in funcs]
    return Finding(
        id=fid,
        target_id=target_id,
        category=FindingCategory.MEMORY,
        evidence=Evidence(kind=EvidenceKind.DYNAMIC_CRASH, reproducer=f"crashes/{fid}.bin"),
        confidence=0.9,
        source_component=SourceComponent.FUZZER,
        dedup_key=dedup_key(frames, FindingCategory.MEMORY),
    )


def test_target_crud_and_priority() -> None:
    with Blackboard() as bb:
        tgt = TargetDescriptor(id="tgt_1", kind=TargetKind.SOURCE_FN, location="a.c:1")
        bb.put_target(tgt)
        assert bb.get_target("tgt_1") == tgt
        bb.set_priority("tgt_1", 0.7)
        assert bb.get_target("tgt_1").priority_score == 0.7  # type: ignore[union-attr]


def test_target_priority_ordering() -> None:
    with Blackboard() as bb:
        bb.put_target(TargetDescriptor(id="tgt_lo", kind=TargetKind.MODULE, location="x", priority_score=0.1))
        bb.put_target(TargetDescriptor(id="tgt_hi", kind=TargetKind.MODULE, location="y", priority_score=0.9))
        ordered = bb.list_targets(by_priority=True)
        assert [t.id for t in ordered] == ["tgt_hi", "tgt_lo"]


def test_corpus_roundtrip() -> None:
    with Blackboard() as bb:
        c = Corpus(target_id="tgt_1", seeds=["s0.bin"], coverage=Coverage(edges_hit=10))
        bb.put_corpus(c)
        assert bb.get_corpus("tgt_1") == c
        assert bb.get_corpus("missing") is None


def test_finding_crud() -> None:
    with Blackboard() as bb:
        f = _crash_finding("tgt_1", ["a", "b"], "find_1")
        bb.put_finding(f)
        assert bb.get_finding("find_1") == f
        assert bb.list_findings(target_id="tgt_1") == [f]


def test_dedup_clustering() -> None:
    with Blackboard() as bb:
        # 두 크래시가 같은 스택 → 같은 dedup_key → 한 클러스터
        f1 = _crash_finding("tgt_1", ["png_read", "decode"], "find_1")
        f2 = _crash_finding("tgt_1", ["png_read", "decode"], "find_2")
        # 다른 스택 → 다른 클러스터
        f3 = _crash_finding("tgt_1", ["png_read", "inflate"], "find_3")
        for f in (f1, f2, f3):
            bb.put_finding(f)

        assert bb.count_unique_findings() == 2
        clusters = bb.clusters()
        assert len(clusters) == 2
        assert len(bb.findings_by_dedup_key(f1.dedup_key)) == 2
        assert len(bb.findings_by_dedup_key(f3.dedup_key)) == 1


def test_knowledge_and_tag_matching() -> None:
    with Blackboard() as bb:
        kb = KnowledgeBase(domain="image/png", grammar="png.g4")
        bb.put_knowledge(kb)
        assert bb.get_knowledge("image/png") == kb
        matched = bb.knowledge_for_tags(["png"])
        assert len(matched) == 1 and matched[0].domain == "image/png"
        assert bb.knowledge_for_tags(["audio"]) == []


def test_persistence_across_reopen(tmp_path: Path) -> None:
    db = tmp_path / "bb.sqlite"
    tgt = TargetDescriptor(id="tgt_p", kind=TargetKind.MODULE, location="z")
    with Blackboard(db) as bb:
        bb.put_target(tgt)
    # 재오픈해도 데이터가 남아 있어야
    with Blackboard(db) as bb2:
        assert bb2.get_target("tgt_p") == tgt


def test_wal_mode_enabled(tmp_path: Path) -> None:
    db = tmp_path / "bb.sqlite"
    with Blackboard(db) as bb:
        mode = bb._conn.execute("PRAGMA journal_mode").fetchone()[0]  # noqa: SLF001
        assert mode.lower() == "wal"


def test_concurrent_reads_during_writes(tmp_path: Path) -> None:
    """단일 라이터 + 다중 리더 스트레스: 손상/예외 없이 완료되는가(D8)."""
    db = tmp_path / "bb.sqlite"
    with Blackboard(db) as bb:
        bb.put_target(TargetDescriptor(id="tgt_1", kind=TargetKind.MODULE, location="x"))
        errors: list[Exception] = []
        stop = threading.Event()

        def writer() -> None:
            try:
                for i in range(100):
                    bb.put_finding(_crash_finding("tgt_1", [f"f{i}"], f"find_{i}"))
            except Exception as e:  # noqa: BLE001
                errors.append(e)
            finally:
                stop.set()

        def reader() -> None:
            try:
                while not stop.is_set():
                    bb.list_findings()
                    bb.count_unique_findings()
            except Exception as e:  # noqa: BLE001
                errors.append(e)

        threads = [threading.Thread(target=writer)] + [
            threading.Thread(target=reader) for _ in range(3)
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=30)

        assert not errors, f"concurrency errors: {errors}"
        assert bb.count_unique_findings() == 100
