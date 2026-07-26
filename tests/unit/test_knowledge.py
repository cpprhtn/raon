"""KnowledgeBase 테스트 (P0-8 DoD): 스키마 검증 + [01]/[02] 소비 가능."""

from __future__ import annotations

import struct
import zlib
from pathlib import Path

from raon.contracts import KnowledgeBase
from raon.knowledge import (
    builtin_knowledge_bases,
    minimal_png,
    png_knowledge_base,
    register_builtins,
    write_seed_templates,
)
from raon.knowledge.png import PNG_SIGNATURE
from raon.store import Blackboard


def test_png_kb_valid_schema() -> None:
    kb = png_knowledge_base()
    assert isinstance(kb, KnowledgeBase)
    assert kb.domain == "image/png"
    assert kb.invariants
    assert kb.known_weak_interfaces  # Agent C 근거


def test_minimal_png_is_valid() -> None:
    data = minimal_png()
    assert data.startswith(PNG_SIGNATURE)
    # IHDR 청크 파싱: 시그니처(8) 뒤 length(4)+type(4)
    length = struct.unpack(">I", data[8:12])[0]
    assert data[12:16] == b"IHDR"
    assert length == 13  # IHDR 데이터는 항상 13바이트
    # CRC 검증(마지막 청크 IEND)
    assert data.endswith(struct.pack(">I", zlib.crc32(b"IEND") & 0xFFFFFFFF))


def test_write_seed_templates(tmp_path: Path) -> None:
    paths = write_seed_templates(tmp_path)
    assert len(paths) == 1
    p = Path(paths[0])
    assert p.exists()
    assert p.read_bytes().startswith(PNG_SIGNATURE)


def test_register_builtins_into_blackboard() -> None:
    with Blackboard() as bb:
        register_builtins(bb)
        kb = bb.get_knowledge("image/png")
        assert kb is not None
        # 타겟의 domain_tags와 매칭되는지(00 §3.1 연결)
        matched = bb.knowledge_for_tags(["png"])
        assert any(k.domain == "image/png" for k in matched)


def test_builtin_list_has_png_and_json() -> None:
    domains = {kb.domain for kb in builtin_knowledge_bases()}
    assert "image/png" in domains
    assert "text/json" in domains


def test_json_kb_valid_and_seeds_parse() -> None:
    import json as _json

    from raon.knowledge.json_pack import JSON_SEEDS, json_knowledge_base

    kb = json_knowledge_base()
    assert kb.domain == "text/json"
    assert kb.known_weak_interfaces
    # 시드가 실제로 유효한 JSON이어야(구조 인지 시드 프라이밍 전제)
    for seed in JSON_SEEDS:
        _json.loads(seed.decode("utf-8"))


def test_json_write_seed_templates(tmp_path) -> None:
    from raon.knowledge.json_pack import write_seed_templates

    paths = write_seed_templates(tmp_path)
    assert paths and (tmp_path / "min.json").exists()


def test_json_kb_registered_in_blackboard() -> None:
    with Blackboard() as bb:
        register_builtins(bb)
        assert bb.get_knowledge("text/json") is not None
        assert bb.knowledge_for_tags(["json"])
