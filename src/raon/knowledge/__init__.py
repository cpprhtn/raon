"""내장 도메인 지식 레지스트리 (P0-8, 00 §3.4).

KnowledgeBase는 [01] 시드/문법과 [02] Agent C 추론에 이중 활용되는 살아있는 자산.
새 도메인은 여기 등록한다.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from raon.contracts import KnowledgeBase

from .json_pack import json_knowledge_base
from .png import minimal_png, png_knowledge_base, write_seed_templates

if TYPE_CHECKING:
    from raon.store import Blackboard


def builtin_knowledge_bases() -> list[KnowledgeBase]:
    """내장 KnowledgeBase 목록."""
    return [png_knowledge_base(), json_knowledge_base()]


def register_builtins(blackboard: Blackboard) -> None:
    """내장 KB들을 블랙보드에 등록."""
    for kb in builtin_knowledge_bases():
        blackboard.put_knowledge(kb)


__all__ = [
    "builtin_knowledge_bases",
    "register_builtins",
    "png_knowledge_base",
    "json_knowledge_base",
    "minimal_png",
    "write_seed_templates",
]
