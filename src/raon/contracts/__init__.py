"""raon 공유 계약 (Shared Contracts) — `00_통합아키텍처.md §3`.

3개 컴포넌트가 유기적으로 붙는 이유는 전부 여기서 나온다. 각 컴포넌트는 이 스키마만
알면 나머지를 몰라도 된다(느슨한 결합). 이 패키지는 raon의 안정적 공개 API 표면이다.
"""

from __future__ import annotations

from .base import SCHEMA_VERSION, RaonModel
from .corpus import Corpus, Coverage, StuckBranch
from .enums import EvidenceKind, FindingCategory, SourceComponent, TargetKind
from .finding import Evidence, Finding
from .ids import new_finding_id, new_target_id, sequential_id
from .knowledge import KnowledgeBase
from .target import Param, Signature, TargetDescriptor

__all__ = [
    "SCHEMA_VERSION",
    "RaonModel",
    # enums
    "TargetKind",
    "FindingCategory",
    "EvidenceKind",
    "SourceComponent",
    # target
    "TargetDescriptor",
    "Signature",
    "Param",
    # corpus
    "Corpus",
    "Coverage",
    "StuckBranch",
    # finding
    "Finding",
    "Evidence",
    # knowledge
    "KnowledgeBase",
    # id helpers
    "new_target_id",
    "new_finding_id",
    "sequential_id",
]
