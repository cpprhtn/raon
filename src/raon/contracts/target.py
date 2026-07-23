"""`TargetDescriptor` — "무엇을 테스트하는가" (00 §3.1).

생산자: 소스면 파서, 바이너리면 [03]. 소비자: [01] 퍼징, [02] 오케스트레이션.
소스/바이너리가 **동일 스키마**를 쓰는 것이 유기적 결합의 핵심(03 §4).
"""

from __future__ import annotations

from pydantic import Field

from .base import RaonModel
from .enums import TargetKind
from .ids import new_target_id


class Param(RaonModel):
    """함수 시그니처의 파라미터 하나."""

    name: str
    type: str


class Signature(RaonModel):
    """타겟의 호출 시그니처. 소스면 파싱, 바이너리면 [03]이 복원.

    이것이 [01] 하네스 자동합성의 재료가 된다(01 §4.1).
    """

    params: list[Param] = Field(default_factory=list)
    returns: str = "void"
    side_effects: list[str] = Field(
        default_factory=list,
        description="예: heap_alloc, file_write — 하네스가 자원을 어떻게 다뤄야 하는지 힌트",
    )


class TargetDescriptor(RaonModel):
    """테스트 대상 하나의 구조화된 기술.

    `priority_score`는 [02]가 채운다(초기 0.0). `domain_tags`는 KnowledgeBase 연결 키.
    """

    id: str = Field(default_factory=new_target_id)
    kind: TargetKind
    location: str = Field(description="예: src/decode.c:142  또는  ./bin+0x4a10")
    signature: Signature = Field(default_factory=Signature)
    reachability: list[str] = Field(
        default_factory=list,
        description="진입 경로. 예: ['main → parse_header → decode']",
    )
    domain_tags: list[str] = Field(
        default_factory=list,
        description="KnowledgeBase 연결 키. 예: ['image', 'file_parser']",
    )
    priority_score: float = Field(
        default=0.0,
        ge=0.0,
        le=1.0,
        description="[02] 오케스트레이션이 부여하는 우선순위 (0~1)",
    )
