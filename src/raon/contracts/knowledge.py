"""`KnowledgeBase` — 도메인 사전 (00 §3.4, 구 L2.3 흡수).

체크리스트로 두면 죽은 문서, 여기 넣으면 살아있는 자산. [01]의 시드/문법과
[02] Agent C의 추론 근거로 **동시에** 소비된다.
"""

from __future__ import annotations

from pydantic import Field

from .base import RaonModel


class KnowledgeBase(RaonModel):
    """한 도메인(예: image/png)의 퍼징/추론 연료.

    `domain_tags`(TargetDescriptor)와 `domain`이 매칭되어 타겟↔KB가 연결된다.
    """

    domain: str = Field(description="예: image/png")
    grammar: str | None = Field(
        default=None,
        description="문법 파일 경로 또는 식별자. 예: png.g4 — [01] 문법 기반 시드 생성 연료",
    )
    seed_templates: list[str] = Field(
        default_factory=list,
        description="시드 템플릿 파일 경로. 예: templates/min.png",
    )
    invariants: list[str] = Field(
        default_factory=list,
        description="도메인 불변식. 예: 'chunk_len ≤ remaining_bytes', 'CRC matches'",
    )
    known_weak_interfaces: list[str] = Field(
        default_factory=list,
        description="알려진 취약 인터페이스. 예: 'idat inflate 경계' — [02] Agent C 추론 근거",
    )
