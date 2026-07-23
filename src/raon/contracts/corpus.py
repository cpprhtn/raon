"""`Corpus` / 커버리지 상태 — "탐색이 어디까지 갔나" (00 §3.2).

생산자: [01] 퍼징. 소비자: [01](자기 진화), [02](막힌 지점 보고 LLM 개입 판단).
‼️ 커버리지 기준은 edge/basic-block. "모든 path"는 루프 때문에 지수/무한이라 정적 불가.
"""

from __future__ import annotations

from pydantic import Field

from .base import RaonModel


class Coverage(RaonModel):
    """edge 커버리지 스냅샷."""

    edges_hit: int = Field(default=0, ge=0)
    frontier: list[str] = Field(
        default_factory=list,
        description="미탐색 인접 엣지 식별자들 — 다음에 뚫을 후보",
    )


class StuckBranch(RaonModel):
    """엔진이 오래 정체한 분기. [02]가 stuck-escape LLM 개입을 판단하는 신호(01 §4.3)."""

    loc: str = Field(description="예: decode.c:210")
    reason: str = Field(description="예: magic_bytes_check, checksum_gate")


class Corpus(RaonModel):
    """한 타겟의 시드 집합 + 커버리지 + 막힌 분기.

    seeds/reproducer는 파일 경로로만 참조한다(바이너리 데이터는 FS에, 메타는 여기에).
    """

    target_id: str
    seeds: list[str] = Field(
        default_factory=list,
        description="시드 파일 경로들. 예: corpus/seed_0001.bin",
    )
    coverage: Coverage = Field(default_factory=Coverage)
    stuck_branches: list[StuckBranch] = Field(default_factory=list)
