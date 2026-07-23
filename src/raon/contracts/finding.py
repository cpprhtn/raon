"""`Finding` — "버그 후보 하나" (00 §3.3).

모든 컴포넌트가 생산하고 [02]가 최종 소비·병합한다. 이 정규화된 단위가 있어야
"동적 크래시"(높은 신뢰)와 "정적 추론"·"에이전트 의견"(낮은 신뢰)을 *한 테이블에서*
비교·충돌해소할 수 있다.

`dedup_key`는 `raon.triage.dedup`이 계산한다(normalized_stack + category). 여기서는
문자열로 보관만 한다 — 계약 모델이 트리아지 로직에 의존하지 않도록(느슨한 결합).
"""

from __future__ import annotations

from pydantic import Field, model_validator

from .base import RaonModel
from .enums import EvidenceKind, FindingCategory, SourceComponent
from .ids import new_finding_id


class Evidence(RaonModel):
    """Finding을 뒷받침하는 증거. `kind`에 따라 채워지는 필드가 다르다."""

    kind: EvidenceKind
    reproducer: str | None = Field(
        default=None,
        description="동적 크래시일 때 재현 입력 파일 경로. 예: crashes/poc_0007.bin",
    )
    sanitizer_report: str | None = Field(
        default=None,
        description="ASan/UBSan/TSan 원문 리포트 (동적일 때)",
    )
    static_path: list[str] = Field(
        default_factory=list,
        description="정적 분석이 제시한 경로 (static_path일 때)",
    )

    @model_validator(mode="after")
    def _check_kind_consistency(self) -> Evidence:
        """증거 종류와 채워진 필드의 최소 정합성 검증(D5: 가짜 증거 조기 차단)."""
        if self.kind == EvidenceKind.DYNAMIC_CRASH and not self.reproducer:
            raise ValueError("dynamic_crash 증거는 reproducer 경로가 있어야 한다")
        if self.kind == EvidenceKind.STATIC_PATH and not self.static_path:
            raise ValueError("static_path 증거는 static_path가 비어 있으면 안 된다")
        return self


class Finding(RaonModel):
    """정규화된 버그 후보 보고 단위.

    `confidence`는 생산 컴포넌트가 부여(동적=높게, 추론=낮게).
    `exploitability`는 [02] Supervisor가 최종 랭킹에서 채운다(초기 None).
    """

    id: str = Field(default_factory=new_finding_id)
    target_id: str
    category: FindingCategory
    evidence: Evidence
    coverage_context: str | None = Field(
        default=None,
        description="예: tgt_00123 @ edge 8102",
    )
    confidence: float = Field(
        default=0.0,
        ge=0.0,
        le=1.0,
        description="생산 컴포넌트가 부여하는 신뢰도 (0~1)",
    )
    exploitability: float | None = Field(
        default=None,
        ge=0.0,
        le=1.0,
        description="[02]가 최종 랭킹에서 채움. 미평가면 None",
    )
    source_component: SourceComponent
    dedup_key: str = Field(
        description="sha1(normalized_stack + category). raon.triage.dedup이 계산.",
    )
