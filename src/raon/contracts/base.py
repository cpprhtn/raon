"""공유 계약의 공통 베이스.

모든 계약 모델은 `RaonModel`을 상속하여 `schema_version`을 갖는다(D14: 스키마 진화 파급 방어).
`00_통합아키텍처.md`가 정의한 4종 스키마가 시간이 지나며 바뀌어도, 저장된 데이터가
어떤 버전으로 쓰였는지 추적할 수 있어야 마이그레이션이 가능하다.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

SCHEMA_VERSION = "1.0"
"""공유 계약 스키마의 현재 버전. 계약 구조가 바뀌면 올린다."""


class RaonModel(BaseModel):
    """모든 공유 계약 모델의 베이스.

    - `schema_version`을 자동 부여하여 저장 데이터의 진화를 추적.
    - `extra="forbid"`로 오타/미지 필드를 조기에 잡는다(LLM 구조화 출력 검증에도 유리).
    - `validate_assignment=True`로 생성 이후 대입도 검증.
    """

    model_config = ConfigDict(
        extra="forbid",
        validate_assignment=True,
        use_enum_values=False,
        frozen=False,
    )

    schema_version: str = Field(
        default=SCHEMA_VERSION,
        description="이 인스턴스가 준수하는 공유 계약 스키마 버전",
    )
