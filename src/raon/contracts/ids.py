"""공유 계약 엔티티의 ID 생성 헬퍼.

`00_통합아키텍처.md`의 예시는 `tgt_00123`, `find_0007` 같은 접두사+연번 형태다.
연번은 전역 상태가 필요하므로(경합 위험), 기본 생성기는 **접두사 + 짧은 랜덤 hex**를 쓴다.
연번이 필요한 곳(예: 저장소가 순서를 부여)에서는 `sequential_id()`를 명시적으로 사용한다.
"""

from __future__ import annotations

import uuid

TARGET_PREFIX = "tgt"
FINDING_PREFIX = "find"


def _short_hex(n: int = 8) -> str:
    return uuid.uuid4().hex[:n]


def new_target_id() -> str:
    """새 TargetDescriptor용 랜덤 ID (`tgt_<hex8>`)."""
    return f"{TARGET_PREFIX}_{_short_hex()}"


def new_finding_id() -> str:
    """새 Finding용 랜덤 ID (`find_<hex8>`)."""
    return f"{FINDING_PREFIX}_{_short_hex()}"


def sequential_id(prefix: str, n: int, width: int = 5) -> str:
    """연번 ID (`<prefix>_<n zero-padded>`). 저장소가 순서를 부여할 때 사용."""
    return f"{prefix}_{n:0{width}d}"
