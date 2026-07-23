"""공유 저장소 (블랙보드) — `00_통합아키텍처.md §2,§3`.

모든 컴포넌트가 여기에 읽고 쓴다. 에이전트끼리 직접 통신하지 않고 이 블랙보드를 경유해
느슨하게 결합한다(02 §2). 대용량 바이너리(시드/재현물)는 파일시스템에, 메타데이터는
SQLite에 둔다.
"""

from __future__ import annotations

from .blackboard import Blackboard

__all__ = ["Blackboard"]
