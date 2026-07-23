"""[02] 멀티에이전트 오케스트레이션 (02_멀티에이전트_오케스트레이션.md).

블랙보드 + 슈퍼바이저 패턴. 에이전트끼리 직접 통신하지 않고 공유 저장소를 경유한다.
진짜 기여는 에이전트가 아니라 Supervisor의 오케스트레이션(dedup·충돌해소·랭킹)이다.
"""

from __future__ import annotations

from .agent_a import AgentA
from .agent_b import AgentB
from .agent_c import AgentC
from .supervisor import Supervisor, TriageResult

__all__ = ["AgentA", "AgentB", "AgentC", "Supervisor", "TriageResult"]
