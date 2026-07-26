"""[02] 멀티에이전트 오케스트레이션 (02_멀티에이전트_오케스트레이션.md).

블랙보드 + 슈퍼바이저 패턴. 에이전트끼리 직접 통신하지 않고 공유 저장소를 경유한다.
진짜 기여는 에이전트가 아니라 Supervisor의 오케스트레이션(dedup·충돌해소·랭킹)이다.

에이전트 이름은 역할 기반이다(0.2.0):
- StaticAnalysisAgent      (구 AgentA)
- CrashTriageAgent         (구 AgentB)
- InterfaceInferenceAgent  (구 AgentC)
구 이름은 DeprecationWarning과 함께 한 버전 유지된다.
"""

from __future__ import annotations

from .agent_a import AgentA, StaticAnalysisAgent
from .agent_b import AgentB, CrashTriageAgent
from .agent_c import AgentC, InterfaceInferenceAgent
from .supervisor import Supervisor, TriageResult

__all__ = [
    # role-based names (preferred)
    "StaticAnalysisAgent",
    "CrashTriageAgent",
    "InterfaceInferenceAgent",
    "Supervisor",
    "TriageResult",
    # deprecated aliases (0.2.0)
    "AgentA",
    "AgentB",
    "AgentC",
]
