"""공유 계약에서 쓰이는 열거형.

`00_통합아키텍처.md §3`의 문자열 유니언을 타입 안전한 열거형으로 고정한다.
모든 값은 문자열이라 JSON 직렬화가 그대로 된다(str, Enum).
"""

from __future__ import annotations

from enum import Enum


class TargetKind(str, Enum):
    """`TargetDescriptor.kind` — 무엇을 테스트하는 단위인가."""

    SOURCE_FN = "source_fn"
    BINARY_FN = "binary_fn"
    MODULE = "module"
    INTERFACE = "interface"


class FindingCategory(str, Enum):
    """`Finding.category` — 버그 후보의 대분류."""

    MEMORY = "memory"
    LOGIC = "logic"
    API_MISUSE = "api_misuse"
    UNDEFINED_BEHAVIOR = "undefined_behavior"


class EvidenceKind(str, Enum):
    """`Finding.evidence.kind` — 증거의 성격. 이종 증거 병합의 가중치 축."""

    DYNAMIC_CRASH = "dynamic_crash"
    STATIC_PATH = "static_path"
    AGENT_INFERENCE = "agent_inference"


class SourceComponent(str, Enum):
    """`Finding.source_component` — 어느 컴포넌트가 이 Finding을 생산했나.

    값은 역할 기반이다(0.2.0에서 agent_A/B/C 코드명 대체). 스토어에 문자열로 저장되므로
    외부 사용자가 리포트에서 바로 이해할 수 있게 명시적 이름을 쓴다.
    """

    FUZZER = "fuzzer"
    STATIC_ANALYSIS = "static_analysis"
    CRASH_TRIAGE = "crash_triage"
    INTERFACE_INFERENCE = "interface_inference"
