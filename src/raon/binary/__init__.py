"""[03] 바이너리 분석 연동 (03_바이너리분석_연동.md, P4 스트레치).

소스 없는 타겟을 (a) TargetDescriptor로 구조화하고 (b) 크래시 주소를 함수/타입 문맥으로
역해석(grounding). 자체 디컴파일러를 만들지 않고 angr/Ghidra/LIEF를 감싼다(원칙 2).

무거운 의존성(angr)은 선택적(`pip install 'raon[binary]'`). 정합성 로직(주소→함수 포함
검증, LLM 재타이핑)은 angr 없이도 단위 검증된다.
"""

from __future__ import annotations

from .grounding import find_containing, ground
from .recover import retype_signature, to_target_descriptor
from .types import FunctionInfo, GroundingResult

__all__ = [
    "FunctionInfo",
    "GroundingResult",
    "find_containing",
    "ground",
    "retype_signature",
    "to_target_descriptor",
]
