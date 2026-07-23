"""바이너리 분석 데이터 구조 (03)."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class FunctionInfo:
    """복원된 함수 하나. angr/Ghidra 어느 쪽에서 와도 동일 형태."""

    addr: int
    size: int
    name: str
    # 복원된 파라미터 타입들(초안; LLM 재타이핑 전에는 register-width 수준).
    param_types: tuple[str, ...] = ()
    returns: str = "undefined"

    @property
    def end(self) -> int:
        return self.addr + self.size

    def contains(self, addr: int) -> bool:
        """addr가 이 함수 범위 안인가. ‼️ floor_func는 이 검증을 안 하므로 필수(D11)."""
        return self.addr <= addr < self.end


@dataclass
class GroundingResult:
    """크래시 주소 grounding 결과 (03 §2 뒷단)."""

    address: int
    function: FunctionInfo | None
    offset: int | None = None  # 함수 시작으로부터의 오프셋
    note: str = ""
    context: list[str] = field(default_factory=list)

    @property
    def grounded(self) -> bool:
        return self.function is not None
