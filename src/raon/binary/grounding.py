"""크래시 주소 → 함수 문맥 grounding (03 §2 뒷단, P4).

## 정합성 핵심 (research D11)
angr의 `FunctionManager.floor_func(addr)`는 addr 이하의 가장 가까운 함수 진입점을 줄 뿐,
addr가 **실제로 그 함수 안**인지 검증하지 않는다. 함수 사이 gap/PLT/데이터에서는 엉뚱한
함수를 반환한다. 그래서 반드시 포함 검증(`FunctionInfo.contains`)을 덧댄다.

`find_containing`은 순수 함수라 angr 없이 단위 검증된다. angr 어댑터는 이 목록의 생산자일 뿐.
"""

from __future__ import annotations

from bisect import bisect_right
from collections.abc import Sequence

from .types import FunctionInfo, GroundingResult


def find_containing(functions: Sequence[FunctionInfo], addr: int) -> FunctionInfo | None:
    """정렬 여부와 무관하게 addr를 포함하는 함수를 찾는다(floor + 포함 검증).

    floor(addr 이하 최댓값)를 이진 탐색으로 찾고, 포함되지 않으면 None(gap/데이터).
    """
    if not functions:
        return None
    ordered = sorted(functions, key=lambda f: f.addr)
    starts = [f.addr for f in ordered]
    idx = bisect_right(starts, addr) - 1
    if idx < 0:
        return None
    candidate = ordered[idx]
    return candidate if candidate.contains(addr) else None


def ground(functions: Sequence[FunctionInfo], addr: int) -> GroundingResult:
    """주소를 grounding한 결과(함수 + 오프셋 + 노트)."""
    fn = find_containing(functions, addr)
    if fn is None:
        return GroundingResult(
            address=addr,
            function=None,
            note="주소가 복원된 어떤 함수 범위에도 없음(gap/PLT/데이터 추정)",
        )
    return GroundingResult(
        address=addr,
        function=fn,
        offset=addr - fn.addr,
        note=f"{fn.name}+{addr - fn.addr:#x}",
    )


def load_functions_angr(binary_path: str) -> list[FunctionInfo]:  # pragma: no cover - angr 의존
    """angr로 바이너리에서 함수 목록을 복원(선택적 의존).

    `pip install 'raon[binary]'` 필요. CFGFast로 함수 경계를 얻고
    CompleteCallingConventions로 시그니처 초안을 복원한다(register-width 수준).
    """
    try:
        import angr
    except ImportError as e:
        raise ImportError(
            "load_functions_angr requires angr. Install with: pip install 'raon[binary]'"
        ) from e

    proj = angr.Project(binary_path, auto_load_libs=False)
    cfg = proj.analyses.CFGFast(normalize=True)
    proj.analyses.CompleteCallingConventions(cfg=cfg.model, analyze_callsites=True)

    out: list[FunctionInfo] = []
    for addr, func in proj.kb.functions.items():
        proto = func.prototype
        params: tuple[str, ...] = ()
        returns = "undefined"
        if proto is not None:
            params = tuple(str(a) for a in (proto.args or ()))
            returns = str(proto.returnty) if proto.returnty is not None else "void"
        out.append(
            FunctionInfo(
                addr=addr,
                size=func.size or 0,
                name=func.name,
                param_types=params,
                returns=returns,
            )
        )
    return out
