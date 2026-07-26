"""하위호환 별칭 헬퍼 (0.2.0 에이전트 리네이밍).

AgentA/B/C 는 역할 기반 이름(StaticAnalysisAgent 등)으로 대체되었다. 기존 이름은
DeprecationWarning을 내며 한 버전 동안 유지된다.
"""

from __future__ import annotations

import warnings
from typing import Any, TypeVar

_T = TypeVar("_T")


def deprecated_alias(new_cls: type[_T], old_name: str) -> type[_T]:
    """new_cls를 상속해 인스턴스화 시 DeprecationWarning을 내는 별칭 클래스를 만든다."""
    new_name = new_cls.__name__

    class _Alias(new_cls):  # type: ignore[valid-type, misc]
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            warnings.warn(
                f"{old_name} is deprecated and will be removed in a future release; "
                f"use {new_name} instead.",
                DeprecationWarning,
                stacklevel=2,
            )
            super().__init__(*args, **kwargs)

    _Alias.__name__ = old_name
    _Alias.__qualname__ = old_name
    _Alias.__doc__ = f"Deprecated alias for {new_name}. Use {new_name} instead."
    return _Alias
