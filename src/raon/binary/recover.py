"""LLM 타입/시그니처 복원 (03 §3.4, P4 핵심 개입점).

디컴파일 출력은 `undefined4 param_1` 같은 노이즈다. angr/Ghidra는 register-width까지만
복원한다(research). LLM이 주변 사용 패턴·문자열·호출 API를 보고 의미 있는 타입으로
재구성한다(예: `undefined8*` → `struct png_header*`). 이게 [01] 하네스 합성 재료가 된다.

환각 방어(D11): 복원 결과는 angr 실제 메모리접근 패턴과 대조 검증해야 한다(여기선 타입
초안까지; 대조는 P4 심화). provider 없으면 원본 시그니처를 그대로 둔다(안전 후퇴).
"""

from __future__ import annotations

import json
import re

from raon.contracts import Param, Signature, TargetDescriptor, TargetKind
from raon.llm import LLMRequest, Message, ModelTier, Provider

from .types import FunctionInfo

_JSON_OBJ_RE = re.compile(r"\{.*\}", re.DOTALL)


def _build_prompt(func: FunctionInfo, pseudo_c: str | None) -> str:
    params = ", ".join(func.param_types) or "(unknown)"
    ctx = f"\n[의사 C]\n{pseudo_c}\n" if pseudo_c else ""
    return (
        "너는 디컴파일 타입 복원 전문가다. 아래 함수의 노이즈 타입을 의미 있는 C 타입으로"
        " 재구성하라. 확신 없으면 원래 타입을 유지하라.\n"
        f"함수: {func.name}\n현재 파라미터 타입: {params}\n반환: {func.returns}\n{ctx}\n"
        '출력은 JSON만: {"params":[{"name":"..","type":".."}],"returns":".."}'
    )


def _parse_signature(text: str, fallback: Signature) -> Signature:
    m = _JSON_OBJ_RE.search(text)
    if not m:
        return fallback
    try:
        data = json.loads(m.group(0))
    except json.JSONDecodeError:
        return fallback
    if not isinstance(data, dict):
        return fallback
    params_raw = data.get("params", [])
    params: list[Param] = []
    if isinstance(params_raw, list):
        for i, p in enumerate(params_raw):
            if isinstance(p, dict) and "type" in p:
                params.append(Param(name=str(p.get("name", f"arg{i}")), type=str(p["type"])))
    returns = str(data.get("returns", fallback.returns))
    return Signature(params=params, returns=returns, side_effects=fallback.side_effects)


def retype_signature(
    func: FunctionInfo,
    provider: Provider | None = None,
    *,
    pseudo_c: str | None = None,
) -> Signature:
    """FunctionInfo(초안 타입) → 의미 타입으로 재구성한 Signature.

    provider 없으면 register-width 초안을 그대로 Signature로 감싼다(후퇴).
    """
    fallback = Signature(
        params=[Param(name=f"arg{i}", type=t) for i, t in enumerate(func.param_types)],
        returns=func.returns,
    )
    if provider is None:
        return fallback

    messages: list[Message] = [{"role": "user", "content": _build_prompt(func, pseudo_c)}]
    resp = provider.complete(
        LLMRequest(
            messages=messages,
            tier=ModelTier.PREMIUM,
            purpose="type_recovery",
            effort="high",
            max_tokens=1024,
        )
    )
    return _parse_signature(resp.text, fallback)


def to_target_descriptor(
    func: FunctionInfo,
    signature: Signature,
    *,
    binary_name: str = "bin",
) -> TargetDescriptor:
    """복원된 함수 → TargetDescriptor(kind=binary_fn). 소스와 **동일 스키마**(03 §4).

    이 덕분에 [01]/[02]는 소스/바이너리 타겟을 구분 없이 처리한다(유기적 결합).
    """
    return TargetDescriptor(
        kind=TargetKind.BINARY_FN,
        location=f"./{binary_name}+{func.addr:#x}",
        signature=signature,
    )
