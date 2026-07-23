"""바이너리 분석 로직 테스트 (03, P4) — angr 불필요(순수 로직)."""

from __future__ import annotations

from raon.binary import (
    FunctionInfo,
    find_containing,
    ground,
    retype_signature,
    to_target_descriptor,
)
from raon.contracts import TargetKind
from raon.llm import MockProvider

FUNCS = [
    FunctionInfo(addr=0x1000, size=0x100, name="parse_header"),
    FunctionInfo(addr=0x1100, size=0x080, name="decode"),  # 0x1100..0x1180
    FunctionInfo(addr=0x2000, size=0x040, name="cleanup"),  # gap before this
]


def test_find_containing_inside() -> None:
    assert find_containing(FUNCS, 0x1120).name == "decode"
    assert find_containing(FUNCS, 0x1000).name == "parse_header"


def test_find_containing_gap_returns_none() -> None:
    # 0x1180..0x2000 는 함수 사이 gap → floor_func라면 decode를 잘못 반환하지만
    # 포함 검증으로 None (D11 정합성 핵심)
    assert find_containing(FUNCS, 0x1500) is None


def test_find_containing_below_all() -> None:
    assert find_containing(FUNCS, 0x500) is None


def test_find_containing_empty() -> None:
    assert find_containing([], 0x1000) is None


def test_ground_result() -> None:
    r = ground(FUNCS, 0x1120)
    assert r.grounded
    assert r.function is not None and r.function.name == "decode"
    assert r.offset == 0x20
    assert "decode+0x20" in r.note


def test_ground_gap() -> None:
    r = ground(FUNCS, 0x1500)
    assert not r.grounded
    assert "gap" in r.note or "데이터" in r.note


def test_retype_without_provider_keeps_draft() -> None:
    func = FunctionInfo(addr=0x1100, size=0x80, name="decode", param_types=("long long", "long long"), returns="int")
    sig = retype_signature(func)
    assert sig.returns == "int"
    assert [p.type for p in sig.params] == ["long long", "long long"]


def test_retype_with_llm_promotes_types() -> None:
    func = FunctionInfo(addr=0x1100, size=0x80, name="decode", param_types=("long long", "long long"), returns="int")
    provider = MockProvider(
        default_text='{"params":[{"name":"buf","type":"uint8_t*"},{"name":"len","type":"size_t"}],"returns":"int"}'
    )
    sig = retype_signature(func, provider)
    assert [p.type for p in sig.params] == ["uint8_t*", "size_t"]
    assert sig.params[0].name == "buf"


def test_retype_llm_garbage_falls_back() -> None:
    func = FunctionInfo(addr=0x1100, size=0x80, name="decode", param_types=("int",), returns="int")
    provider = MockProvider(default_text="not json")
    sig = retype_signature(func, provider)
    assert [p.type for p in sig.params] == ["int"]  # 후퇴


def test_to_target_descriptor_same_schema() -> None:
    func = FunctionInfo(addr=0x1100, size=0x80, name="decode")
    sig = retype_signature(func)
    tgt = to_target_descriptor(func, sig, binary_name="libpng.so")
    assert tgt.kind == TargetKind.BINARY_FN
    assert tgt.location == "./libpng.so+0x1100"
