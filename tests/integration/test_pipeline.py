"""수직 슬라이스 통합 테스트 (P1-5, 00 §6) — 실제 clang 필요.

컴파일 → 크래시 → ASan 파싱 → Agent B Finding → 블랙보드 저장을 실제로 관통.
Magma/libFuzzer 없이 소스 있는 타겟으로 성립(00 §6: v0는 [03] 없이 성립).
clang이 없으면 스킵.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from raon.agents import AgentB, Supervisor
from raon.contracts import EvidenceKind, FindingCategory, TargetDescriptor, TargetKind
from raon.fuzzing.engine import HarnessMode, clang_path, compile_harness, run_input
from raon.store import Blackboard

pytestmark = pytest.mark.integration

TARGET_SRC = Path(__file__).parent.parent / "fixtures" / "targets" / "vuln_decode.c"

if clang_path() is None:
    pytest.skip("clang not available", allow_module_level=True)


@pytest.fixture
def harness(tmp_path: Path):
    out = tmp_path / "vuln"
    return compile_harness([TARGET_SRC], out, mode=HarnessMode.FILE_ARG)


def test_benign_input_no_crash(harness, tmp_path: Path) -> None:
    good = tmp_path / "good.bin"
    good.write_bytes(b"AAAA")  # 4 bytes < 8, 안전
    result = run_input(harness, good)
    assert not result.crashed


def test_overflow_input_crashes(harness, tmp_path: Path) -> None:
    bad = tmp_path / "bad.bin"
    bad.write_bytes(b"A" * 32)  # 32 > 8 → heap-buffer-overflow
    result = run_input(harness, bad)
    assert result.crashed
    assert result.error_type == "heap-buffer-overflow"


def test_full_vertical_slice(harness, tmp_path: Path) -> None:
    """★ P1 수직 슬라이스: 크래시 → Agent B → Finding → 저장 → 재현 검증."""
    # 1. 크래시 유발 입력
    bad = tmp_path / "poc.bin"
    bad.write_bytes(b"A" * 32)
    result = run_input(harness, bad)
    assert result.crashed

    # 2. Agent B 트리아지 → Finding
    b = AgentB()
    finding = b.triage(
        result.sanitizer_output,
        target_id="tgt_vuln",
        reproducer=str(bad),
        finding_id="find_0001",
    )
    assert finding is not None
    assert finding.category == FindingCategory.MEMORY
    assert finding.evidence.kind == EvidenceKind.DYNAMIC_CRASH

    # 3. 블랙보드 저장 (Finding 스키마가 실제 경로에서 채워지는가 — 00 §6 검증)
    with Blackboard(tmp_path / "bb.sqlite") as bb:
        bb.put_target(
            TargetDescriptor(id="tgt_vuln", kind=TargetKind.SOURCE_FN, location="vuln_decode.c:8")
        )
        bb.put_finding(finding)
        assert bb.count_unique_findings() == 1
        stored = bb.get_finding("find_0001")
        assert stored is not None and stored.dedup_key == finding.dedup_key

        # 4. Supervisor 랭킹
        result_triage = Supervisor().triage([finding], targets={"tgt_vuln": bb.get_target("tgt_vuln")})  # type: ignore[dict-item]
        assert result_triage.representatives[0].exploitability is not None

    # 5. 재현 검증: reproducer로 다시 크래시가 나는가
    reproduced = run_input(harness, bad)
    assert reproduced.crashed and reproduced.error_type == "heap-buffer-overflow"
