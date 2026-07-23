#!/usr/bin/env python3
"""raon 수직 슬라이스 데모 (00 §6).

소스 있는 취약 타겟을 컴파일 → 크래시 입력 실행 → sanitizer 파싱 → Finding 정규화 →
블랙보드 저장 → Supervisor 랭킹까지 한 번에 관통한다.

실행:
    python examples/demo_vertical_slice.py

clang(ASan 포함)이 필요하다. LLM은 쓰지 않는다(Agent B 규칙 기반 경로).
"""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path

from raon.agents import AgentB, Supervisor
from raon.contracts import TargetDescriptor, TargetKind
from raon.fuzzing.engine import HarnessMode, clang_path, compile_harness, run_input
from raon.store import Blackboard

TARGET = Path(__file__).parent.parent / "tests" / "fixtures" / "targets" / "vuln_decode.c"


def main() -> int:
    if clang_path() is None:
        print("clang이 필요합니다 (ASan 포함). 설치 후 다시 실행하세요.", file=sys.stderr)
        return 1

    with tempfile.TemporaryDirectory() as d:
        work = Path(d)
        print("1) 타겟 컴파일 (ASan)…")
        harness = compile_harness([TARGET], work / "vuln", mode=HarnessMode.FILE_ARG)

        # 안전한 입력과 오버플로우 입력
        good = work / "good.bin"
        good.write_bytes(b"AA")
        bad = work / "poc.bin"
        bad.write_bytes(b"A" * 32)

        print("2) 입력 실행 → 크래시 탐지…")
        agent_b = AgentB()
        target = TargetDescriptor(
            id="tgt_demo", kind=TargetKind.SOURCE_FN, location="vuln_decode.c:8"
        )

        with Blackboard(work / "raon.sqlite") as bb:
            bb.put_target(target)
            for name, inp in [("good", good), ("poc", bad)]:
                result = run_input(harness, inp)
                status = f"CRASH ({result.error_type})" if result.crashed else "ok"
                print(f"   - {name:5} → {status}")
                if result.crashed:
                    finding = agent_b.triage(
                        result.sanitizer_output,
                        target_id=target.id,
                        reproducer=str(inp),
                        finding_id="find_0001",
                    )
                    if finding:
                        bb.put_finding(finding)

            print("3) Supervisor 트리아지·랭킹…")
            triage = Supervisor().triage(bb.list_findings(), targets={target.id: target})
            print(f"   unique bugs = {triage.unique_count}")
            for f in triage.representatives:
                print(
                    f"   [{f.category.value}] exploitability={f.exploitability} "
                    f"dedup={f.dedup_key[:12]} src={f.source_component.value}"
                )
    print("\n✅ 수직 슬라이스 관통 완료 (compile → crash → parse → Finding → rank).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
