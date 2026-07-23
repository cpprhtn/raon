"""raon 명령줄 인터페이스 (P1-5).

수직 슬라이스를 실제로 관통하는 엔트리포인트:
    ingest → (compile) run/triage → normalize Finding → store → rank → report

서브커맨드:
    raon version                     버전 출력
    raon kb                          내장 KnowledgeBase 목록
    raon triage <report> [...]       sanitizer 리포트 → Finding (clang 불필요)
    raon run <target.c> --input ...  FILE_ARG 타겟 컴파일·실행·트리아지 (clang 필요)
    raon report --db <db>            저장된 Finding을 랭킹해 출력
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from raon import __version__
from raon.agents import AgentB, Supervisor
from raon.contracts import TargetDescriptor, TargetKind
from raon.knowledge import builtin_knowledge_bases
from raon.store import Blackboard


def _print(obj: object) -> None:
    print(json.dumps(obj, ensure_ascii=False, indent=2, default=str))


def cmd_version(_args: argparse.Namespace) -> int:
    print(f"raon {__version__}")
    return 0


def cmd_kb(_args: argparse.Namespace) -> int:
    kbs = builtin_knowledge_bases()
    _print(
        [
            {
                "domain": kb.domain,
                "invariants": len(kb.invariants),
                "weak_interfaces": kb.known_weak_interfaces,
            }
            for kb in kbs
        ]
    )
    return 0


def cmd_triage(args: argparse.Namespace) -> int:
    report = Path(args.report).read_text(encoding="utf-8")
    finding = AgentB().triage(
        report,
        target_id=args.target_id,
        reproducer=args.reproducer or args.report,
    )
    if finding is None:
        print("no recognizable sanitizer crash in report", file=sys.stderr)
        return 2
    if args.db:
        with Blackboard(args.db) as bb:
            bb.put_finding(finding)
    _print(json.loads(finding.model_dump_json()))
    return 0


def _collect_inputs(args: argparse.Namespace) -> list[Path]:
    inputs: list[Path] = [Path(p) for p in (args.input or [])]
    if args.corpus:
        corpus = Path(args.corpus)
        if corpus.is_dir():
            inputs.extend(sorted(p for p in corpus.iterdir() if p.is_file()))
    return inputs


def cmd_run(args: argparse.Namespace) -> int:
    # 지연 임포트: clang 관련은 필요할 때만
    from raon.fuzzing.engine import HarnessMode, clang_path, compile_harness, run_input

    if clang_path() is None:
        print("clang not found; `run` needs a C compiler", file=sys.stderr)
        return 3

    inputs = _collect_inputs(args)
    if not inputs:
        print("no inputs given (use --input or --corpus)", file=sys.stderr)
        return 2

    workdir = Path(args.workdir) if args.workdir else Path(".raon_run")
    workdir.mkdir(parents=True, exist_ok=True)
    harness = compile_harness([args.target], workdir / "harness", mode=HarnessMode.FILE_ARG)

    agent_b = AgentB()
    findings = []
    target = TargetDescriptor(
        id=args.target_id, kind=TargetKind.SOURCE_FN, location=args.target
    )
    with Blackboard(args.db or (workdir / "raon.sqlite")) as bb:
        bb.put_target(target)
        for i, inp in enumerate(inputs):
            result = run_input(harness, inp)
            if not result.crashed:
                continue
            finding = agent_b.triage(
                result.sanitizer_output,
                target_id=target.id,
                reproducer=str(inp),
                finding_id=f"find_{i:05d}",
            )
            if finding is not None:
                bb.put_finding(finding)
                findings.append(finding)

        triage = Supervisor().triage(findings, targets={target.id: target})
        report = {
            "target": target.id,
            "inputs_run": len(inputs),
            "crashes": len(findings),
            "unique_bugs": triage.unique_count,
            "findings": [
                {
                    "id": f.id,
                    "category": f.category.value,
                    "error": (f.evidence.sanitizer_report or "").splitlines()[1:2],
                    "exploitability": f.exploitability,
                    "dedup_key": f.dedup_key[:12],
                }
                for f in triage.representatives
            ],
        }
    _print(report)
    return 0


def cmd_report(args: argparse.Namespace) -> int:
    with Blackboard(args.db) as bb:
        findings = bb.list_findings()
        targets = {t.id: t for t in bb.list_targets()}
    triage = Supervisor().triage(findings, targets=targets)
    _print(
        {
            "total_findings": len(findings),
            "unique_bugs": triage.unique_count,
            "ranked": [
                {
                    "id": f.id,
                    "category": f.category.value,
                    "source": f.source_component.value,
                    "confidence": f.confidence,
                    "exploitability": f.exploitability,
                }
                for f in triage.representatives
            ],
        }
    )
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="raon", description="LLM 기반 취약점 발견 시스템")
    sub = p.add_subparsers(dest="command", required=True)

    sub.add_parser("version", help="버전 출력").set_defaults(func=cmd_version)
    sub.add_parser("kb", help="내장 KnowledgeBase 목록").set_defaults(func=cmd_kb)

    pt = sub.add_parser("triage", help="sanitizer 리포트 → Finding")
    pt.add_argument("report", help="sanitizer 리포트 파일")
    pt.add_argument("--target-id", default="tgt_unknown")
    pt.add_argument("--reproducer", default=None)
    pt.add_argument("--db", default=None, help="블랙보드 DB 경로(저장 시)")
    pt.set_defaults(func=cmd_triage)

    pr = sub.add_parser("run", help="FILE_ARG 타겟 컴파일·실행·트리아지 (clang 필요)")
    pr.add_argument("target", help="타겟 C 소스(argv[1] 파일을 읽는 main 포함)")
    pr.add_argument("--input", action="append", help="입력 파일(반복 가능)")
    pr.add_argument("--corpus", default=None, help="입력 파일 디렉토리")
    pr.add_argument("--target-id", default="tgt_cli")
    pr.add_argument("--db", default=None)
    pr.add_argument("--workdir", default=None)
    pr.set_defaults(func=cmd_run)

    prp = sub.add_parser("report", help="저장된 Finding 랭킹 출력")
    prp.add_argument("--db", required=True)
    prp.set_defaults(func=cmd_report)

    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    func = args.func
    return int(func(args))


if __name__ == "__main__":
    raise SystemExit(main())
