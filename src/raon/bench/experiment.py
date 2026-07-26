"""단일(순진) vs 멀티에이전트(오케스트레이션) 트리아지 델타 실험 (02 §7 부분).

문서 02 §7의 완전한 "단일 LLM vs A/B/C+Supervisor" 실험은 라이브 LLM과 ground-truth 버그셋
(Magma)이 필요하다. 여기서는 그 핵심 축 하나 — **크래시 중복제거 품질** — 을 라이브 LLM 없이
실측한다.

## 설정
같은 버그라도 ASLR/리빌드로 sanitizer 리포트의 원문(주소 등)이 달라진다. 각 버그 타겟을 여러 번
실행해 **같은 버그의 서로 다른 원문 리포트**를 얻는다(실제 변동, 조작 아님).

- **Baseline(단일·순진)**: 원문 스택 문자열이 완전히 같을 때만 같은 버그로 본다(정규화 없음).
  → ASLR로 원문이 달라지면 같은 버그를 여러 개로 **과다계수**한다.
- **raon(오케스트레이션)**: 정규화 dedup_key(주소/라인/경로 제거) + Supervisor 병합.
  → 같은 버그를 올바르게 하나로 합친다.

정답(gold): 타겟 하나 = 버그 하나. 지표: 보고된 unique 수 vs gold, pairwise dedup F1.
결과는 `run_experiment()`가 실제 실행에서 측정한다(맥에서도 ASan으로 동작).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import tempfile
from dataclasses import asdict, dataclass
from pathlib import Path

from raon.agents import CrashTriageAgent, Supervisor
from raon.bench.metrics import ClusterEval, dedup_accuracy
from raon.contracts import Finding
from raon.fuzzing.engine import HarnessMode, clang_path, compile_harness, run_input

# 버그 타겟들(safe 제외). 각자 gold cluster 하나.
_BUGGY_TARGETS = [
    "heap_overflow.c",
    "use_after_free.c",
    "stack_overflow.c",
    "global_overflow.c",
]
_DRIVER = "_file_driver.c"
_RUNS_PER_TARGET = 3
_CRASH_INPUT = b"A" * 64  # 모든 타겟의 버그를 트리거


def _targets_dir() -> Path:
    return Path(__file__).parent / "eval_targets"


def _baseline_key(report: str) -> str:
    """단일·순진 baseline: 원문 리포트 전체를 정규화 없이 해시(주소 포함)."""
    return hashlib.sha1(report.encode("utf-8")).hexdigest()


@dataclass
class ExperimentResult:
    gold_unique: int
    baseline_unique: int
    raon_unique: int
    baseline_eval: ClusterEval
    raon_eval: ClusterEval
    total_findings: int

    def to_markdown(self) -> str:
        return "\n".join(
            [
                "| Approach | Unique bugs reported | Dedup F1 (vs gold) |",
                "|---|---|---|",
                f"| Baseline (single, raw-stack dedup) | {self.baseline_unique} | "
                f"{self.baseline_eval.f1:.2f} |",
                f"| raon (normalized dedup + Supervisor) | {self.raon_unique} | "
                f"{self.raon_eval.f1:.2f} |",
                "",
                f"Ground truth: {self.gold_unique} unique bugs across "
                f"{self.total_findings} crash reports "
                f"({_RUNS_PER_TARGET} runs × {len(_BUGGY_TARGETS)} targets).",
            ]
        )


def run_experiment(*, workdir: str | Path | None = None) -> ExperimentResult:
    """실제로 크래시를 생성해 baseline vs raon 중복제거를 비교한다.

    clang(ASan)만 있으면 된다(libFuzzer 불필요). 없으면 RuntimeError.
    """
    if clang_path() is None:
        raise RuntimeError("clang with ASan required")

    tdir = _targets_dir()
    driver = tdir / _DRIVER
    agent = CrashTriageAgent()

    ctx = tempfile.TemporaryDirectory() if workdir is None else None
    base = Path(workdir) if workdir is not None else Path(ctx.name)  # type: ignore[union-attr]
    try:
        input_path = base / "crash.bin"
        base.mkdir(parents=True, exist_ok=True)
        input_path.write_bytes(_CRASH_INPUT)

        # gold: finding id -> gold cluster(타겟 이름)
        findings: list[Finding] = []
        gold_of: dict[str, str] = {}
        baseline_key_of: dict[str, str] = {}

        for tgt in _BUGGY_TARGETS:
            stem = Path(tgt).stem
            work = base / stem
            work.mkdir(parents=True, exist_ok=True)
            harness = compile_harness(
                [driver, tdir / tgt], work / "h", mode=HarnessMode.FILE_ARG
            )
            for run_i in range(_RUNS_PER_TARGET):
                res = run_input(harness, input_path)
                if not res.crashed:
                    continue
                fid = f"{stem}_{run_i}"
                finding = agent.triage(
                    res.sanitizer_output,
                    target_id=f"exp_{stem}",
                    reproducer=str(input_path),
                    finding_id=fid,
                )
                if finding is None:
                    continue
                findings.append(finding)
                gold_of[fid] = stem
                baseline_key_of[fid] = _baseline_key(res.sanitizer_output)

        # gold clusters
        gold: dict[str, list[str]] = {}
        for fid, g in gold_of.items():
            gold.setdefault(g, []).append(fid)
        gold_clusters = list(gold.values())

        # baseline clusters (raw-stack exact)
        base_clusters_map: dict[str, list[str]] = {}
        for fid, k in baseline_key_of.items():
            base_clusters_map.setdefault(k, []).append(fid)
        baseline_clusters = list(base_clusters_map.values())

        # raon clusters (Supervisor triage → dedup_key clusters). provider 없음=규칙 기반.
        triage = Supervisor().triage(findings, semantic=False)
        raon_clusters = [[f.id for f in members] for members in triage.clusters.values()]

        return ExperimentResult(
            gold_unique=len(gold_clusters),
            baseline_unique=len(baseline_clusters),
            raon_unique=len(raon_clusters),
            baseline_eval=dedup_accuracy(baseline_clusters, gold_clusters),
            raon_eval=dedup_accuracy(raon_clusters, gold_clusters),
            total_findings=len(findings),
        )
    finally:
        if ctx is not None:
            ctx.cleanup()


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        prog="raon.bench.experiment",
        description="single (naive) vs multi-agent (orchestrated) triage delta",
    )
    p.add_argument("--json", default=None, help="write result JSON to this path")
    p.add_argument("--md", default=None, help="write the Markdown table to this path")
    args = p.parse_args(argv)

    try:
        result = run_experiment()
    except RuntimeError as e:
        print(f"skipped: {e}", file=sys.stderr)
        return 3

    table = result.to_markdown()
    print(table)
    if args.json:
        Path(args.json).write_text(json.dumps(asdict(result), indent=2, default=str), "utf-8")
    if args.md:
        Path(args.md).write_text(table + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
