"""자체 평가 벤치마크 (0.2.0) — raon이 실제로 버그를 찾는지 측정한다.

Magma 대규모 캠페인(x86_64 Linux 전용)과 별개로, 번들된 소형 버그 타겟 모음에 대해
**실제 libFuzzer 커버리지 유도 퍼징**을 돌려 raon 파이프라인 전체(퍼징→파싱→트리아지→
중복제거)를 관통시키고 측정 숫자를 낸다. libFuzzer 런타임이 있는 플랫폼(Linux/Docker) 필요.

정직성: 이 벤치는 **자체 타겟**에 대한 것이며 Magma ground-truth가 아니다. 결과는 "이 도구가
실제로 이런 버그를 찾는다"의 재현 가능한 증거일 뿐, 알려진 CVE 재현율이 아니다.

실행:
    python -m raon.bench.eval --time 20 --md RESULTS.md
"""

from __future__ import annotations

import argparse
import json
import statistics
import sys
import tempfile
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path

from raon.agents import CrashTriageAgent
from raon.contracts import FindingCategory
from raon.fuzzing.engine import (
    HarnessMode,
    compile_harness,
    fuzz,
    libfuzzer_available,
)

# (파일명, 기대 카테고리). safe 타겟은 None(버그 없음, 오탐 점검용).
EVAL_MANIFEST: list[tuple[str, FindingCategory | None]] = [
    ("heap_overflow.c", FindingCategory.MEMORY),
    ("use_after_free.c", FindingCategory.MEMORY),
    ("stack_overflow.c", FindingCategory.MEMORY),
    ("global_overflow.c", FindingCategory.MEMORY),
    ("safe.c", None),
]


def targets_dir() -> Path:
    return Path(__file__).parent / "eval_targets"


@dataclass
class EvalResult:
    name: str
    is_buggy: bool
    crashed: bool
    error_type: str | None
    category: str | None
    seconds: float | None
    dedup_key: str | None
    detected: bool  # 버그 타겟을 올바른 카테고리로 잡았나
    false_positive: bool  # safe 타겟이 크래시했나


@dataclass
class EvalSummary:
    total_targets: int = 0
    buggy_targets: int = 0
    detected: int = 0
    detection_rate: float = 0.0
    unique_bugs: int = 0
    false_positives: int = 0
    mean_seconds: float | None = None
    median_seconds: float | None = None


def run_eval(
    *,
    max_time_per_target: int = 20,
    timeout: int = 90,
    workdir: str | Path | None = None,
) -> list[EvalResult]:
    """매니페스트의 각 타겟을 컴파일·퍼징·트리아지하고 결과를 모은다.

    libFuzzer 런타임이 없으면 RuntimeError(호출자가 skip 판단).
    """
    if not libfuzzer_available():
        raise RuntimeError(
            "libFuzzer runtime unavailable; run this on Linux or in the Docker image"
        )

    tdir = targets_dir()
    agent = CrashTriageAgent()
    results: list[EvalResult] = []

    ctx = tempfile.TemporaryDirectory() if workdir is None else None
    base = Path(workdir) if workdir is not None else Path(ctx.name)  # type: ignore[union-attr]
    try:
        for fname, expected in EVAL_MANIFEST:
            is_buggy = expected is not None
            src = tdir / fname
            work = base / Path(fname).stem
            work.mkdir(parents=True, exist_ok=True)
            harness = compile_harness([src], work / "h", mode=HarnessMode.LIBFUZZER)

            start = time.monotonic()
            fr = fuzz(
                harness,
                work / "corpus",
                work / "artifacts",
                max_total_time=max_time_per_target,
                timeout=timeout,
            )
            elapsed = round(time.monotonic() - start, 2)

            category: str | None = None
            dedup_key: str | None = None
            error_type: str | None = None
            if fr.crashed:
                finding = agent.triage(
                    fr.sanitizer_output,
                    target_id=f"eval_{Path(fname).stem}",
                    reproducer=fr.reproducer or "",
                )
                if finding is not None:
                    category = finding.category.value
                    dedup_key = finding.dedup_key
                from raon.fuzzing.asan import parse_report

                parsed = parse_report(fr.sanitizer_output)
                error_type = parsed.error_type if parsed else None

            detected = bool(is_buggy and fr.crashed and category == (expected.value if expected else None))
            false_positive = bool((not is_buggy) and fr.crashed)
            results.append(
                EvalResult(
                    name=fname,
                    is_buggy=is_buggy,
                    crashed=fr.crashed,
                    error_type=error_type,
                    category=category,
                    seconds=elapsed if fr.crashed else None,
                    dedup_key=dedup_key,
                    detected=detected,
                    false_positive=false_positive,
                )
            )
    finally:
        if ctx is not None:
            ctx.cleanup()
    return results


def summarize(results: list[EvalResult]) -> EvalSummary:
    buggy = [r for r in results if r.is_buggy]
    detected = [r for r in buggy if r.detected]
    times = [r.seconds for r in detected if r.seconds is not None]
    unique = len({r.dedup_key for r in detected if r.dedup_key})
    return EvalSummary(
        total_targets=len(results),
        buggy_targets=len(buggy),
        detected=len(detected),
        detection_rate=round(len(detected) / len(buggy), 3) if buggy else 0.0,
        unique_bugs=unique,
        false_positives=sum(1 for r in results if r.false_positive),
        mean_seconds=round(statistics.mean(times), 2) if times else None,
        median_seconds=round(statistics.median(times), 2) if times else None,
    )


def to_markdown(results: list[EvalResult], summ: EvalSummary) -> str:
    lines = [
        "| Target | Bug class | Detected | Sanitizer error | Time to crash (s) |",
        "|---|---|---|---|---|",
    ]
    for r in results:
        cls = "— (safe)" if not r.is_buggy else (r.category or "?")
        if not r.is_buggy:
            detected = "no crash ✓" if not r.crashed else "FALSE POSITIVE"
        else:
            detected = "✅" if r.detected else "❌"
        err = r.error_type or "—"
        secs = f"{r.seconds}" if r.seconds is not None else "—"
        lines.append(f"| `{r.name}` | {cls} | {detected} | {err} | {secs} |")
    lines += [
        "",
        f"**Detection rate:** {summ.detected}/{summ.buggy_targets} "
        f"({summ.detection_rate:.0%}) buggy targets · "
        f"**unique bugs:** {summ.unique_bugs} · "
        f"**false positives:** {summ.false_positives} · "
        f"**median time-to-crash:** {summ.median_seconds}s",
    ]
    return "\n".join(lines)


@dataclass
class _Report:
    results: list[EvalResult] = field(default_factory=list)
    summary: EvalSummary = field(default_factory=EvalSummary)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="raon.bench.eval", description="raon self-contained eval")
    p.add_argument("--time", type=int, default=20, help="max fuzz seconds per target")
    p.add_argument("--json", default=None, help="write full results JSON to this path")
    p.add_argument("--md", default=None, help="write the Markdown table to this path")
    args = p.parse_args(argv)

    try:
        results = run_eval(max_time_per_target=args.time)
    except RuntimeError as e:
        print(f"skipped: {e}", file=sys.stderr)
        return 3

    summ = summarize(results)
    table = to_markdown(results, summ)
    print(table)

    if args.json:
        payload = {"results": [asdict(r) for r in results], "summary": asdict(summ)}
        Path(args.json).write_text(json.dumps(payload, indent=2), encoding="utf-8")
    if args.md:
        Path(args.md).write_text(table + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
