"""Agent A — 표준 위반 / 디펜던시 패턴 (정적) (02 §3).

역할: 라이브러리 표준 위반, 위험 API 오용, 알려진 안티패턴 감지.
도구: Semgrep(→CodeQL) 실행 + LLM이 결과 해석·우선순위. ‼️ 분석기 재구현 아님(원칙 2).
산출: evidence.kind = static_path, confidence 중.

Semgrep 실행기는 주입 가능(테스트에서 fixture 결과 주입). semgrep 미설치 시 빈 결과.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from collections.abc import Callable
from typing import Any

from raon.contracts import (
    Evidence,
    EvidenceKind,
    Finding,
    FindingCategory,
    SourceComponent,
)
from raon.llm import Provider
from raon.triage.dedup import dedup_key_from_functions

from ._compat import deprecated_alias

# Semgrep 실행기: 경로 → 결과 dict 리스트 (semgrep --json 의 "results").
SemgrepRunner = Callable[[str], list[dict[str, Any]]]

_STATIC_CONFIDENCE = 0.55

# check_id/메시지 키워드 → 카테고리 힌트.
_CATEGORY_HINTS: list[tuple[str, FindingCategory]] = [
    ("overflow", FindingCategory.MEMORY),
    ("buffer", FindingCategory.MEMORY),
    ("use-after", FindingCategory.MEMORY),
    ("free", FindingCategory.MEMORY),
    ("memcpy", FindingCategory.MEMORY),
    ("format-string", FindingCategory.API_MISUSE),
    ("injection", FindingCategory.API_MISUSE),
    ("unchecked", FindingCategory.API_MISUSE),
    ("integer", FindingCategory.UNDEFINED_BEHAVIOR),
]


def default_semgrep_runner(path: str) -> list[dict[str, Any]]:
    """설치된 semgrep으로 스캔. 미설치/실패 시 빈 리스트(안전 후퇴)."""
    if shutil.which("semgrep") is None:
        return []
    try:
        proc = subprocess.run(
            ["semgrep", "--json", "--quiet", "--config", "auto", path],
            capture_output=True,
            text=True,
            timeout=300,
            check=False,
        )
        data = json.loads(proc.stdout or "{}")
    except (subprocess.SubprocessError, json.JSONDecodeError, OSError):
        return []
    results = data.get("results", [])
    return results if isinstance(results, list) else []


def _category_for(check_id: str, message: str) -> FindingCategory:
    hay = f"{check_id} {message}".lower()
    for kw, cat in _CATEGORY_HINTS:
        if kw in hay:
            return cat
    return FindingCategory.LOGIC


class StaticAnalysisAgent:
    """정적 분석 에이전트 (Semgrep/CodeQL + LLM 해석)."""

    source = SourceComponent.STATIC_ANALYSIS

    def __init__(
        self,
        provider: Provider | None = None,
        *,
        semgrep_runner: SemgrepRunner | None = None,
    ):
        self._provider = provider
        self._runner = semgrep_runner or default_semgrep_runner

    def analyze(self, path: str, *, target_id: str) -> list[Finding]:
        """경로를 정적 분석해 static_path Finding들을 생산."""
        findings: list[Finding] = []
        for result in self._runner(path):
            check_id = str(result.get("check_id", "unknown"))
            file_path = str(result.get("path", path))
            start = result.get("start", {})
            line = start.get("line", 0) if isinstance(start, dict) else 0
            extra = result.get("extra", {})
            message = str(extra.get("message", "")) if isinstance(extra, dict) else ""

            category = _category_for(check_id, message)
            loc = f"{file_path}:{line}"
            findings.append(
                Finding(
                    target_id=target_id,
                    category=category,
                    evidence=Evidence(
                        kind=EvidenceKind.STATIC_PATH,
                        static_path=[check_id, loc, message][: 3 if message else 2],
                    ),
                    confidence=_STATIC_CONFIDENCE,
                    source_component=self.source,
                    dedup_key=dedup_key_from_functions([check_id, loc], category),
                )
            )
        return findings


# Deprecated alias (0.2.0). Use StaticAnalysisAgent.
AgentA = deprecated_alias(StaticAnalysisAgent, "AgentA")
