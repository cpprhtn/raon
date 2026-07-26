"""Agent B — 메모리/런타임 (동적, sanitizer 해석) (02 §3).

역할: ASan/TSan/UBSan 출력을 파싱·트리아지·root-cause 요약. ‼️ sanitizer 재구현 아님.
입력: [01]이 낸 크래시(sanitizer 리포트). 산출: 정규화 스택·dedup_key·높은 confidence.
"""

from __future__ import annotations

from raon.contracts import Finding, SourceComponent
from raon.fuzzing.asan import finding_from_report, parse_report
from raon.llm import LLMRequest, Message, ModelTier, Provider

from ._compat import deprecated_alias


class CrashTriageAgent:
    """새니타이저 리포트 → 정규화 Finding + (선택) LLM root-cause 요약 (동적 크래시 트리아지)."""

    source = SourceComponent.CRASH_TRIAGE

    def __init__(self, provider: Provider | None = None):
        self._provider = provider

    def triage(
        self,
        sanitizer_report: str,
        *,
        target_id: str,
        reproducer: str,
        coverage_context: str | None = None,
        finding_id: str | None = None,
    ) -> Finding | None:
        """리포트 → 동적 크래시 Finding. 인식 실패 시 None.

        confidence는 높게(동적 재현 증거). source_component는 agent_B.
        """
        return finding_from_report(
            sanitizer_report,
            target_id=target_id,
            reproducer=reproducer,
            source_component=self.source,
            confidence=0.95,
            coverage_context=coverage_context,
            finding_id=finding_id,
        )

    def root_cause_summary(self, sanitizer_report: str) -> str | None:
        """LLM으로 크래시 root-cause를 한두 문장으로 요약(리포트용). provider 없으면 None.

        CHEAP 티어(1차 필터) — 값싼 모델로 충분(02 §6.2).
        """
        if self._provider is None:
            return None
        parsed = parse_report(sanitizer_report)
        if parsed is None:
            return None
        prompt = (
            "다음 sanitizer 크래시 리포트의 root cause를 한국어 한두 문장으로 요약하라. "
            "어느 함수에서 어떤 종류의 위반이 왜 일어났는지에 집중하라.\n\n"
            f"{sanitizer_report}"
        )
        messages: list[Message] = [{"role": "user", "content": prompt}]
        resp = self._provider.complete(
            LLMRequest(
                messages=messages,
                tier=ModelTier.CHEAP,
                purpose="sanitizer_triage",
                effort="low",
                max_tokens=512,
            )
        )
        return resp.text.strip() or None


# Deprecated alias (0.2.0). Use CrashTriageAgent.
AgentB = deprecated_alias(CrashTriageAgent, "AgentB")
