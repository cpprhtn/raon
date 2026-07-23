"""Agent C — 설계의도 기반 취약 인터페이스 추론 (02 §3).

역할: KnowledgeBase.known_weak_interfaces + 시그니처를 보고 "이 인터페이스가 왜 위험한가"를
추론. 크래시 없이도 가설 생성 → [01]에 퍼징 타겟으로 되먹임.
산출: evidence.kind = agent_inference, confidence 낮음(가설).

환각 위험(D10): confidence를 낮게 두고, 동적 검증(퍼징) 통과해야 승격(Supervisor가 관리).
"""

from __future__ import annotations

from raon.contracts import (
    Evidence,
    EvidenceKind,
    Finding,
    FindingCategory,
    KnowledgeBase,
    SourceComponent,
    TargetDescriptor,
)
from raon.llm import LLMRequest, Message, ModelTier, Provider
from raon.triage.dedup import Frame, dedup_key

_HYPOTHESIS_CONFIDENCE = 0.3


class AgentC:
    """취약 인터페이스 추론 에이전트."""

    source = SourceComponent.AGENT_C

    def __init__(self, provider: Provider | None = None):
        self._provider = provider

    def hypothesize(
        self,
        target: TargetDescriptor,
        kb: KnowledgeBase,
    ) -> list[Finding]:
        """타겟 시그니처 × KB 취약 인터페이스 → 가설 Finding들.

        provider가 있으면 LLM으로 각 인터페이스의 위험성을 판정하고, 없으면
        모든 known_weak_interface에 대해 낮은 confidence 가설을 낸다(규칙 기반 후퇴).
        """
        findings: list[Finding] = []
        for interface in kb.known_weak_interfaces:
            reasoning = self._assess(target, interface)
            if reasoning is None:
                continue
            # 함수명 기반 dedup_key(추론은 스택이 없으므로 타겟 위치를 프레임처럼 사용)
            key_frames = [Frame(function=target.location)]
            findings.append(
                Finding(
                    target_id=target.id,
                    category=FindingCategory.API_MISUSE,
                    evidence=Evidence(
                        kind=EvidenceKind.AGENT_INFERENCE,
                        static_path=[interface, reasoning],
                    ),
                    confidence=_HYPOTHESIS_CONFIDENCE,
                    source_component=self.source,
                    dedup_key=dedup_key(key_frames, FindingCategory.API_MISUSE),
                )
            )
        return findings

    def _assess(self, target: TargetDescriptor, interface: str) -> str | None:
        """인터페이스가 타겟에 위험한 근거를 반환. provider 없으면 인터페이스명 자체를 근거로."""
        if self._provider is None:
            return f"KB 취약 인터페이스 '{interface}'가 타겟 시그니처와 관련될 수 있음(가설)"

        sig = target.signature
        params = ", ".join(f"{p.type} {p.name}" for p in sig.params)
        prompt = (
            "너는 취약점 인터페이스 추론 에이전트다. 아래 타겟 함수가 주어진 '취약 인터페이스'와"
            " 관련해 위험할 수 있는지 한국어 한 문장으로 근거를 대라. 관련 없으면 정확히"
            " 'NONE'만 출력하라.\n\n"
            f"타겟: {target.location}\n시그니처: {sig.returns} f({params})\n"
            f"side_effects: {sig.side_effects}\n취약 인터페이스: {interface}\n"
        )
        messages: list[Message] = [{"role": "user", "content": prompt}]
        resp = self._provider.complete(
            LLMRequest(
                messages=messages,
                tier=ModelTier.CHEAP,
                purpose="weak_interface_inference",
                effort="low",
                max_tokens=256,
            )
        )
        text = resp.text.strip()
        if not text or text.upper().startswith("NONE"):
            return None
        return text
