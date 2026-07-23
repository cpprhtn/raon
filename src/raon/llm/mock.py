"""테스트/오프라인용 MockProvider (P0-4).

네트워크·API 키 없이 결정적으로 동작. 스크립트된 응답 또는 콜백으로 응답을 정한다.
usage는 텍스트 길이에서 추정해 비용 계산 경로를 테스트할 수 있게 한다.
"""

from __future__ import annotations

from collections.abc import Callable

from .provider import (
    DEFAULT_TIER_MODELS,
    LLMRequest,
    LLMResponse,
    ModelTier,
    Provider,
    Usage,
    estimate_cost,
)

Responder = Callable[[LLMRequest], str]


def _approx_tokens(text: str) -> int:
    """대략적 토큰 수(≈ 4 chars/token). 정확도보다 결정성이 목적."""
    return max(1, len(text) // 4)


class MockProvider(Provider):
    """결정적 목 프로바이더.

    - `responder`가 있으면 그것으로 응답 텍스트를 만든다.
    - 없으면 `default_text`를 반환.
    호출 횟수를 세어(테스트에서 캐시 히트 검증) `call_count`로 노출.
    """

    def __init__(
        self,
        *,
        responder: Responder | None = None,
        default_text: str = "MOCK_RESPONSE",
        tier_models: dict[ModelTier, str] | None = None,
    ):
        self._responder = responder
        self._default_text = default_text
        self._tier_models = tier_models or dict(DEFAULT_TIER_MODELS)
        self.call_count = 0

    @property
    def name(self) -> str:
        return "mock"

    def model_for_tier(self, tier: ModelTier) -> str:
        return self._tier_models[tier]

    def complete(self, request: LLMRequest) -> LLMResponse:
        self.call_count += 1
        text = self._responder(request) if self._responder else self._default_text
        model = self.model_for_tier(request.tier)
        prompt_text = (request.system or "") + "".join(m["content"] for m in request.messages)
        usage = Usage(
            input_tokens=_approx_tokens(prompt_text),
            output_tokens=_approx_tokens(text),
        )
        return LLMResponse(
            text=text,
            model=model,
            usage=usage,
            cost_usd=estimate_cost(model, usage),
            cached=False,
            stop_reason="end_turn",
            purpose=request.purpose,
        )
