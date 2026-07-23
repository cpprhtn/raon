"""Anthropic(Claude) 프로바이더 구현 (P0-4, 04 §2.3).

`anthropic` 패키지가 설치돼 있어야 한다(`pip install 'raon[llm]'`). 임포트를 지연시켜
LLM 없이도 raon 코어가 동작하게 한다.

## 설계 준수
- **adaptive thinking + effort** 사용. `temperature`/`budget_tokens`는 전달하지 않는다
  (Opus 4.8 등에서 400).
- 큰 max_tokens는 스트리밍으로(HTTP 타임아웃 방어).
- refusal stop_reason을 명시 처리.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from .provider import (
    DEFAULT_TIER_MODELS,
    LLMRequest,
    LLMResponse,
    ModelTier,
    Provider,
    Usage,
    estimate_cost,
)

if TYPE_CHECKING:
    from anthropic import Anthropic

_STREAM_THRESHOLD = 16000


class AnthropicProvider(Provider):
    """Claude Messages API 프로바이더."""

    def __init__(
        self,
        client: Anthropic | None = None,
        *,
        tier_models: dict[ModelTier, str] | None = None,
    ):
        if client is None:
            try:
                from anthropic import Anthropic
            except ImportError as e:  # pragma: no cover - 환경 의존
                raise ImportError(
                    "AnthropicProvider requires the 'anthropic' package. "
                    "Install with: pip install 'raon[llm]'"
                ) from e
            client = Anthropic()
        self._client = client
        self._tier_models = tier_models or dict(DEFAULT_TIER_MODELS)

    @property
    def name(self) -> str:
        return "anthropic"

    def model_for_tier(self, tier: ModelTier) -> str:
        return self._tier_models[tier]

    def complete(self, request: LLMRequest) -> LLMResponse:
        model = self.model_for_tier(request.tier)
        kwargs: dict[str, Any] = {
            "model": model,
            "max_tokens": request.max_tokens,
            "messages": request.messages,
            "thinking": {"type": "adaptive"},
            "output_config": {"effort": request.effort},
        }
        if request.system is not None:
            kwargs["system"] = request.system
        if request.stop_sequences:
            kwargs["stop_sequences"] = request.stop_sequences

        if request.max_tokens > _STREAM_THRESHOLD:
            with self._client.messages.stream(**kwargs) as stream:
                message = stream.get_final_message()
        else:
            message = self._client.messages.create(**kwargs)

        text_parts: list[str] = []
        for block in message.content:
            if block.type == "text":
                text_parts.append(block.text)
        text = "".join(text_parts)
        usage = Usage(
            input_tokens=getattr(message.usage, "input_tokens", 0) or 0,
            output_tokens=getattr(message.usage, "output_tokens", 0) or 0,
            cache_read_input_tokens=getattr(message.usage, "cache_read_input_tokens", 0) or 0,
            cache_creation_input_tokens=getattr(
                message.usage, "cache_creation_input_tokens", 0
            )
            or 0,
        )
        return LLMResponse(
            text=text,
            model=model,
            usage=usage,
            cost_usd=estimate_cost(model, usage),
            cached=False,
            stop_reason=message.stop_reason,
            purpose=request.purpose,
        )
