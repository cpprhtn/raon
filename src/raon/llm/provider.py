"""LLM 전략층 추상화 (P0-4, 04 §2.3).

원칙 1: LLM은 hot loop 밖 전략층에만. 이 모듈은 퍼저 루프와 물리적으로 분리된다.

## 재현성 (D4)
최신 Claude 모델(Opus 4.8 등)은 `temperature`/`top_p`/`budget_tokens`를 **거부**한다(400).
따라서 "temperature=0 결정성"은 성립하지 않는다. 대신 재현성은
**프롬프트 해시 캐싱(cache.py) + 전량 I/O 로깅(logging.py)**으로 확보한다.

## 모델 티어링 (D9, 02 §6.2)
"값싼 모델로 1차 필터 → 비싼 모델로 심판" 원칙을 티어로 표현한다:
- CHEAP    → Haiku (1차 필터·간단 분류)
- STANDARD → Sonnet
- PREMIUM  → Opus (하네스 합성·심판)
"""

from __future__ import annotations

import hashlib
import json
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Literal, TypedDict

Role = Literal["user", "assistant"]


class Message(TypedDict):
    """대화 메시지 하나 (Anthropic Messages 형식과 호환)."""

    role: Role
    content: str


class ModelTier(str, Enum):
    """비용/능력 티어. 구체 모델 ID는 Provider가 매핑한다."""

    CHEAP = "cheap"
    STANDARD = "standard"
    PREMIUM = "premium"


# 모델별 가격 (USD / 1M tokens). claude-api 스킬 기준(2026).
# (input, output) 튜플.
PRICING: dict[str, tuple[float, float]] = {
    "claude-opus-4-8": (5.00, 25.00),
    "claude-opus-4-7": (5.00, 25.00),
    "claude-sonnet-5": (3.00, 15.00),
    "claude-haiku-4-5": (1.00, 5.00),
}

# 티어 → 기본 모델 ID.
DEFAULT_TIER_MODELS: dict[ModelTier, str] = {
    ModelTier.CHEAP: "claude-haiku-4-5",
    ModelTier.STANDARD: "claude-sonnet-5",
    ModelTier.PREMIUM: "claude-opus-4-8",
}


@dataclass(frozen=True)
class Usage:
    """토큰 사용량. 비용/버그 지표(00 §8)의 원재료."""

    input_tokens: int = 0
    output_tokens: int = 0
    cache_read_input_tokens: int = 0
    cache_creation_input_tokens: int = 0


def estimate_cost(model: str, usage: Usage) -> float:
    """usage → USD 비용 추정. 캐시 read 0.1×, write 1.25× (prompt-caching 경제학)."""
    prices = PRICING.get(model)
    if prices is None:
        return 0.0
    in_price, out_price = prices
    per_m = 1_000_000.0
    cost = usage.input_tokens / per_m * in_price
    cost += usage.output_tokens / per_m * out_price
    cost += usage.cache_read_input_tokens / per_m * in_price * 0.1
    cost += usage.cache_creation_input_tokens / per_m * in_price * 1.25
    return cost


@dataclass
class LLMRequest:
    """전략층 LLM 호출 하나.

    `purpose`는 로깅/분석용 태그(예: harness_synth, sanitizer_triage, judge).
    `temperature`는 의도적으로 없다 — 최신 모델이 거부하고, 재현성은 캐싱으로 잡는다.
    """

    messages: list[Message]
    tier: ModelTier = ModelTier.CHEAP
    system: str | None = None
    max_tokens: int = 4096
    effort: Literal["low", "medium", "high", "xhigh", "max"] = "high"
    stop_sequences: list[str] = field(default_factory=list)
    purpose: str = "generic"

    def cache_key(self, model: str) -> str:
        """이 요청의 결정적 캐시 키. 응답에 영향을 주는 모든 필드를 해시."""
        payload = json.dumps(
            {
                "model": model,
                "system": self.system,
                "messages": self.messages,
                "max_tokens": self.max_tokens,
                "effort": self.effort,
                "stop_sequences": self.stop_sequences,
            },
            sort_keys=True,
            ensure_ascii=False,
        )
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()


@dataclass
class LLMResponse:
    """LLM 응답 + 계측."""

    text: str
    model: str
    usage: Usage = field(default_factory=Usage)
    cost_usd: float = 0.0
    cached: bool = False
    stop_reason: str | None = None
    purpose: str = "generic"


class Provider(ABC):
    """LLM 프로바이더 인터페이스. 구현: MockProvider, AnthropicProvider, 캐싱/로깅 래퍼."""

    @property
    @abstractmethod
    def name(self) -> str:
        """프로바이더 식별자 (로깅/캐시 키에 사용)."""

    @abstractmethod
    def model_for_tier(self, tier: ModelTier) -> str:
        """티어 → 구체 모델 ID."""

    @abstractmethod
    def complete(self, request: LLMRequest) -> LLMResponse:
        """요청을 실행하고 응답을 반환한다."""
