"""raon LLM 전략층 (04 §2.3).

원칙 1(LLM은 hot loop 밖)을 코드 경계로 강제하는 층. Provider 추상화 위에
캐싱·로깅 래퍼를 얹고, 기본 구현은 Anthropic(Claude)이다.

>>> from raon.llm import MockProvider, build_provider, InMemoryCache
>>> provider = build_provider(MockProvider(), cache=InMemoryCache())
"""

from __future__ import annotations

from .cache import InMemoryCache, PromptCache
from .logging import JsonlLogger
from .mock import MockProvider
from .provider import (
    DEFAULT_TIER_MODELS,
    PRICING,
    LLMRequest,
    LLMResponse,
    Message,
    ModelTier,
    Provider,
    Usage,
    estimate_cost,
)
from .wrappers import CachingProvider, LoggingProvider, build_provider

__all__ = [
    # provider core
    "Provider",
    "LLMRequest",
    "LLMResponse",
    "Message",
    "ModelTier",
    "Usage",
    "estimate_cost",
    "PRICING",
    "DEFAULT_TIER_MODELS",
    # implementations
    "MockProvider",
    # cache / logging
    "PromptCache",
    "InMemoryCache",
    "JsonlLogger",
    # wrappers
    "CachingProvider",
    "LoggingProvider",
    "build_provider",
]
