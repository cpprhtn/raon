"""Provider 조합 래퍼 — 캐싱·로깅을 얇게 얹는다 (P0-4).

`build_provider()`로 Logging(Caching(inner)) 스택을 만든다. 각 래퍼는 Provider를
구현하고 name/model_for_tier를 inner에 위임한다.
"""

from __future__ import annotations

from typing import Protocol

from .provider import LLMRequest, LLMResponse, ModelTier, Provider


class CacheBackend(Protocol):
    """PromptCache / InMemoryCache 공통 인터페이스."""

    def get(self, key: str) -> LLMResponse | None: ...
    def put(self, key: str, response: LLMResponse) -> None: ...


class _Wrapper(Provider):
    """name/model_for_tier를 inner에 위임하는 베이스."""

    def __init__(self, inner: Provider):
        self._inner = inner

    @property
    def name(self) -> str:
        return self._inner.name

    def model_for_tier(self, tier: ModelTier) -> str:
        return self._inner.model_for_tier(tier)


class CachingProvider(_Wrapper):
    """프롬프트 해시 캐시로 inner 호출을 단락(short-circuit)."""

    def __init__(self, inner: Provider, cache: CacheBackend):
        super().__init__(inner)
        self._cache = cache

    def complete(self, request: LLMRequest) -> LLMResponse:
        model = self._inner.model_for_tier(request.tier)
        key = request.cache_key(model)
        hit = self._cache.get(key)
        if hit is not None:
            # 캐시 히트는 새 비용이 없다(재생). purpose는 이번 요청 것으로.
            return LLMResponse(
                text=hit.text,
                model=hit.model,
                usage=hit.usage,
                cost_usd=0.0,
                cached=True,
                stop_reason=hit.stop_reason,
                purpose=request.purpose,
            )
        resp = self._inner.complete(request)
        self._cache.put(key, resp)
        return resp


class LoggingProvider(_Wrapper):
    """모든 호출을 JsonlLogger로 기록(캐시 히트 포함)."""

    def __init__(self, inner: Provider, logger: JsonlLoggerLike):
        super().__init__(inner)
        self._logger = logger

    def complete(self, request: LLMRequest) -> LLMResponse:
        resp = self._inner.complete(request)
        self._logger.log(request, resp)
        return resp


class JsonlLoggerLike(Protocol):
    def log(self, request: LLMRequest, response: LLMResponse) -> None: ...


def build_provider(
    inner: Provider,
    *,
    cache: CacheBackend | None = None,
    logger: JsonlLoggerLike | None = None,
) -> Provider:
    """Logging(Caching(inner)) 스택을 조립. 캐시가 로깅 안쪽이라 히트도 기록된다."""
    provider = inner
    if cache is not None:
        provider = CachingProvider(provider, cache)
    if logger is not None:
        provider = LoggingProvider(provider, logger)
    return provider
