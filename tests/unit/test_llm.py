"""LLM 추상화 테스트 (P0-4 DoD): 캐시 hit/miss·결정성·비용·로깅."""

from __future__ import annotations

import json
from pathlib import Path

from raon.llm import (
    InMemoryCache,
    JsonlLogger,
    LLMRequest,
    Message,
    MockProvider,
    ModelTier,
    PromptCache,
    Usage,
    build_provider,
    estimate_cost,
)


def _req(text: str = "hi", purpose: str = "test") -> LLMRequest:
    msgs: list[Message] = [{"role": "user", "content": text}]
    return LLMRequest(messages=msgs, tier=ModelTier.CHEAP, purpose=purpose)


def test_mock_provider_basic() -> None:
    p = MockProvider(default_text="hello")
    resp = p.complete(_req())
    assert resp.text == "hello"
    assert resp.model == "claude-haiku-4-5"
    assert resp.cost_usd > 0
    assert p.call_count == 1


def test_tier_mapping() -> None:
    p = MockProvider()
    assert p.model_for_tier(ModelTier.CHEAP) == "claude-haiku-4-5"
    assert p.model_for_tier(ModelTier.PREMIUM) == "claude-opus-4-8"


def test_cost_estimation() -> None:
    usage = Usage(input_tokens=1_000_000, output_tokens=1_000_000)
    # opus: $5 in + $25 out = $30
    assert estimate_cost("claude-opus-4-8", usage) == 30.0
    # unknown model → 0
    assert estimate_cost("mystery", usage) == 0.0


def test_cost_cache_discount() -> None:
    usage = Usage(cache_read_input_tokens=1_000_000)
    # haiku input $1 × 0.1 = $0.10
    assert round(estimate_cost("claude-haiku-4-5", usage), 4) == 0.10


def test_cache_key_deterministic() -> None:
    r1 = _req("same")
    r2 = _req("same")
    assert r1.cache_key("m") == r2.cache_key("m")
    assert _req("a").cache_key("m") != _req("b").cache_key("m")
    # 모델이 다르면 키도 다르다
    assert _req("x").cache_key("m1") != _req("x").cache_key("m2")


def test_caching_short_circuits_inner() -> None:
    inner = MockProvider(default_text="cached-me")
    cache = InMemoryCache()
    provider = build_provider(inner, cache=cache)

    r1 = provider.complete(_req("q1"))
    assert r1.cached is False
    assert inner.call_count == 1

    # 같은 요청 → 캐시 히트, inner 재호출 없음, 비용 0
    r2 = provider.complete(_req("q1"))
    assert r2.cached is True
    assert r2.text == "cached-me"
    assert r2.cost_usd == 0.0
    assert inner.call_count == 1

    # 다른 요청 → miss
    provider.complete(_req("q2"))
    assert inner.call_count == 2


def test_file_cache_persists(tmp_path: Path) -> None:
    inner = MockProvider(default_text="persisted")
    cache = PromptCache(tmp_path / "cache")
    p1 = build_provider(inner, cache=cache)
    p1.complete(_req("k"))
    assert inner.call_count == 1

    # 새 캐시 인스턴스(같은 디렉토리) → 여전히 히트
    inner2 = MockProvider(default_text="different")
    cache2 = PromptCache(tmp_path / "cache")
    p2 = build_provider(inner2, cache=cache2)
    resp = p2.complete(_req("k"))
    assert resp.cached is True
    assert resp.text == "persisted"  # 원본 캐시 값
    assert inner2.call_count == 0


def test_logging_records_all_calls(tmp_path: Path) -> None:
    logpath = tmp_path / "llm.jsonl"
    logger = JsonlLogger(logpath)
    inner = MockProvider(default_text="logged")
    cache = InMemoryCache()
    provider = build_provider(inner, cache=cache, logger=logger)

    provider.complete(_req("q", purpose="harness_synth"))
    provider.complete(_req("q", purpose="harness_synth"))  # 캐시 히트도 로깅

    lines = logpath.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 2
    rec0 = json.loads(lines[0])
    rec1 = json.loads(lines[1])
    assert rec0["purpose"] == "harness_synth"
    assert rec0["cached"] is False
    assert rec1["cached"] is True  # 두 번째는 캐시 히트


def test_logger_total_cost(tmp_path: Path) -> None:
    logpath = tmp_path / "llm.jsonl"
    logger = JsonlLogger(logpath)
    provider = build_provider(MockProvider(default_text="x"), logger=logger)
    provider.complete(_req("a"))
    provider.complete(_req("b"))
    assert logger.total_cost() > 0


def test_responder_callback() -> None:
    p = MockProvider(responder=lambda req: f"echo:{req.messages[-1]['content']}")
    resp = p.complete(_req("ping"))
    assert resp.text == "echo:ping"
