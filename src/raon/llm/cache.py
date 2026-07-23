"""프롬프트 해시 캐시 (P0-4, D4 재현성).

최신 모델은 temperature를 거부해 응답이 완전 결정적이지 않다. 캐시는 *같은 프롬프트에
같은 응답*을 재생함으로써 실험 재현성과 비용 절감을 동시에 제공한다.

디렉토리 기반(키당 JSON 파일)이라 사람이 들여다보기 쉽다(감사·디버깅).
in-memory 백엔드는 테스트용.
"""

from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path
from typing import Any

from .provider import LLMResponse, Usage


def _response_to_dict(resp: LLMResponse) -> dict[str, Any]:
    return asdict(resp)


def _response_from_dict(d: dict[str, Any]) -> LLMResponse:
    usage = Usage(**d.pop("usage"))
    return LLMResponse(usage=usage, **d)


class PromptCache:
    """프롬프트 해시 → 응답 캐시. 파일 디렉토리 백엔드."""

    def __init__(self, root: str | Path):
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)

    def _path(self, key: str) -> Path:
        return self.root / f"{key}.json"

    def get(self, key: str) -> LLMResponse | None:
        path = self._path(key)
        if not path.exists():
            return None
        data = json.loads(path.read_text(encoding="utf-8"))
        return _response_from_dict(data)

    def put(self, key: str, response: LLMResponse) -> None:
        self._path(key).write_text(
            json.dumps(_response_to_dict(response), ensure_ascii=False, indent=2),
            encoding="utf-8",
        )


class InMemoryCache:
    """테스트용 in-memory 캐시. 동일 인터페이스."""

    def __init__(self) -> None:
        self._store: dict[str, LLMResponse] = {}

    def get(self, key: str) -> LLMResponse | None:
        return self._store.get(key)

    def put(self, key: str, response: LLMResponse) -> None:
        self._store[key] = response
