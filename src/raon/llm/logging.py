"""LLM I/O 전량 로깅 (P0-4, D4 재현성, 02 §6.4).

모든 호출을 JSONL로 append한다: 프롬프트·응답·모델·캐시여부·usage·비용.
실험 재현·감사·비용 분석의 원장(ledger).
"""

from __future__ import annotations

import json
import threading
import time
from dataclasses import asdict
from pathlib import Path

from .provider import LLMRequest, LLMResponse


class JsonlLogger:
    """LLM 호출을 JSONL 파일에 append. 스레드 안전."""

    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()

    def log(self, request: LLMRequest, response: LLMResponse) -> None:
        record = {
            "ts": time.time(),
            "purpose": request.purpose,
            "tier": request.tier.value,
            "model": response.model,
            "cached": response.cached,
            "system": request.system,
            "messages": request.messages,
            "effort": request.effort,
            "max_tokens": request.max_tokens,
            "response_text": response.text,
            "stop_reason": response.stop_reason,
            "usage": asdict(response.usage),
            "cost_usd": response.cost_usd,
        }
        line = json.dumps(record, ensure_ascii=False)
        with self._lock, self.path.open("a", encoding="utf-8") as f:
            f.write(line + "\n")

    def total_cost(self) -> float:
        """로그의 누적 비용 (비용/버그 지표 산출용)."""
        if not self.path.exists():
            return 0.0
        total = 0.0
        with self.path.open(encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    total += json.loads(line).get("cost_usd", 0.0)
        return total
