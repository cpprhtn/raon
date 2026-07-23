"""하네스 자동합성 + 검증 게이트 (P2-1, 01 §4.1).

⚠️ 최대 난제(00 §10.1): 합성된 하네스가 (a) 컴파일되고 (b) 실제로 타겟에 도달하며
(c) API 계약을 지키는가? → **self-repair 루프**: 컴파일 실패 시 컴파일러 에러를 LLM에
피드백해 재합성한다. 이게 이 컴포넌트의 진짜 기여다.

LLM은 전략층(원칙 1) — 하네스 코드를 *한 번* 생성하고, 실패 시에만 재호출한다(hot loop 아님).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

from raon.contracts import TargetDescriptor
from raon.llm import LLMRequest, Message, ModelTier, Provider

from .engine import CompiledHarness, CompileError, HarnessMode, compile_harness

_CODE_FENCE_RE = re.compile(r"```(?:c|cpp|c\+\+)?\s*(.*?)```", re.DOTALL)


@dataclass
class SynthAttempt:
    """합성 시도 하나의 기록(재현성·분석용)."""

    code: str
    compiled: bool
    error: str | None = None


@dataclass
class SynthResult:
    """하네스 합성 결과."""

    ok: bool
    harness: CompiledHarness | None = None
    code: str | None = None
    attempts: list[SynthAttempt] = field(default_factory=list)

    @property
    def repair_count(self) -> int:
        """재합성 횟수(첫 시도 제외)."""
        return max(0, len(self.attempts) - 1)


def extract_code(text: str) -> str:
    """LLM 응답에서 C 코드를 추출. 코드펜스가 있으면 그 안, 없으면 전체."""
    m = _CODE_FENCE_RE.search(text)
    return (m.group(1) if m else text).strip()


def _signature_desc(target: TargetDescriptor) -> str:
    sig = target.signature
    params = ", ".join(f"{p.type} {p.name}" for p in sig.params) or "const uint8_t *data, size_t size"
    return f"{sig.returns} {_entry_name(target)}({params})"


def _entry_name(target: TargetDescriptor) -> str:
    """타겟 위치에서 진입 함수명 추정.

    location이 함수명이면(예: 'decode') 그대로, 파일 경로면(예: 'src/decode.c:8')
    파일명 stem을 쓴다.
    """
    first = target.location.split(":")[0]
    if "/" in first or "." in first:
        return Path(first).stem
    return first


class HarnessSynthesizer:
    """시그니처 → libFuzzer/FILE_ARG 하네스 코드 → 컴파일 검증 → self-repair."""

    def __init__(
        self,
        provider: Provider,
        *,
        mode: HarnessMode = HarnessMode.FILE_ARG,
        max_repairs: int = 2,
        tier: ModelTier = ModelTier.PREMIUM,
    ):
        self._provider = provider
        self._mode = mode
        self._max_repairs = max_repairs
        self._tier = tier

    def _initial_prompt(self, target: TargetDescriptor) -> str:
        entry = _entry_name(target)
        if self._mode == HarnessMode.LIBFUZZER:
            shape = (
                "int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) 형태의 libFuzzer "
                "하네스를 작성하라. main을 넣지 마라."
            )
        else:
            shape = (
                "int main(int argc, char **argv)에서 argv[1] 파일을 버퍼로 읽어 타겟을 호출하는 "
                "완전한 C 프로그램을 작성하라."
            )
        return (
            "너는 퍼징 하네스를 작성하는 전문가다. 아래 타겟 함수를 호출하는 하네스를 C로 합성하라.\n"
            f"타겟 시그니처: {_signature_desc(target)}\n"
            f"진입 함수명: {entry}  (extern 선언해서 링크됨; 정의를 다시 쓰지 마라)\n"
            f"{shape}\n"
            "입력을 타겟의 파라미터로 적절히 매핑하라. 자원 초기화/해제 계약을 지켜라.\n"
            "코드만 출력하라(설명 금지). ```c 코드펜스로 감싸도 된다."
        )

    def _repair_prompt(self, code: str, error: str) -> str:
        return (
            "방금 하네스가 컴파일에 실패했다. 컴파일러 에러를 보고 고쳐서 다시 완전한 C 코드를 출력하라.\n\n"
            f"[이전 코드]\n{code}\n\n[컴파일러 에러]\n{error}\n\n코드만 출력하라."
        )

    def _ask(self, prompt: str) -> str:
        messages: list[Message] = [{"role": "user", "content": prompt}]
        resp = self._provider.complete(
            LLMRequest(
                messages=messages,
                tier=self._tier,
                purpose="harness_synth",
                effort="high",
                max_tokens=2048,
            )
        )
        return extract_code(resp.text)

    def synthesize(
        self,
        target: TargetDescriptor,
        target_source: str | Path,
        *,
        out: str | Path,
        workdir: str | Path | None = None,
    ) -> SynthResult:
        """하네스를 합성·컴파일하고 self-repair로 재시도. SynthResult 반환.

        target_source는 타겟 함수 정의를 담은 소스(main 없음). 합성된 드라이버와 함께 컴파일된다.
        """
        work = Path(workdir) if workdir else Path(out).parent
        work.mkdir(parents=True, exist_ok=True)
        driver_path = work / "harness_driver.c"

        code = self._ask(self._initial_prompt(target))
        attempts: list[SynthAttempt] = []

        for _ in range(self._max_repairs + 1):
            driver_path.write_text(code, encoding="utf-8")
            try:
                harness = compile_harness(
                    [driver_path, target_source], out, mode=self._mode
                )
                attempts.append(SynthAttempt(code=code, compiled=True))
                return SynthResult(ok=True, harness=harness, code=code, attempts=attempts)
            except CompileError as e:
                error = str(e)
                attempts.append(SynthAttempt(code=code, compiled=False, error=error))
                # self-repair: 에러를 피드백해 재합성
                code = self._ask(self._repair_prompt(code, error))

        return SynthResult(ok=False, harness=None, code=code, attempts=attempts)
