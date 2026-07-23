"""크래시 스택 정규화 & `dedup_key` 계산 (D3, 00 §3.3).

`dedup_key = sha1(normalized_stack + category)`의 **"normalized"를 여기서 못박는다.**
정규화가 부실하면 같은 버그가 다른 key를 받아(under-dedup) dedup 정확도가 무너지고,
과하면 다른 버그가 같은 key로 뭉쳐(over-dedup) unique-bug 수가 왜곡된다.

## 정규화 규약 (ClusterFuzz/AFL 스택 해싱 관행 기반)

1. **상위 N 프레임만** 사용(기본 N=5). 깊은 프레임은 호출 문맥에 따라 요동쳐 노이즈.
2. 프레임 서명 = **함수명** (있으면). 함수명이 없으면 **소스 파일 basename**으로 대체.
3. 제거 대상(빌드/실행마다 달라지는 것):
   - 절대 주소 `0x55a3f2e1` 및 모듈 로드 오프셋 `+0x1a2b`
   - 빌드 경로 접두사 → 파일은 basename만 (`/home/u/magma/src/png.c` → `png.c`)
   - 라인:컬럼 번호 (`png.c:1234:5` → `png.c`) — 리빌드로 흔들리므로 key에서 제외
   - PID/TID, 템플릿 인자 내부 공백 정규화
4. 프레임들을 개행으로 join → `"|" + category` 접미 → sha1 hex.

라인 번호를 key에서 빼는 건 의도적이다: 같은 함수의 같은 버그가 리빌드로 라인이 밀려도
같은 key를 받아야 한다(under-dedup 방지). 대신 함수+파일 조합으로 서로 다른 버그를 구분한다.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Sequence
from dataclasses import dataclass

from raon.contracts.enums import FindingCategory

DEFAULT_TOP_N = 5

_ADDR_RE = re.compile(r"0x[0-9a-fA-F]+")
_OFFSET_RE = re.compile(r"\+0x[0-9a-fA-F]+")
_WS_RE = re.compile(r"\s+")
# 파일 경로 뒤에 붙는 :line 또는 :line:col
_LINECOL_RE = re.compile(r":\d+(?::\d+)?$")


@dataclass(frozen=True)
class Frame:
    """정규화 대상 스택 프레임 하나.

    ASan 파서(`raon.fuzzing.asan`)가 이 형태로 프레임을 넘긴다.
    `function`/`file` 중 최소 하나는 있어야 유의미하다.
    """

    function: str | None = None
    file: str | None = None  # 원본 경로 (basename+line:col 포함 가능)


def _basename(path: str) -> str:
    """경로에서 파일명만. 라인:컬럼 접미도 제거."""
    # 경로 구분자 뒤부분
    base = re.split(r"[\\/]", path)[-1]
    return _LINECOL_RE.sub("", base)


def _clean_function(func: str) -> str:
    """함수명에서 주소/오프셋 노이즈 제거 + 공백 정규화."""
    func = _OFFSET_RE.sub("", func)
    func = _ADDR_RE.sub("", func)
    func = _WS_RE.sub(" ", func).strip()
    return func


def normalize_frame(frame: Frame) -> str | None:
    """프레임 하나를 안정적 서명 문자열로. 유의미한 정보가 없으면 None."""
    if frame.function:
        cleaned = _clean_function(frame.function)
        # 함수명이 순수 주소만 남으면(심볼 없음) 파일로 폴백
        if cleaned and not _ADDR_RE.fullmatch(cleaned):
            return cleaned
    if frame.file:
        base = _basename(frame.file)
        if base:
            return base
    return None


def normalize_stack(frames: Sequence[Frame], top_n: int = DEFAULT_TOP_N) -> list[str]:
    """상위 N 프레임을 정규화 서명 리스트로. 노이즈 프레임(None)은 스킵.

    스킵으로 상위 프레임이 비어도, 다음 유의미 프레임으로 채우기 위해 전체를 훑되
    최대 top_n개까지만 수집한다.
    """
    out: list[str] = []
    for fr in frames:
        sig = normalize_frame(fr)
        if sig is None:
            continue
        out.append(sig)
        if len(out) >= top_n:
            break
    return out


def dedup_key(
    frames: Sequence[Frame],
    category: FindingCategory | str,
    top_n: int = DEFAULT_TOP_N,
) -> str:
    """`sha1(normalized_stack + category)` — Finding의 중복제거 키.

    프레임이 하나도 유의미하지 않으면(심볼 전무) 카테고리만으로 key를 만든다
    (최소한 카테고리 단위 클러스터링은 유지).
    """
    cat = category.value if isinstance(category, FindingCategory) else str(category)
    normalized = normalize_stack(frames, top_n=top_n)
    payload = "\n".join(normalized) + "|" + cat
    return hashlib.sha1(payload.encode("utf-8")).hexdigest()


def dedup_key_from_functions(
    function_names: Sequence[str],
    category: FindingCategory | str,
    top_n: int = DEFAULT_TOP_N,
) -> str:
    """함수명 리스트만 있을 때의 편의 함수(정적 분석 Finding 등)."""
    frames = [Frame(function=fn) for fn in function_names]
    return dedup_key(frames, category, top_n=top_n)
