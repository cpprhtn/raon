"""JSON 도메인 지식 (0.2.0 도메인 팩 확장).

PNG(바이너리 포맷)과 대비되는 텍스트 포맷 파서 대상. [01] 시드/문법과 [02] 추론 근거로
소비된다. JSON 파서는 재귀 하강이 많아 깊은 중첩·큰 수·유니코드 이스케이프에서 약하다.
"""

from __future__ import annotations

from pathlib import Path

from raon.contracts import KnowledgeBase

JSON_DOMAIN = "text/json"

# 구조적으로 유효한 최소 시드들(경계를 건드리기 좋은 씨앗).
JSON_SEEDS: list[bytes] = [
    b"{}",
    b"[]",
    b'{"a":1}',
    b'[1,2,3]',
    b'{"k":"v","n":-0.0e0,"b":true,"z":null}',
    b'[[[[[]]]]]',  # 중첩 씨앗(깊은 중첩 변이 유도)
    b'{"u":"\\u0041\\ud83d\\ude00"}',  # 유니코드 이스케이프
]


def json_knowledge_base() -> KnowledgeBase:
    """text/json 도메인의 KnowledgeBase."""
    return KnowledgeBase(
        domain=JSON_DOMAIN,
        grammar="json",
        seed_templates=["templates/min.json"],
        invariants=[
            "braces {} and brackets [] are balanced and properly nested",
            "strings are double-quoted with valid \\uXXXX / escape sequences",
            "numbers match JSON grammar (no leading zeros, valid exponent)",
            "no trailing bytes after the top-level value",
            "input is valid UTF-8",
        ],
        known_weak_interfaces=[
            "깊은 중첩 — 재귀 하강 파서의 스택 오버플로우",
            "매우 큰/정밀한 수 파싱 (정수 오버플로우·부동소수 처리)",
            "\\uXXXX 유니코드 이스케이프·서로게이트 페어 경계",
            "긴 문자열·거대 배열의 메모리 증폭",
            "중복 키·비정상 제어문자 처리",
        ],
    )


def write_seed_templates(dest_dir: str | Path) -> list[str]:
    """JSON 시드 템플릿들을 dest_dir에 쓰고 경로 리스트 반환."""
    dest = Path(dest_dir)
    dest.mkdir(parents=True, exist_ok=True)
    paths: list[str] = []
    for i, seed in enumerate(JSON_SEEDS):
        p = dest / ("min.json" if i == 0 else f"seed_{i:02d}.json")
        p.write_bytes(seed)
        paths.append(str(p))
    return paths
