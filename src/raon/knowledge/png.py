"""PNG 도메인 지식 (P0-8, 00 §3.4).

이 KnowledgeBase는 두 곳에서 동시에 소비된다:
- [01] 퍼징: seed_templates(유효 최소 PNG)·invariants로 구조 인지 시드 생성
- [02] Agent C: known_weak_interfaces로 크래시 없이 취약 가설 추론

`minimal_png()`는 실제로 유효한 1×1 PNG 바이트를 생성한다 → 퍼징 시드 프라이밍의 씨앗.
"""

from __future__ import annotations

import struct
import zlib
from pathlib import Path

from raon.contracts import KnowledgeBase

PNG_DOMAIN = "image/png"
PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"


def _chunk(chunk_type: bytes, data: bytes) -> bytes:
    """PNG 청크 하나: length(4) + type(4) + data + crc(4)."""
    body = chunk_type + data
    crc = zlib.crc32(body) & 0xFFFFFFFF
    return struct.pack(">I", len(data)) + body + struct.pack(">I", crc)


def minimal_png() -> bytes:
    """유효한 1×1 8-bit RGB PNG 바이트 생성.

    시그니처 + IHDR + IDAT(압축된 한 스캔라인) + IEND. 퍼저 시드로 바로 쓸 수 있다.
    """
    # IHDR: width=1, height=1, bit_depth=8, color_type=2(RGB), 나머지 0
    ihdr = struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0)
    # 한 스캔라인: 필터바이트(0) + RGB(3 bytes)
    raw = b"\x00\xff\x00\x00"
    idat = zlib.compress(raw)
    return PNG_SIGNATURE + _chunk(b"IHDR", ihdr) + _chunk(b"IDAT", idat) + _chunk(b"IEND", b"")


def png_knowledge_base() -> KnowledgeBase:
    """image/png 도메인의 KnowledgeBase."""
    return KnowledgeBase(
        domain=PNG_DOMAIN,
        grammar="png",  # 문법 식별자 (Nautilus/Grammarinator 연동 시 실제 문법으로)
        seed_templates=["templates/min.png"],
        invariants=[
            "signature == 89 50 4E 47 0D 0A 1A 0A",
            "chunk_length <= remaining_bytes",  # 경계 오버플로우 유발점
            "chunk CRC matches computed crc32(type+data)",
            "first chunk is IHDR, last chunk is IEND",
            "IHDR width/height are non-zero and <= 2^31-1",
            "IDAT streams form a valid zlib stream",
            "bit_depth in {1,2,4,8,16} consistent with color_type",
        ],
        known_weak_interfaces=[
            "idat inflate 경계 — 압축 해제 길이 vs 선언 크기 불일치",
            "chunk length 필드 정수 오버플로우 (거대 length)",
            "tRNS/PLTE 인덱스 경계 초과",
            "iCCP/zTXt 압축 프로파일 zlib 폭탄",
            "인터레이스(Adam7) 패스 크기 계산 오버플로우",
        ],
    )


def write_seed_templates(dest_dir: str | Path) -> list[str]:
    """시드 템플릿 파일들을 dest_dir에 쓰고 경로 리스트 반환."""
    dest = Path(dest_dir)
    dest.mkdir(parents=True, exist_ok=True)
    min_path = dest / "min.png"
    min_path.write_bytes(minimal_png())
    return [str(min_path)]
