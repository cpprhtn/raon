"""CLI 테스트 (P1-5): 서브커맨드 동작 + 실제 run 관통."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from raon.cli import main
from raon.fuzzing.engine import clang_path

FIXTURES = Path(__file__).parent.parent / "fixtures"
REPORT = FIXTURES / "sanitizer" / "heap_buffer_overflow.txt"
TARGET = FIXTURES / "targets" / "vuln_decode.c"


def test_version(capsys) -> None:
    assert main(["version"]) == 0
    assert "raon" in capsys.readouterr().out


def test_kb_lists_png(capsys) -> None:
    assert main(["kb"]) == 0
    out = capsys.readouterr().out
    assert "image/png" in out


def test_triage_report(capsys) -> None:
    rc = main(["triage", str(REPORT), "--target-id", "tgt_x"])
    assert rc == 0
    data = json.loads(capsys.readouterr().out)
    assert data["category"] == "memory"
    assert data["source_component"] == "crash_triage"


def test_triage_stores_to_db(tmp_path: Path, capsys) -> None:
    db = tmp_path / "bb.sqlite"
    main(["triage", str(REPORT), "--target-id", "t", "--db", str(db)])
    capsys.readouterr()
    # report 커맨드로 다시 읽힘
    assert main(["report", "--db", str(db)]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["unique_bugs"] == 1


def test_triage_unrecognized_returns_2(tmp_path: Path) -> None:
    junk = tmp_path / "junk.txt"
    junk.write_text("not a crash")
    assert main(["triage", str(junk)]) == 2


@pytest.mark.integration
@pytest.mark.skipif(clang_path() is None, reason="clang not available")
def test_run_end_to_end(tmp_path: Path, capsys) -> None:
    """★ raon run: 컴파일 → 크래시 입력 실행 → 트리아지 → 리포트."""
    good = tmp_path / "good.bin"
    good.write_bytes(b"AA")
    bad = tmp_path / "bad.bin"
    bad.write_bytes(b"A" * 32)
    rc = main(
        [
            "run",
            str(TARGET),
            "--input",
            str(good),
            "--input",
            str(bad),
            "--db",
            str(tmp_path / "raon.sqlite"),
            "--workdir",
            str(tmp_path / "work"),
        ]
    )
    assert rc == 0
    report = json.loads(capsys.readouterr().out)
    assert report["inputs_run"] == 2
    assert report["crashes"] == 1  # bad.bin만 크래시
    assert report["unique_bugs"] == 1
    assert report["findings"][0]["exploitability"] is not None
