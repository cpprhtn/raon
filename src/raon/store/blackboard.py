"""블랙보드 저장소 — SQLite(WAL) + 파일시스템 (P0-3).

## 설계 결정 (D8: 동시성)
- **SQLite WAL 모드**: 다중 리더 + 단일 라이터 동시성. 퍼저 프로세스가 크래시를 쓰는 동안
  에이전트가 읽을 수 있다.
- **쓰기 단일화**: 쓰기는 `threading.Lock`으로 직렬화(같은 프로세스 내). 퍼저는 매 exec가 아니라
  *크래시/코퍼스 스냅샷* 단위로만 쓰므로 쓰기 빈도가 낮아 이 모델로 충분(원칙 1).
- **저장 형태**: 각 계약 모델의 전체 JSON을 `data` 컬럼에 보관하고, 쿼리에 쓰는 필드
  (id·target_id·dedup_key·category…)만 별도 컬럼으로 인덱싱한다. 스키마 진화(D14)에 유연.

## 아티팩트
시드/재현물 같은 바이너리는 `artifacts/` 하위에 저장하고 계약 모델은 그 경로만 참조한다.
"""

from __future__ import annotations

import contextlib
import sqlite3
import threading
from collections.abc import Iterator
from pathlib import Path
from types import TracebackType

from raon.contracts import (
    Corpus,
    Finding,
    KnowledgeBase,
    TargetDescriptor,
)

_SCHEMA = """
CREATE TABLE IF NOT EXISTS targets (
    id             TEXT PRIMARY KEY,
    kind           TEXT NOT NULL,
    priority_score REAL NOT NULL DEFAULT 0,
    data           TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS corpus (
    target_id TEXT PRIMARY KEY,
    data      TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS findings (
    id               TEXT PRIMARY KEY,
    target_id        TEXT NOT NULL,
    category         TEXT NOT NULL,
    source_component TEXT NOT NULL,
    dedup_key        TEXT NOT NULL,
    confidence       REAL NOT NULL,
    exploitability   REAL,
    data             TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_findings_dedup  ON findings(dedup_key);
CREATE INDEX IF NOT EXISTS ix_findings_target ON findings(target_id);

CREATE TABLE IF NOT EXISTS knowledge (
    domain TEXT PRIMARY KEY,
    data   TEXT NOT NULL
);
"""


class Blackboard:
    """공유 저장소. 컨텍스트 매니저로 쓰거나 명시적으로 `close()`한다.

    >>> with Blackboard(":memory:") as bb:
    ...     _ = bb.put_target(TargetDescriptor(kind="module", location="x"))
    """

    def __init__(self, db_path: str | Path = ":memory:", *, artifacts_dir: str | Path | None = None):
        self._db_path = str(db_path)
        self._is_memory = self._db_path == ":memory:"
        self._write_lock = threading.Lock()
        # 스레드마다 자기 연결을 갖는다(D8). SQLite WAL은 여러 연결을 전제로 한
        # "다중 리더 + 단일 라이터" 동시성을 지원하지만, *하나의* 연결을 여러 스레드가
        # 공유하면 커서 상태가 엉킨다. 그래서 thread-local 연결을 쓴다.
        self._local = threading.local()
        self._all_conns: list[sqlite3.Connection] = []
        self._conns_lock = threading.Lock()

        if self._is_memory:
            # in-memory DB를 여러 연결이 공유하려면 shared-cache URI가 필요하고,
            # 최소 하나의 연결이 열려 있어야 DB가 파괴되지 않는다(keepalive).
            self._uri = f"file:raon_mem_{id(self)}?mode=memory&cache=shared"
            self._use_uri = True
        else:
            self._uri = self._db_path
            self._use_uri = False

        self._keepalive = self._new_connection()
        with self._keepalive:  # 스키마 초기화
            self._keepalive.executescript(_SCHEMA)

        if artifacts_dir is not None:
            self.artifacts_dir = Path(artifacts_dir)
        elif not self._is_memory:
            self.artifacts_dir = Path(self._db_path).parent / "artifacts"
        else:
            self.artifacts_dir = Path(".raon_artifacts")

    def _new_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._uri, uri=self._use_uri, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA busy_timeout=5000")
        if not self._is_memory:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=NORMAL")
        conn.execute("PRAGMA foreign_keys=ON")
        with self._conns_lock:
            self._all_conns.append(conn)
        return conn

    @property
    def _conn(self) -> sqlite3.Connection:
        """현재 스레드의 연결(없으면 생성)."""
        conn: sqlite3.Connection | None = getattr(self._local, "conn", None)
        if conn is None:
            conn = self._new_connection()
            self._local.conn = conn
        return conn

    # ---- lifecycle -------------------------------------------------------
    def close(self) -> None:
        with self._conns_lock:
            for conn in self._all_conns:
                with contextlib.suppress(sqlite3.Error):
                    conn.close()
            self._all_conns.clear()

    def __enter__(self) -> Blackboard:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.close()

    # ---- targets ---------------------------------------------------------
    def put_target(self, target: TargetDescriptor) -> str:
        """타겟 upsert. id 반환."""
        with self._write_lock:
            self._conn.execute(
                "INSERT INTO targets(id, kind, priority_score, data) VALUES(?,?,?,?) "
                "ON CONFLICT(id) DO UPDATE SET "
                "kind=excluded.kind, priority_score=excluded.priority_score, data=excluded.data",
                (
                    target.id,
                    target.kind.value,
                    target.priority_score,
                    target.model_dump_json(),
                ),
            )
            self._conn.commit()
        return target.id

    def get_target(self, target_id: str) -> TargetDescriptor | None:
        row = self._conn.execute(
            "SELECT data FROM targets WHERE id=?", (target_id,)
        ).fetchone()
        return TargetDescriptor.model_validate_json(row["data"]) if row else None

    def list_targets(self, *, by_priority: bool = False) -> list[TargetDescriptor]:
        order = "ORDER BY priority_score DESC, id ASC" if by_priority else "ORDER BY id ASC"
        rows = self._conn.execute(f"SELECT data FROM targets {order}").fetchall()
        return [TargetDescriptor.model_validate_json(r["data"]) for r in rows]

    def set_priority(self, target_id: str, priority_score: float) -> None:
        """[02]가 타겟 우선순위를 갱신(피드백 루프)."""
        tgt = self.get_target(target_id)
        if tgt is None:
            raise KeyError(f"unknown target: {target_id}")
        tgt.priority_score = priority_score
        self.put_target(tgt)

    # ---- corpus ----------------------------------------------------------
    def put_corpus(self, corpus: Corpus) -> None:
        with self._write_lock:
            self._conn.execute(
                "INSERT INTO corpus(target_id, data) VALUES(?,?) "
                "ON CONFLICT(target_id) DO UPDATE SET data=excluded.data",
                (corpus.target_id, corpus.model_dump_json()),
            )
            self._conn.commit()

    def get_corpus(self, target_id: str) -> Corpus | None:
        row = self._conn.execute(
            "SELECT data FROM corpus WHERE target_id=?", (target_id,)
        ).fetchone()
        return Corpus.model_validate_json(row["data"]) if row else None

    # ---- findings --------------------------------------------------------
    def put_finding(self, finding: Finding) -> str:
        """Finding upsert(id 기준). 저장소는 dedup하지 않고 전부 보관한다 —
        dedup은 트리아지 단계의 쿼리로 수행(00 §4의 6단계). id 반환."""
        with self._write_lock:
            self._conn.execute(
                "INSERT INTO findings"
                "(id, target_id, category, source_component, dedup_key, confidence, exploitability, data) "
                "VALUES(?,?,?,?,?,?,?,?) "
                "ON CONFLICT(id) DO UPDATE SET "
                "target_id=excluded.target_id, category=excluded.category, "
                "source_component=excluded.source_component, dedup_key=excluded.dedup_key, "
                "confidence=excluded.confidence, exploitability=excluded.exploitability, "
                "data=excluded.data",
                (
                    finding.id,
                    finding.target_id,
                    finding.category.value,
                    finding.source_component.value,
                    finding.dedup_key,
                    finding.confidence,
                    finding.exploitability,
                    finding.model_dump_json(),
                ),
            )
            self._conn.commit()
        return finding.id

    def get_finding(self, finding_id: str) -> Finding | None:
        row = self._conn.execute(
            "SELECT data FROM findings WHERE id=?", (finding_id,)
        ).fetchone()
        return Finding.model_validate_json(row["data"]) if row else None

    def list_findings(self, *, target_id: str | None = None) -> list[Finding]:
        if target_id is not None:
            rows = self._conn.execute(
                "SELECT data FROM findings WHERE target_id=? ORDER BY id ASC", (target_id,)
            ).fetchall()
        else:
            rows = self._conn.execute("SELECT data FROM findings ORDER BY id ASC").fetchall()
        return [Finding.model_validate_json(r["data"]) for r in rows]

    def findings_by_dedup_key(self, dedup_key: str) -> list[Finding]:
        rows = self._conn.execute(
            "SELECT data FROM findings WHERE dedup_key=? ORDER BY id ASC", (dedup_key,)
        ).fetchall()
        return [Finding.model_validate_json(r["data"]) for r in rows]

    def count_unique_findings(self) -> int:
        """서로 다른 dedup_key 수 = unique bug 근사치(00 §8 핵심 지표)."""
        row = self._conn.execute(
            "SELECT COUNT(DISTINCT dedup_key) AS n FROM findings"
        ).fetchone()
        return int(row["n"])

    def clusters(self) -> dict[str, list[Finding]]:
        """dedup_key → Finding[] 클러스터. 트리아지 1차 클러스터링(02 §4.1)."""
        out: dict[str, list[Finding]] = {}
        for f in self.list_findings():
            out.setdefault(f.dedup_key, []).append(f)
        return out

    # ---- knowledge -------------------------------------------------------
    def put_knowledge(self, kb: KnowledgeBase) -> None:
        with self._write_lock:
            self._conn.execute(
                "INSERT INTO knowledge(domain, data) VALUES(?,?) "
                "ON CONFLICT(domain) DO UPDATE SET data=excluded.data",
                (kb.domain, kb.model_dump_json()),
            )
            self._conn.commit()

    def get_knowledge(self, domain: str) -> KnowledgeBase | None:
        row = self._conn.execute(
            "SELECT data FROM knowledge WHERE domain=?", (domain,)
        ).fetchone()
        return KnowledgeBase.model_validate_json(row["data"]) if row else None

    def knowledge_for_tags(self, domain_tags: list[str]) -> list[KnowledgeBase]:
        """타겟의 domain_tags와 매칭되는 KB들을 찾는다(부분 문자열 매칭).

        예: tag 'image'/'png' ↔ domain 'image/png'.
        """
        results: list[KnowledgeBase] = []
        rows = self._conn.execute("SELECT domain, data FROM knowledge").fetchall()
        for r in rows:
            domain = r["domain"]
            if any(tag in domain or domain in tag for tag in domain_tags):
                results.append(KnowledgeBase.model_validate_json(r["data"]))
        return results

    # ---- misc ------------------------------------------------------------
    def iter_targets_by_priority(self) -> Iterator[TargetDescriptor]:
        yield from self.list_targets(by_priority=True)
