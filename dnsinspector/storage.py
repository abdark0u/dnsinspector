"""Historial de analisis guardado en SQLite."""

import json
import sqlite3
from contextlib import closing
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS analyses (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    domain TEXT NOT NULL,
    created_at TEXT NOT NULL,
    duration_ms INTEGER NOT NULL,
    highest_severity TEXT,
    counts TEXT NOT NULL,
    report TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_analyses_domain ON analyses(domain, created_at);
"""


class Storage:
    """Abre una conexion por operacion, asi no hay lios con los hilos de FastAPI."""

    def __init__(self, path: Path | str) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with closing(self._connect()) as conn:
            conn.executescript(SCHEMA)

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path)
        conn.row_factory = sqlite3.Row
        return conn

    def save(self, report: dict) -> int:
        summary = report["summary"]
        with closing(self._connect()) as conn, conn:
            cursor = conn.execute(
                "INSERT INTO analyses (domain, created_at, duration_ms, highest_severity, counts,"
                " report) VALUES (?, ?, ?, ?, ?, ?)",
                (
                    report["domain"],
                    report["started_at"],
                    report["duration_ms"],
                    summary["highest_severity"],
                    json.dumps(summary["counts"]),
                    json.dumps(report),
                ),
            )
            return int(cursor.lastrowid)

    def list(self, domain: str | None = None, limit: int = 50, offset: int = 0) -> list[dict]:
        sql = "SELECT id, domain, created_at, duration_ms, highest_severity, counts FROM analyses"
        params: list = []
        if domain:
            sql += " WHERE domain = ?"
            params.append(domain)
        sql += " ORDER BY created_at DESC, id DESC LIMIT ? OFFSET ?"
        params += [limit, offset]
        with closing(self._connect()) as conn:
            rows = conn.execute(sql, params).fetchall()
        return [{**dict(row), "counts": json.loads(row["counts"])} for row in rows]

    def get(self, analysis_id: int) -> dict | None:
        with closing(self._connect()) as conn:
            row = conn.execute(
                "SELECT report FROM analyses WHERE id = ?", (analysis_id,)
            ).fetchone()
        if row is None:
            return None
        return {"id": analysis_id, **json.loads(row["report"])}

    def delete(self, analysis_id: int) -> bool:
        with closing(self._connect()) as conn, conn:
            cursor = conn.execute("DELETE FROM analyses WHERE id = ?", (analysis_id,))
            return cursor.rowcount > 0
