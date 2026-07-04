"""SQLite storage for the web interface.

Each uploaded file becomes one job database. Records and detections are
inserted in batches while parsing streams, so the browser can page and
filter server-side even on multi-GB inputs.
"""

from __future__ import annotations

import json
import re
import sqlite3
from typing import Any, Dict, List, Optional, Tuple

RECORD_COLUMNS = (
    "timestamp", "date", "time", "s_ip", "method", "uri_stem", "uri_query",
    "s_port", "c_ip", "username", "user_agent", "referer", "status",
    "substatus", "win32_status", "time_taken", "host", "url", "raw", "line",
)
DETECTION_COLUMNS = (
    "detection", "severity", "description", "timestamp", "c_ip", "method",
    "uri", "status", "field", "value", "line",
)

FILTER_MODES = ("contains", "exact", "regex", "startswith", "endswith",
                "not_contains", "gte", "lte")

_LOG_FIELDS = set(RECORD_COLUMNS)
_DET_FIELDS = set(DETECTION_COLUMNS)


def _regexp(pattern: str, value: Optional[str]) -> bool:
    if value is None:
        return False
    try:
        return re.search(pattern, value, re.IGNORECASE) is not None
    except re.error:
        return False


class Store:
    def __init__(self, path: str):
        self.conn = sqlite3.connect(path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.conn.create_function("REGEXP", 2, lambda p, v: _regexp(p, v))
        self.conn.executescript("""
            PRAGMA journal_mode=WAL;
            PRAGMA synchronous=OFF;
            CREATE TABLE IF NOT EXISTS records (
                id INTEGER PRIMARY KEY,
                timestamp TEXT, date TEXT, time TEXT, s_ip TEXT, method TEXT,
                uri_stem TEXT, uri_query TEXT, s_port INTEGER, c_ip TEXT,
                username TEXT, user_agent TEXT, referer TEXT, status INTEGER,
                substatus INTEGER, win32_status INTEGER, time_taken INTEGER,
                host TEXT, url TEXT, raw TEXT, line INTEGER);
            CREATE TABLE IF NOT EXISTS detections (
                id INTEGER PRIMARY KEY,
                detection TEXT, severity TEXT, description TEXT,
                timestamp TEXT, c_ip TEXT, method TEXT, uri TEXT,
                status INTEGER, field TEXT, value TEXT, line INTEGER);
            CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT);
        """)

    def create_indexes(self) -> None:
        """Deferred until after bulk load — much faster for big files."""
        self.conn.executescript("""
            CREATE INDEX IF NOT EXISTS idx_rec_ts ON records(timestamp);
            CREATE INDEX IF NOT EXISTS idx_rec_ip ON records(c_ip);
            CREATE INDEX IF NOT EXISTS idx_rec_status ON records(status);
            CREATE INDEX IF NOT EXISTS idx_rec_uri ON records(uri_stem);
            CREATE INDEX IF NOT EXISTS idx_det_ts ON detections(timestamp);
            CREATE INDEX IF NOT EXISTS idx_det_sev ON detections(severity);
            CREATE INDEX IF NOT EXISTS idx_det_name ON detections(detection);
            CREATE INDEX IF NOT EXISTS idx_det_ip ON detections(c_ip);
        """)
        self.conn.commit()

    def insert_records(self, rows: List[Dict[str, Any]]) -> None:
        self.conn.executemany(
            f"INSERT INTO records ({','.join(RECORD_COLUMNS)}) "
            f"VALUES ({','.join('?' * len(RECORD_COLUMNS))})",
            [tuple(row.get(col) for col in RECORD_COLUMNS) for row in rows])

    def insert_detections(self, rows: List[Dict[str, Any]]) -> None:
        self.conn.executemany(
            f"INSERT INTO detections ({','.join(DETECTION_COLUMNS)}) "
            f"VALUES ({','.join('?' * len(DETECTION_COLUMNS))})",
            [tuple(row.get(col) for col in DETECTION_COLUMNS) for row in rows])

    def commit(self) -> None:
        self.conn.commit()

    def set_meta(self, key: str, value: Any) -> None:
        self.conn.execute(
            "INSERT OR REPLACE INTO meta (key, value) VALUES (?, ?)",
            (key, json.dumps(value)))
        self.conn.commit()

    def get_meta(self, key: str) -> Any:
        row = self.conn.execute(
            "SELECT value FROM meta WHERE key = ?", (key,)).fetchone()
        return json.loads(row["value"]) if row else None

    # ------------------------------------------------------------------
    # querying

    def _where(self, filters: List[Dict[str, Any]], allowed: set,
               free_text_columns: Tuple[str, ...]) -> Tuple[str, List[Any]]:
        clauses: List[str] = []
        params: List[Any] = []
        for flt in filters or []:
            field = flt.get("field", "")
            mode = flt.get("mode", "contains")
            value = flt.get("value", "")
            if mode not in FILTER_MODES:
                raise ValueError(f"Unknown filter mode: {mode!r}")
            if field in ("_text", "_regex"):
                mode = "regex" if field == "_regex" else mode
                sub, sub_params = [], []
                for column in free_text_columns:
                    clause, clause_params = self._clause(column, mode, value)
                    sub.append(clause)
                    sub_params.extend(clause_params)
                clauses.append(f"({' OR '.join(sub)})")
                params.extend(sub_params)
                continue
            if field in allowed:
                column = field
            else:
                raise ValueError(f"Unknown filter field: {field!r}")
            clause, clause_params = self._clause(column, mode, value)
            clauses.append(clause)
            params.extend(clause_params)
        where = f" WHERE {' AND '.join(clauses)}" if clauses else ""
        return where, params

    @staticmethod
    def _clause(column: str, mode: str, value: Any) -> Tuple[str, List[Any]]:
        escaped = str(value).replace("\\", "\\\\") \
                            .replace("%", r"\%").replace("_", r"\_")
        if mode == "contains":
            return f"{column} LIKE ? ESCAPE '\\'", [f"%{escaped}%"]
        if mode == "not_contains":
            return (f"({column} IS NULL OR {column} NOT LIKE ? ESCAPE '\\')",
                    [f"%{escaped}%"])
        if mode == "exact":
            return f"{column} = ?", [value]
        if mode == "startswith":
            return f"{column} LIKE ? ESCAPE '\\'", [f"{escaped}%"]
        if mode == "endswith":
            return f"{column} LIKE ? ESCAPE '\\'", [f"%{escaped}"]
        if mode == "regex":
            return f"REGEXP(?, {column})", [str(value)]
        op = ">=" if mode == "gte" else "<="
        return f"{column} {op} ?", [value]

    def _page(self, table: str, allowed: set,
              free_text_columns: Tuple[str, ...],
              filters: List[Dict[str, Any]], page: int, size: int,
              order: str) -> Dict[str, Any]:
        page = max(1, int(page))
        size = min(500, max(1, int(size)))
        where, params = self._where(filters, allowed, free_text_columns)
        total = self.conn.execute(
            f"SELECT COUNT(*) AS n FROM {table}{where}", params).fetchone()["n"]
        rows = self.conn.execute(
            f"SELECT * FROM {table}{where} ORDER BY {order} LIMIT ? OFFSET ?",
            params + [size, (page - 1) * size]).fetchall()
        return {"total": total, "page": page, "size": size,
                "pages": max(1, -(-total // size)),
                "rows": [dict(row) for row in rows]}

    def query_logs(self, filters: List[Dict[str, Any]], page: int = 1,
                   size: int = 50) -> Dict[str, Any]:
        return self._page("records", _LOG_FIELDS, ("raw", "url"),
                          filters, page, size, "id")

    def query_detections(self, filters: List[Dict[str, Any]], page: int = 1,
                         size: int = 50) -> Dict[str, Any]:
        return self._page("detections", _DET_FIELDS,
                          ("value", "uri", "detection"), filters, page,
                          size, "CASE severity WHEN 'critical' THEN 0 "
                          "WHEN 'high' THEN 1 WHEN 'medium' THEN 2 "
                          "ELSE 3 END, id")

    def close(self) -> None:
        self.conn.close()
