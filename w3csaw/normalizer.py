"""Normalize raw W3C records into the stable W3CSaw schema."""

from __future__ import annotations

import os
from datetime import timezone
from typing import Any, Dict, Optional

from .parser import RawRecord
from .utils import build_timestamp, safe_int, url_decode

# W3C field name -> normalized schema name
FIELD_MAP: Dict[str, str] = {
    "date": "date",
    "time": "time",
    "s-sitename": "site_name",
    "s-ip": "server_ip",
    "cs-method": "method",
    "cs-uri-stem": "uri_path",
    "cs-uri-query": "uri_query",
    "c-ip": "src_ip",
    "cs-username": "username",
    "cs(User-Agent)": "user_agent",
    "cs(Referer)": "referer",
    "sc-status": "status",
    "sc-substatus": "substatus",
    "sc-win32-status": "win32_status",
    "sc-bytes": "bytes_sent",
    "cs-bytes": "bytes_received",
    "time-taken": "time_taken",
    "cs-host": "host",
}

INT_FIELDS = frozenset({
    "status", "substatus", "win32_status",
    "bytes_sent", "bytes_received", "time_taken",
})

# Every record carries these keys even when the source log omits the field.
SCHEMA_KEYS = (
    "timestamp", "date", "time", "site_name", "server_ip", "method",
    "uri_path", "uri_query", "src_ip", "username", "user_agent", "referer",
    "status", "substatus", "win32_status", "bytes_sent", "bytes_received",
    "time_taken", "host",
)


def normalize(record: RawRecord, tz: timezone = timezone.utc) -> Dict[str, Any]:
    """Map a RawRecord into the normalized schema with derived helper fields."""
    row: Dict[str, Any] = {key: None for key in SCHEMA_KEYS}

    for w3c_name, value in record.fields.items():
        key = FIELD_MAP.get(w3c_name, w3c_name)
        if value == "-":
            row[key] = None
        elif key in INT_FIELDS:
            row[key] = safe_int(value)
        else:
            row[key] = value

    row["timestamp"] = build_timestamp(row.get("date"), row.get("time"), tz)

    uri_path = row.get("uri_path")
    uri_query = row.get("uri_query")
    if uri_path and uri_query:
        row["url_original"] = f"{uri_path}?{uri_query}"
    else:
        row["url_original"] = uri_path
    row["uri_path_decoded"] = url_decode(uri_path)
    row["uri_query_decoded"] = url_decode(uri_query)
    row["url_decoded"] = url_decode(row["url_original"])

    status = row.get("status")
    row["is_success_status"] = status is not None and 200 <= status < 400
    row["is_error_status"] = status is not None and status >= 400
    row["extension"] = _extension(row.get("uri_path_decoded"))

    row["raw_line"] = record.raw_line
    row["log_file"] = record.log_file
    row["line_number"] = record.line_number
    return row


def _extension(path: Optional[str]) -> Optional[str]:
    if not path:
        return None
    ext = os.path.splitext(path.split("?", 1)[0])[1]
    return ext.lower() if ext else None
