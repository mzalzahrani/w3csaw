"""Streaming parsers with content-based format detection.

Supported inputs: IIS W3C extended logs, CSV exports, and plain text files
containing IIS-like log lines. Format is decided by inspecting the first
chunk of the file, never by extension alone. All parsers are generators —
the whole file is never loaded into memory, so multi-GB inputs are fine.
"""

from __future__ import annotations

import csv
import io
import logging
import os
import re
import time as time_mod
from datetime import datetime
from typing import Any, Dict, Iterator, List, Optional
from urllib.parse import unquote_plus

logger = logging.getLogger("iis_hunter")

FIELDS_PREFIX = "#Fields:"
SNIFF_BYTES = 65536

# W3C / CSV column name -> canonical schema name. Keys are lowercased with
# underscores and spaces collapsed to hyphens before lookup.
FIELD_MAP: Dict[str, str] = {
    "date": "date",
    "time": "time",
    "datetime": "timestamp",
    "timestamp": "timestamp",
    "s-sitename": "site_name",
    "s-computername": "computer_name",
    "s-ip": "s_ip",
    "server-ip": "s_ip",
    "cs-method": "method",
    "method": "method",
    "cs-uri-stem": "uri_stem",
    "uri-stem": "uri_stem",
    "url": "uri_stem",
    "cs-uri-query": "uri_query",
    "uri-query": "uri_query",
    "query": "uri_query",
    "s-port": "s_port",
    "port": "s_port",
    "cs-username": "username",
    "username": "username",
    "c-ip": "c_ip",
    "client-ip": "c_ip",
    "clientip": "c_ip",
    "source-ip": "c_ip",
    "src-ip": "c_ip",
    "cs(user-agent)": "user_agent",
    "cs-user-agent": "user_agent",
    "user-agent": "user_agent",
    "useragent": "user_agent",
    "cs(referer)": "referer",
    "cs-referer": "referer",
    "referer": "referer",
    "referrer": "referer",
    "cs(cookie)": "cookie",
    "sc-status": "status",
    "status": "status",
    "status-code": "status",
    "sc-substatus": "substatus",
    "substatus": "substatus",
    "sc-win32-status": "win32_status",
    "win32-status": "win32_status",
    "sc-bytes": "bytes_sent",
    "cs-bytes": "bytes_received",
    "time-taken": "time_taken",
    "timetaken": "time_taken",
    "cs-host": "host",
    "host": "host",
    "cs-version": "protocol",
    "x-forwarded-for": "x_forwarded_for",
}

INT_FIELDS = frozenset({
    "s_port", "status", "substatus", "win32_status",
    "bytes_sent", "bytes_received", "time_taken",
})

# Canonical W3C layouts, keyed by token count, used for header-less plain
# text lines that look like IIS log rows.
_PLAIN_LAYOUTS: Dict[int, List[str]] = {
    15: ["date", "time", "s-ip", "cs-method", "cs-uri-stem", "cs-uri-query",
         "s-port", "cs-username", "c-ip", "cs(User-Agent)", "cs(Referer)",
         "sc-status", "sc-substatus", "sc-win32-status", "time-taken"],
    14: ["date", "time", "s-ip", "cs-method", "cs-uri-stem", "cs-uri-query",
         "s-port", "cs-username", "c-ip", "cs(User-Agent)",
         "sc-status", "sc-substatus", "sc-win32-status", "time-taken"],
    18: ["date", "time", "s-sitename", "s-computername", "s-ip", "cs-method",
         "cs-uri-stem", "cs-uri-query", "s-port", "cs-username", "c-ip",
         "cs(User-Agent)", "cs(Referer)", "cs-host", "sc-status",
         "sc-substatus", "sc-win32-status", "time-taken"],
}

_PLAIN_LINE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\s+\S")


class ParseError(Exception):
    pass


def canonical_field(name: str) -> str:
    key = name.strip().lstrip("\ufeff").lower()
    key = re.sub(r"[\s_]+", "-", key)
    return FIELD_MAP.get(key, re.sub(r"[^a-z0-9_()]+", "_", key).strip("_"))


def detect_format(path: str) -> str:
    """Inspect file contents and return 'w3c', 'csv', or 'plain'."""
    with open(path, "r", encoding="utf-8-sig", errors="replace") as handle:
        head = handle.read(SNIFF_BYTES)
    lines = [ln for ln in head.splitlines() if ln.strip()]
    if not lines:
        raise ParseError(f"{path}: file is empty")
    if any(ln.startswith(FIELDS_PREFIX) for ln in lines[:50]):
        return "w3c"
    sample = [ln for ln in lines[:50] if not ln.startswith("#")]
    if sample and all(_PLAIN_LINE_RE.match(ln) for ln in sample[:10]):
        return "plain"
    try:
        dialect = csv.Sniffer().sniff("\n".join(sample[:20]), delimiters=",;\t|")
        first = next(csv.reader(io.StringIO(sample[0]), dialect))
        if len(first) >= 3:
            return "csv"
    except (csv.Error, StopIteration):
        pass
    if sample and all(_PLAIN_LINE_RE.match(ln) for ln in sample[:3]):
        return "plain"
    raise ParseError(
        f"{path}: unrecognized format (not W3C, CSV, or IIS-like plain text)")


def _finalize(fields: Dict[str, str], raw: str, line_no: int) -> Dict[str, Any]:
    """Map raw field names to the canonical schema and derive helper fields."""
    row: Dict[str, Any] = {}
    for name, value in fields.items():
        key = canonical_field(name)
        value = value.strip()
        if value in ("", "-"):
            row[key] = None
        elif key in INT_FIELDS:
            try:
                row[key] = int(float(value))
            except ValueError:
                row[key] = None
        else:
            row[key] = value

    if not row.get("timestamp") and row.get("date") and row.get("time"):
        row["timestamp"] = f"{row['date']}T{row['time']}"
    ts = row.get("timestamp")
    if ts:
        row["timestamp"] = ts.replace(" ", "T")[:19]

    stem = row.get("uri_stem") or ""
    query = row.get("uri_query") or ""
    url = f"{stem}?{query}" if query else stem
    row["url"] = _url_decode(url)
    row["raw"] = raw
    row["line"] = line_no
    return row


def _url_decode(value: str, passes: int = 3) -> str:
    decoded = value
    for _ in range(passes):
        nxt = unquote_plus(decoded)
        if nxt == decoded:
            break
        decoded = nxt
    return decoded


def parse_w3c(path: str, follow: bool = False) -> Iterator[Dict[str, Any]]:
    active: Optional[List[str]] = None
    with open(path, "r", encoding="utf-8-sig", errors="replace") as handle:
        for line_no, line in _iter_lines(handle, follow):
            if line.startswith("#"):
                if line.startswith(FIELDS_PREFIX):
                    active = line[len(FIELDS_PREFIX):].split()
                continue
            if active is None:
                logger.warning("%s:%d: data before #Fields: header, skipped",
                               path, line_no)
                continue
            values = line.split(" ")
            if len(values) != len(active):
                logger.warning("%s:%d: expected %d fields, got %d; skipped",
                               path, line_no, len(active), len(values))
                continue
            yield _finalize(dict(zip(active, values)), line, line_no)


def parse_csv_log(path: str, follow: bool = False) -> Iterator[Dict[str, Any]]:
    with open(path, "r", encoding="utf-8-sig", errors="replace",
              newline="") as handle:
        head = handle.read(SNIFF_BYTES)
        handle.seek(0)
        try:
            dialect = csv.Sniffer().sniff(head, delimiters=",;\t|")
        except csv.Error:
            dialect = csv.excel
        reader = csv.reader(handle, dialect)
        header: Optional[List[str]] = None
        for values in reader:
            if not values or not any(v.strip() for v in values):
                continue
            if header is None:
                if values[0].lstrip().startswith("#"):
                    continue
                header = values
                continue
            if len(values) != len(header):
                logger.warning("%s:%d: expected %d columns, got %d; skipped",
                               path, reader.line_num, len(header), len(values))
                continue
            yield _finalize(dict(zip(header, values)),
                            dialect.delimiter.join(values), reader.line_num)


def parse_plain(path: str, follow: bool = False) -> Iterator[Dict[str, Any]]:
    """Header-less IIS-like lines: pick a known layout by token count."""
    with open(path, "r", encoding="utf-8-sig", errors="replace") as handle:
        for line_no, line in _iter_lines(handle, follow):
            if line.startswith("#"):
                continue
            if not _PLAIN_LINE_RE.match(line):
                continue
            values = line.split()
            layout = _PLAIN_LAYOUTS.get(len(values))
            if layout is None:
                layout = _guess_layout(values)
            if layout is None:
                logger.warning("%s:%d: cannot map %d tokens to IIS fields; "
                               "skipped", path, line_no, len(values))
                continue
            yield _finalize(dict(zip(layout, values)), line, line_no)


_VERB_RE = re.compile(r"^(?:GET|POST|HEAD|PUT|DELETE|OPTIONS|PATCH|TRACE|"
                      r"PROPFIND|CONNECT|RPC_IN_DATA|RPC_OUT_DATA)$")
_IP_RE = re.compile(r"^(?:\d{1,3}(?:\.\d{1,3}){3}|[0-9a-fA-F:]+:[0-9a-fA-F:%.]+)$")


def _guess_layout(values: List[str]) -> Optional[List[str]]:
    """Best-effort positional mapping for unknown token counts."""
    layout = [f"extra{i}" for i in range(len(values))]
    layout[0], layout[1] = "date", "time"
    method_idx = next((i for i, v in enumerate(values) if _VERB_RE.match(v)), None)
    if method_idx is None or method_idx + 2 >= len(values):
        return None
    layout[method_idx] = "cs-method"
    layout[method_idx + 1] = "cs-uri-stem"
    layout[method_idx + 2] = "cs-uri-query"
    if method_idx >= 3 and _IP_RE.match(values[2]):
        layout[2] = "s-ip"
    ips = [i for i, v in enumerate(values)
           if i > method_idx + 2 and _IP_RE.match(v)]
    if ips:
        layout[ips[0]] = "c-ip"
    statuses = [i for i, v in enumerate(values)
                if i > method_idx + 2 and re.match(r"^[1-5]\d\d$", v)]
    if statuses:
        layout[statuses[0]] = "sc-status"
    return layout


def parse(path: str, fmt: Optional[str] = None,
          follow: bool = False) -> Iterator[Dict[str, Any]]:
    """Auto-detect the format (unless given) and stream normalized records."""
    if not os.path.isfile(path):
        raise ParseError(f"Input file not found: {path}")
    fmt = fmt or detect_format(path)
    if fmt == "w3c":
        return parse_w3c(path, follow)
    if fmt == "csv":
        return parse_csv_log(path, follow)
    if fmt == "plain":
        return parse_plain(path, follow)
    raise ParseError(f"Unknown format: {fmt}")


def _iter_lines(handle, follow: bool):
    """Yield (line_no, stripped_line); in follow mode keep tailing the file."""
    line_no = 0
    while True:
        line = handle.readline()
        if line:
            line_no += 1
            line = line.rstrip("\r\n")
            if line.strip():
                yield line_no, line
            continue
        if not follow:
            return
        time_mod.sleep(0.5)


def parse_record_time(ts: Optional[str]) -> Optional[datetime]:
    if not ts:
        return None
    try:
        return datetime.strptime(ts[:19], "%Y-%m-%dT%H:%M:%S")
    except ValueError:
        return None
