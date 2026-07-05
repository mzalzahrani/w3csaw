"""Streaming parser for IIS W3C extended log format files.

Reads files line by line, tracking the active `#Fields:` layout so that
field order can change mid-file and across files. Files with a ``.csv``
extension are parsed as comma-separated exports instead: the first row must
be a header naming the columns (W3C names such as ``cs-uri-stem`` or common
variants such as ``cs_uri_stem`` / ``User-Agent``).
"""

from __future__ import annotations

import csv
import logging
from dataclasses import dataclass, field
from typing import Callable, Dict, Iterable, Iterator, List, Optional

logger = logging.getLogger("w3csaw")

FIELDS_PREFIX = "#Fields:"

# Lowercased, hyphen-normalized CSV header -> canonical W3C field name.
# Anything not listed passes through unchanged (the normalizer keeps unknown
# fields under their raw name, so already-normalized columns still work).
_CSV_HEADER_ALIASES: Dict[str, str] = {
    "date": "date",
    "time": "time",
    "s-sitename": "s-sitename",
    "s-computername": "s-computername",
    "s-ip": "s-ip",
    "s-port": "s-port",
    "cs-method": "cs-method",
    "method": "cs-method",
    "cs-uri-stem": "cs-uri-stem",
    "cs-uri-query": "cs-uri-query",
    "c-ip": "c-ip",
    "client-ip": "c-ip",
    "clientip": "c-ip",
    "cs-username": "cs-username",
    "cs(user-agent)": "cs(User-Agent)",
    "cs-user-agent": "cs(User-Agent)",
    "user-agent": "cs(User-Agent)",
    "useragent": "cs(User-Agent)",
    "cs(referer)": "cs(Referer)",
    "cs-referer": "cs(Referer)",
    "referer": "cs(Referer)",
    "referrer": "cs(Referer)",
    "sc-status": "sc-status",
    "sc-substatus": "sc-substatus",
    "sc-win32-status": "sc-win32-status",
    "sc-bytes": "sc-bytes",
    "cs-bytes": "cs-bytes",
    "time-taken": "time-taken",
    "cs-host": "cs-host",
    "cs-version": "cs-version",
}


def _canonical_csv_field(name: str) -> str:
    """Map a CSV header cell to its canonical W3C field name if known."""
    stripped = name.strip().lstrip("\ufeff")
    key = stripped.lower().replace("_", "-").replace(" ", "-")
    return _CSV_HEADER_ALIASES.get(key, stripped)


class ParseError(Exception):
    """Raised for unrecoverable parse problems when fail-open is disabled."""


@dataclass
class RawRecord:
    """A single data row split according to the active #Fields: layout."""

    fields: Dict[str, str] = field(default_factory=dict)
    raw_line: str = ""
    log_file: str = ""
    line_number: int = 0


def parse_file(path: str, fail_open: bool = True, encoding: str = "utf-8",
               on_skip: Optional[Callable[[], None]] = None) -> Iterator[RawRecord]:
    """Stream RawRecords from one log file (W3C, or CSV by extension).

    With fail_open=True (the default), malformed lines are logged and
    skipped; otherwise a ParseError is raised. ``on_skip`` is invoked once
    for each line skipped in fail-open mode, letting callers count them.
    """
    if path.lower().endswith(".csv"):
        yield from parse_csv_file(path, fail_open=fail_open,
                                  encoding=encoding, on_skip=on_skip)
        return
    active_fields: Optional[List[str]] = None
    with open(path, "r", encoding=encoding, errors="replace") as handle:
        for line_number, line in enumerate(handle, start=1):
            line = line.rstrip("\r\n")
            if not line.strip():
                continue
            if line.startswith("#"):
                if line.startswith(FIELDS_PREFIX):
                    active_fields = line[len(FIELDS_PREFIX):].split()
                    if not active_fields:
                        _fail(f"{path}:{line_number}: empty #Fields: header",
                              fail_open, on_skip)
                        active_fields = None
                continue
            if active_fields is None:
                _fail(f"{path}:{line_number}: data before any #Fields: header; "
                      "skipping remainder of file", fail_open, on_skip)
                return
            values = line.split(" ")
            if len(values) != len(active_fields):
                _fail(f"{path}:{line_number}: expected {len(active_fields)} "
                      f"fields, got {len(values)}; line skipped", fail_open, on_skip)
                continue
            yield RawRecord(
                fields=dict(zip(active_fields, values)),
                raw_line=line,
                log_file=path,
                line_number=line_number,
            )


def parse_csv_file(path: str, fail_open: bool = True, encoding: str = "utf-8-sig",
                   on_skip: Optional[Callable[[], None]] = None) -> Iterator[RawRecord]:
    """Stream RawRecords from a CSV export of IIS logs.

    The first non-comment row is the header; column names are canonicalized
    to W3C field names where recognized. Empty cells become ``-`` so the
    normalizer treats them as missing, matching W3C behavior.
    """
    if encoding == "utf-8":
        encoding = "utf-8-sig"
    header: Optional[List[str]] = None
    with open(path, "r", encoding=encoding, errors="replace", newline="") as handle:
        reader = csv.reader(handle)
        for values in reader:
            line_number = reader.line_num
            if not values or not any(cell.strip() for cell in values):
                continue
            if header is None:
                if values[0].lstrip().startswith("#"):
                    continue
                header = [_canonical_csv_field(cell) for cell in values]
                if len(set(header)) != len(header):
                    _fail(f"{path}:{line_number}: duplicate column names in "
                          "CSV header", fail_open, on_skip)
                continue
            if len(values) != len(header):
                _fail(f"{path}:{line_number}: expected {len(header)} columns, "
                      f"got {len(values)}; line skipped", fail_open, on_skip)
                continue
            yield RawRecord(
                fields={name: (cell if cell.strip() else "-")
                        for name, cell in zip(header, values)},
                raw_line=",".join(values),
                log_file=path,
                line_number=line_number,
            )
    if header is None:
        _fail(f"{path}: no CSV header row found", fail_open, on_skip)


def parse_files(paths: Iterable[str], fail_open: bool = True,
                on_skip: Optional[Callable[[], None]] = None) -> Iterator[RawRecord]:
    """Stream RawRecords from multiple files in order."""
    for path in paths:
        try:
            yield from parse_file(path, fail_open=fail_open, on_skip=on_skip)
        except OSError as exc:
            _fail(f"Cannot read {path}: {exc}", fail_open, on_skip)


def _fail(message: str, fail_open: bool,
          on_skip: Optional[Callable[[], None]] = None) -> None:
    if fail_open:
        logger.warning(message)
        if on_skip is not None:
            on_skip()
    else:
        raise ParseError(message)
