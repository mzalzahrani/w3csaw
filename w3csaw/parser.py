"""Streaming parser for IIS W3C extended log format files.

Reads files line by line, tracking the active `#Fields:` layout so that
field order can change mid-file and across files.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Callable, Dict, Iterable, Iterator, List, Optional

logger = logging.getLogger("w3csaw")

FIELDS_PREFIX = "#Fields:"


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
    """Stream RawRecords from one W3C log file.

    With fail_open=True (the default), malformed lines are logged and
    skipped; otherwise a ParseError is raised. ``on_skip`` is invoked once
    for each line skipped in fail-open mode, letting callers count them.
    """
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
