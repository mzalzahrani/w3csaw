"""Shared helpers: input expansion, URL decoding, severity levels, timestamps."""

from __future__ import annotations

import glob
import logging
import os
from datetime import datetime, timedelta, timezone
from typing import List, Optional
from urllib.parse import unquote_plus

logger = logging.getLogger("w3csaw")

LEVELS = ("low", "medium", "high", "critical")
LEVEL_ORDER = {name: idx for idx, name in enumerate(LEVELS)}

MAX_DECODE_PASSES = 3


def default_rules_dir() -> Optional[str]:
    """Locate the rule pack that ships with W3CSaw.

    Checks, in order: the package's sibling ``rules/`` (source/editable
    installs), a ``rules/`` bundled inside the package, and ``rules/`` in the
    current working directory. Returns the first that exists, else None.
    """
    here = os.path.dirname(os.path.abspath(__file__))
    candidates = [
        os.path.join(os.path.dirname(here), "rules"),
        os.path.join(here, "rules"),
        os.path.join(os.getcwd(), "rules"),
    ]
    for candidate in candidates:
        if os.path.isdir(candidate):
            return candidate
    return None


def level_at_least(level: str, minimum: str) -> bool:
    """Return True if `level` is at or above `minimum` severity."""
    return LEVEL_ORDER.get(level, 0) >= LEVEL_ORDER.get(minimum, 0)


def expand_inputs(input_spec: str) -> List[str]:
    """Expand a file path, directory, or glob into a sorted list of log files.

    Directories are searched recursively for *.log and *.csv files.
    """
    if os.path.isfile(input_spec):
        return [input_spec]
    if os.path.isdir(input_spec):
        matches = []
        for pattern in ("*.log", "*.csv"):
            matches.extend(glob.glob(os.path.join(input_spec, "**", pattern),
                                     recursive=True))
        return sorted(os.path.normpath(p) for p in matches)
    matches = glob.glob(input_spec, recursive=True)
    files = sorted(os.path.normpath(p) for p in matches if os.path.isfile(p))
    if not files:
        raise FileNotFoundError(f"No log files found for input: {input_spec!r}")
    return files


def url_decode(value: Optional[str], max_passes: int = MAX_DECODE_PASSES) -> Optional[str]:
    """Repeatedly URL-decode a value (bounded) so doubly-encoded payloads surface.

    The original value is always preserved elsewhere; this is for detection only.
    """
    if value is None:
        return None
    decoded = value
    for _ in range(max_passes):
        try:
            next_pass = unquote_plus(decoded)
        except Exception:  # pragma: no cover - unquote is very permissive
            break
        if next_pass == decoded:
            break
        decoded = next_pass
    return decoded


def parse_timezone(spec: str) -> timezone:
    """Parse a timezone spec such as 'UTC', '+03:00', or '-0500' into a tzinfo."""
    spec = spec.strip()
    if spec.upper() in ("UTC", "Z", ""):
        return timezone.utc
    sign = 1
    body = spec
    if body[0] in "+-":
        sign = -1 if body[0] == "-" else 1
        body = body[1:]
    body = body.replace(":", "")
    if not body.isdigit() or len(body) not in (2, 4):
        raise ValueError(f"Invalid timezone offset: {spec!r} (use UTC or +HH:MM)")
    hours = int(body[:2])
    minutes = int(body[2:4]) if len(body) == 4 else 0
    if hours > 14 or minutes > 59:
        raise ValueError(f"Invalid timezone offset: {spec!r}")
    return timezone(sign * timedelta(hours=hours, minutes=minutes))


def build_timestamp(date_str: Optional[str], time_str: Optional[str],
                    tz: timezone = timezone.utc) -> Optional[str]:
    """Combine W3C date and time fields into an ISO 8601 UTC timestamp string.

    IIS W3C logs record timestamps in UTC by default; `tz` lets analysts
    reinterpret logs written in local server time.
    """
    dt = parse_datetime(date_str, time_str, tz)
    if dt is None:
        return None
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_datetime(date_str: Optional[str], time_str: Optional[str],
                   tz: timezone = timezone.utc) -> Optional[datetime]:
    """Parse W3C date/time fields into an aware UTC datetime, or None."""
    if not date_str or not time_str:
        return None
    try:
        dt = datetime.strptime(f"{date_str} {time_str}", "%Y-%m-%d %H:%M:%S")
    except ValueError:
        return None
    return dt.replace(tzinfo=tz).astimezone(timezone.utc)


def safe_int(value: Optional[str]) -> Optional[int]:
    """Convert a string to int, returning None for missing or non-numeric values."""
    if value is None or value == "-":
        return None
    try:
        return int(value)
    except (ValueError, TypeError):
        return None
