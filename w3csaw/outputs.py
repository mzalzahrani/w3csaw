"""Finding and record writers: JSONL, CSV, and console tables."""

from __future__ import annotations

import csv
import json
from typing import Any, Dict, Iterable, List, Sequence, TextIO, Tuple

from .engine import Finding

FINDING_COLUMNS = (
    "rule_id", "rule_title", "level", "status", "description", "timestamp",
    "src_ip", "method", "uri_path", "uri_query", "status_code", "user_agent",
    "referer", "host", "matched_fields", "matched_values", "tags",
    "falsepositives", "references", "log_file", "line_number", "raw_line",
)

TIMELINE_COLUMNS = (
    "timestamp", "date", "time", "site_name", "server_ip", "method",
    "uri_path", "uri_query", "src_ip", "username", "user_agent", "referer",
    "status", "substatus", "win32_status", "bytes_sent", "bytes_received",
    "time_taken", "host", "extension", "log_file", "line_number",
)


def write_findings_jsonl(findings: Iterable[Finding], handle: TextIO,
                         include_raw: bool = False) -> int:
    """Write findings as one JSON object per line; returns count written."""
    count = 0
    for finding in findings:
        json.dump(finding.to_dict(include_raw=include_raw), handle,
                  ensure_ascii=False, default=str)
        handle.write("\n")
        count += 1
    return count


def write_findings_csv(findings: Iterable[Finding], handle: TextIO,
                       include_raw: bool = False) -> int:
    """Write findings as CSV; list values are joined with ';'."""
    columns = list(FINDING_COLUMNS)
    if not include_raw:
        columns.remove("raw_line")
    writer = csv.DictWriter(handle, fieldnames=columns, extrasaction="ignore")
    writer.writeheader()
    count = 0
    for finding in findings:
        row = finding.to_dict(include_raw=include_raw)
        for key, value in row.items():
            if isinstance(value, list):
                row[key] = ";".join(str(item) for item in value)
        writer.writerow(row)
        count += 1
    return count


def write_timeline_csv(records: Iterable[Dict[str, Any]], handle: TextIO) -> int:
    """Write normalized records chronologically as a CSV timeline."""
    writer = csv.DictWriter(handle, fieldnames=list(TIMELINE_COLUMNS),
                            extrasaction="ignore")
    writer.writeheader()
    count = 0
    for record in records:
        writer.writerow({key: record.get(key) for key in TIMELINE_COLUMNS})
        count += 1
    return count


def top_counts(records: Iterable[Dict[str, Any]], field_name: str,
               limit: int = 20) -> List[Tuple[Any, int]]:
    """Return the most common values of a field across records."""
    counts: Dict[Any, int] = {}
    for record in records:
        value = record.get(field_name)
        if value is None:
            continue
        counts[value] = counts.get(value, 0) + 1
    ranked = sorted(counts.items(), key=lambda kv: (-kv[1], str(kv[0])))
    return ranked[:limit]


def format_table(headers: Sequence[str], rows: Sequence[Sequence[Any]]) -> str:
    """Render a simple fixed-width console table."""
    str_rows = [[str(cell) for cell in row] for row in rows]
    widths = [len(h) for h in headers]
    for row in str_rows:
        for idx, cell in enumerate(row):
            widths[idx] = max(widths[idx], len(cell))
    lines = [
        "  ".join(h.ljust(widths[i]) for i, h in enumerate(headers)),
        "  ".join("-" * widths[i] for i in range(len(headers))),
    ]
    for row in str_rows:
        lines.append("  ".join(cell.ljust(widths[i]) for i, cell in enumerate(row)))
    return "\n".join(lines)
