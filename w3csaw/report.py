"""Markdown DFIR report generation."""

from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
from typing import Any, Dict, List, Sequence, TextIO

from . import __tool_name__, __version__
from .engine import Finding
from .utils import LEVELS

NEXT_STEPS = """\
Correlate W3CSaw findings with host and network telemetry before drawing
conclusions -- IIS logs show HTTP activity, not code execution:

- **Security.evtx** -- logons around finding timestamps (4624/4625/4672).
- **System.evtx / Application.evtx** -- service installs, crashes, IIS worker events.
- **Microsoft-Windows-PowerShell/Operational.evtx** -- script block logging (4104).
- **Microsoft-Windows-Sysmon/Operational.evtx** -- process creation and network events.
- **w3wp.exe child processes** -- cmd.exe / powershell.exe spawned by the IIS
  worker process is a strong web shell indicator.
- **Web root file changes** -- new or modified .aspx/.ashx/.asmx files
  ($MFT, USN journal, file timestamps) near finding timestamps.
- **IIS configuration** -- new virtual directories, handlers, or modules.
- **EDR process trees and outbound connections** from the web server.
- **Persistence** -- new services, scheduled tasks, and local users created
  shortly after suspicious requests.
"""


def write_markdown_report(handle: TextIO, findings: Sequence[Finding],
                          stats: Dict[str, Any], max_detail_rows: int = 200) -> None:
    """Write the full analyst-facing Markdown report."""
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    handle.write(f"# {__tool_name__} Scan Report\n\n")
    handle.write(f"**Tool:** {__tool_name__} v{__version__}  \n")
    handle.write(f"**Input:** `{stats.get('input', '-')}`  \n")
    handle.write(f"**Rules:** `{stats.get('rules_path', '-')}` "
                 f"({stats.get('rules_loaded', 0)} loaded)  \n")
    handle.write(f"**Scan time:** {now}  \n")
    handle.write(f"**Files parsed:** {stats.get('files_parsed', 0)}  \n")
    handle.write(f"**Lines parsed:** {stats.get('lines_parsed', 0)}  \n")
    handle.write(f"**Total findings:** {len(findings)}\n\n")

    handle.write("## Findings by Severity\n\n")
    by_level = Counter(f.level for f in findings)
    handle.write("| Severity | Count |\n|---|---|\n")
    for level in reversed(LEVELS):
        handle.write(f"| {level} | {by_level.get(level, 0)} |\n")
    handle.write("\n")

    _top_section(handle, "Top Source IPs", "src_ip", findings)
    _top_section(handle, "Top Suspicious URI Paths", "uri_path", findings)
    _top_section(handle, "Top User Agents", "user_agent", findings)

    handle.write("## Rule Hit Summary\n\n")
    rule_hits = Counter((f.rule_id, f.rule_title, f.level) for f in findings)
    handle.write("| Rule ID | Title | Level | Hits |\n|---|---|---|---|\n")
    for (rule_id, title, level), count in rule_hits.most_common():
        handle.write(f"| `{rule_id}` | {_esc(title)} | {level} | {count} |\n")
    handle.write("\n")

    handle.write("## Detailed Findings\n\n")
    if len(findings) > max_detail_rows:
        handle.write(f"_Showing first {max_detail_rows} of {len(findings)} "
                     "findings; see JSONL/CSV output for the full set._\n\n")
    handle.write("| Timestamp | Level | Rule | Source IP | Method | URI | "
                 "Query | Status | Source Line |\n"
                 "|---|---|---|---|---|---|---|---|---|\n")
    for finding in findings[:max_detail_rows]:
        handle.write(
            f"| {finding.timestamp or '-'} "
            f"| {finding.level} "
            f"| `{finding.rule_id}` "
            f"| {finding.src_ip or '-'} "
            f"| {finding.method or '-'} "
            f"| {_esc(finding.uri_path or '-')} "
            f"| {_esc(_trunc(finding.uri_query or '-'))} "
            f"| {finding.status_code if finding.status_code is not None else '-'} "
            f"| {_esc(finding.log_file)}:{finding.line_number} |\n"
        )
    handle.write("\n")

    handle.write("## Analyst Notes\n\n")
    handle.write("_Add triage notes, verdicts, and scoping decisions here._\n\n")

    handle.write("## Recommended Next Hunting Steps\n\n")
    handle.write(NEXT_STEPS)


def _top_section(handle: TextIO, title: str, attr: str,
                 findings: Sequence[Finding], limit: int = 10) -> None:
    handle.write(f"## {title}\n\n")
    counts = Counter(getattr(f, attr) for f in findings
                     if getattr(f, attr) is not None)
    handle.write("| Value | Findings |\n|---|---|\n")
    for value, count in counts.most_common(limit):
        handle.write(f"| {_esc(_trunc(str(value)))} | {count} |\n")
    handle.write("\n")


def _esc(text: str) -> str:
    """Escape characters that would break Markdown tables."""
    return text.replace("|", "\\|").replace("\n", " ")


def _trunc(text: str, limit: int = 120) -> str:
    return text if len(text) <= limit else text[: limit - 3] + "..."
