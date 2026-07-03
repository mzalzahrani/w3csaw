"""Terminal presentation for W3CSaw (the ``--cli`` output mode).

All human-facing rendering lives here so cli.py stays focused on
orchestration. Rendering never mutates findings and keeps only the (small)
findings list in memory; raw log records are still streamed by the caller.
"""

from __future__ import annotations

import os
import sys
from contextlib import contextmanager
from typing import Any, Callable, Dict, Iterable, Iterator, List, Optional, Sequence

from rich.box import ROUNDED, SIMPLE_HEAVY
from rich.console import Console
from rich.panel import Panel
from rich.progress import (BarColumn, MofNCompleteColumn, Progress, SpinnerColumn,
                           TextColumn, TimeElapsedColumn)
from rich.table import Table
from rich.text import Text

from . import __tool_name__, __version__
from .engine import Finding

# Severity ordering used everywhere findings are sorted or grouped.
SEVERITY_ORDER = ("critical", "high", "medium", "low", "informational")
_SEVERITY_RANK = {name: idx for idx, name in enumerate(SEVERITY_ORDER)}

SEVERITY_STYLE = {
    "critical": "bold red",
    "high": "red",
    "medium": "yellow",
    "low": "blue",
    "informational": "dim white",
}

# Directory-name -> display category for rules on disk.
CATEGORY_LABELS = {
    "webshell": "Webshell",
    "rce": "RCE",
    "traversal": "Traversal",
    "scanning": "Scanning",
    "auth": "Auth",
    "upload": "Upload",
    "aggregation": "Aggregation",
}
# Preferred display order for category groups.
CATEGORY_ORDER = ["Webshell", "RCE", "Traversal", "Scanning", "Auth",
                  "Upload", "Aggregation", "Other"]

# Fields truncated by default to keep tables readable.
_LONG_FIELDS = {"uri_path", "uri_query", "user_agent"}
_DEFAULT_TRUNCATE = 40
# Cap rows rendered per group; huge tables are slow, memory-heavy, and
# unreadable. The full set is always available via the machine output.
_DEFAULT_MAX_ROWS = 100

BANNER = r"""
██╗    ██╗██████╗  ██████╗███████╗ █████╗ ██╗    ██╗
██║    ██║╚════██╗██╔════╝██╔════╝██╔══██╗██║    ██║
██║ █╗ ██║ █████╔╝██║     ███████╗███████║██║ █╗ ██║
██║███╗██║ ╚═══██╗██║     ╚════██║██╔══██║██║███╗██║
╚███╔███╔╝██████╔╝╚██████╗███████║██║  ██║╚███╔███╔╝
 ╚══╝╚══╝ ╚═════╝  ╚═════╝╚══════╝╚═╝  ╚═╝ ╚══╝╚══╝"""


_PIPED_WIDTH = 160


def create_console(no_color: bool, stderr: bool = False) -> Console:
    """Build a Console. Color is auto-disabled when output is not a TTY.

    We never force terminal mode, so piped/redirected output is always plain
    text; ``no_color`` additionally strips styling on a real terminal. On a
    real terminal rich uses the actual width; when redirected we widen to a
    comfortable fixed width so tables stay readable in files and pagers.
    """
    stream = sys.stderr if stderr else sys.stdout
    if getattr(stream, "isatty", lambda: False)():
        width = None  # real terminal: use its actual width
    else:
        try:
            width = int(os.environ.get("COLUMNS", _PIPED_WIDTH))
        except ValueError:
            width = _PIPED_WIDTH
    return Console(stderr=stderr, no_color=no_color, width=width,
                   highlight=False, emoji=False, soft_wrap=False)


def severity_style(level: str, no_color: bool = False) -> str:
    """Return the rich style string for a severity level."""
    if no_color:
        return ""
    return SEVERITY_STYLE.get(level, "white")


def severity_rank(level: str) -> int:
    return _SEVERITY_RANK.get(level, len(SEVERITY_ORDER))


def highest_severity(findings: Sequence[Finding]) -> Optional[str]:
    if not findings:
        return None
    return min((f.level for f in findings), key=severity_rank)


def category_from_source(source_path: str) -> str:
    """Derive a display category from a rule's on-disk folder."""
    parent = os.path.basename(os.path.dirname(source_path)).lower()
    return CATEGORY_LABELS.get(parent, "Other")


def build_category_map(rules: Iterable[Any]) -> Dict[str, str]:
    """Map rule_id -> display category using each rule's source folder."""
    return {rule.id: category_from_source(rule.source_path) for rule in rules}


def truncate_value(value: Any, width: int, full: bool) -> str:
    """Render a cell value, truncating long strings unless ``full`` is set."""
    if value is None or value == "":
        return "-"
    text = str(value)
    if full or width <= 0 or len(text) <= width:
        return text
    return text[: max(1, width - 1)] + "…"


def is_aggregation_finding(finding: Finding) -> bool:
    return "event_count" in finding.matched_fields


def aggregation_count(finding: Finding) -> Optional[Any]:
    if "event_count" in finding.matched_fields:
        return finding.matched_values[finding.matched_fields.index("event_count")]
    return None


class ConsoleReporter:
    """Renders scan progress and results to the terminal for ``--cli`` mode."""

    def __init__(self, *, no_color: bool = False, quiet: bool = False,
                 no_banner: bool = False, full: bool = False,
                 group_by: str = "category", max_table_width: Optional[int] = None,
                 category_map: Optional[Dict[str, str]] = None,
                 box_style: str = "rounded",
                 max_rows: int = _DEFAULT_MAX_ROWS) -> None:
        self.no_color = no_color
        self.quiet = quiet
        self.no_banner = no_banner
        self.full = full
        self.group_by = group_by
        self.truncate_width = max_table_width or _DEFAULT_TRUNCATE
        self.max_rows = max_rows
        self.category_map = category_map or {}
        self.box = ROUNDED if box_style == "rounded" else SIMPLE_HEAVY
        # Findings/summary go to stdout (the analyst's product); banner,
        # status and progress are decoration on stderr, so redirecting
        # stdout captures the results without the animation.
        self.out = create_console(no_color)
        self.err = create_console(no_color, stderr=True)
        self._truncated = False

    # -- decoration (stderr) ------------------------------------------------

    def banner(self) -> None:
        if self.quiet or self.no_banner:
            return
        style = "" if self.no_color else "bold cyan"
        self.err.print(Text(BANNER, style=style))
        self.err.print(
            f"{__tool_name__} — Chainsaw-style DFIR hunting for IIS W3C logs",
            style="" if self.no_color else "cyan")
        self.err.print("By TruePositive / Mohammed Alzahrani (@mzalzahrani)",
                       style="" if self.no_color else "dim")
        self.err.print()

    def status(self, message: str) -> None:
        if self.quiet:
            return
        marker = Text("[+] ", style="" if self.no_color else "green")
        self.err.print(marker + Text(message))

    def scan_start(self, input_path: str, rules_path: str) -> None:
        self.status(f"Loading detection rules from: {rules_path}")

    @contextmanager
    def progress(self, total: Optional[int]) -> Iterator[Callable[[int], None]]:
        """Context manager yielding an ``advance(n)`` callable for the bar.

        Silently no-ops in quiet mode. Transient so it clears when done and
        leaves nothing behind on non-interactive terminals.
        """
        if self.quiet:
            yield lambda n=1: None
            return
        columns = [
            TextColumn("[+]", style="" if self.no_color else "green"),
            TextColumn("Hunting"),
            BarColumn(bar_width=None),
            MofNCompleteColumn(),
            TimeElapsedColumn(),
        ] if total else [
            SpinnerColumn(),
            TextColumn("[+] Hunting"),
            TextColumn("{task.completed} records"),
            TimeElapsedColumn(),
        ]
        with Progress(*columns, console=self.err, transient=True) as progress:
            task = progress.add_task("hunting", total=total)

            def advance(n: int = 1) -> None:
                progress.advance(task, n)

            yield advance
            if total:
                progress.update(task, completed=total)

    # -- results (stdout) ---------------------------------------------------

    def summary(self, findings: Sequence[Finding], stats: Dict[str, Any]) -> None:
        if self.quiet:
            return
        top = highest_severity(findings)
        top_text = Text(top or "none",
                        style=severity_style(top, self.no_color) if top else "")
        rows = [
            ("Input", str(stats.get("input", "-"))),
            ("Rules", f"{stats.get('rules_path', '-')} "
                      f"({stats.get('rules_loaded', 0)} loaded)"),
            ("Files parsed", str(stats.get("files_parsed", 0))),
            ("Lines parsed", str(stats.get("lines_parsed", 0))),
            ("Findings", str(len(findings))),
        ]
        if stats.get("skipped"):
            rows.append(("Malformed lines skipped", str(stats["skipped"])))
        if stats.get("output"):
            rows.append(("Output file", str(stats["output"])))
        if stats.get("runtime") is not None:
            rows.append(("Runtime", f"{stats['runtime']:.2f}s"))

        grid = Table.grid(padding=(0, 2))
        grid.add_column(justify="right", style="" if self.no_color else "bold")
        grid.add_column()
        for label, value in rows:
            grid.add_row(label, value)
        grid.add_row("Highest severity", top_text)

        title = f"{__tool_name__} v{__version__} scan summary"
        self.out.print(Panel(grid, title=title, box=self.box,
                             border_style="" if self.no_color else "cyan",
                             expand=False))

    def results(self, findings: Sequence[Finding]) -> None:
        """Render findings grouped and tabulated, or an all-clear message."""
        if not findings:
            self.status("Findings: 0")
            self.out.print(
                "No suspicious IIS activity matched the loaded rules.",
                style="" if self.no_color else "green")
            return

        rule_count = len({f.rule_id for f in findings})
        self.status(f"Findings: {len(findings)} matches across {rule_count} rules")

        groups = self._group(findings)
        for group_name, group_findings in groups:
            self._render_group(group_name, group_findings)

        if self._truncated and not self.full:
            self.out.print(
                "Some values were truncated (use --full to show all content).",
                style="" if self.no_color else "dim")

    # -- grouping / tables --------------------------------------------------

    def _category_of(self, finding: Finding) -> str:
        return self.category_map.get(finding.rule_id, "Other")

    def _group_key(self, finding: Finding) -> str:
        if self.group_by == "category":
            return self._category_of(finding)
        if self.group_by == "level":
            return finding.level
        if self.group_by == "rule":
            return finding.rule_id
        if self.group_by == "src_ip":
            return finding.src_ip or "(none)"
        if self.group_by == "host":
            return finding.host or "(none)"
        return self._category_of(finding)

    def _group(self, findings: Sequence[Finding]):
        buckets: Dict[str, List[Finding]] = {}
        for finding in findings:
            buckets.setdefault(self._group_key(finding), []).append(finding)

        if self.group_by == "category":
            order = {name: i for i, name in enumerate(CATEGORY_ORDER)}
            keys = sorted(buckets, key=lambda k: (order.get(k, len(order)), k))
        elif self.group_by == "level":
            keys = sorted(buckets, key=severity_rank)
        else:
            # Most findings first, then alphabetically for stable output.
            keys = sorted(buckets, key=lambda k: (-len(buckets[k]), k))
        return [(k, buckets[k]) for k in keys]

    def _columns_for(self, findings: Sequence[Finding]) -> List[str]:
        cols = ["timestamp", "level", "rule", "src_ip", "method", "uri_path"]
        if any(self._category_of(f) == "RCE" for f in findings):
            cols.append("uri_query")
        cols += ["status", "user_agent"]
        if any(is_aggregation_finding(f) for f in findings):
            cols.append("count")
        return cols

    def _cell(self, finding: Finding, column: str) -> Text:
        style = "" if self.no_color else None
        if column == "level":
            return Text(finding.level,
                        style=severity_style(finding.level, self.no_color))
        if column == "count":
            value = aggregation_count(finding)
            return Text("-" if value is None else str(value))
        raw = {
            "timestamp": finding.timestamp,
            "rule": finding.rule_id,
            "src_ip": finding.src_ip,
            "method": finding.method,
            "uri_path": finding.uri_path,
            "uri_query": finding.uri_query,
            "status": finding.status_code,
            "user_agent": finding.user_agent,
        }.get(column)
        width = self.truncate_width if column in _LONG_FIELDS else 0
        text = truncate_value(raw, width, self.full)
        if width and not self.full and text.endswith("…"):
            self._truncated = True
        return Text(text, style=style or "")

    def _render_group(self, group_name: str, findings: Sequence[Finding]) -> None:
        self.status(f"Group: {group_name}  ({len(findings)})")
        columns = self._columns_for(findings)
        table = Table(box=self.box, expand=False, show_lines=False,
                      border_style="" if self.no_color else "dim",
                      header_style="" if self.no_color else "bold")
        for column in columns:
            justify = "right" if column in ("status", "count") else "left"
            no_wrap = not self.full and column in _LONG_FIELDS
            table.add_column(column, justify=justify, no_wrap=no_wrap,
                             overflow="fold" if self.full else "ellipsis")

        ordered = sorted(
            findings,
            key=lambda f: (severity_rank(f.level), f.timestamp or ""))
        shown = ordered[: self.max_rows] if self.max_rows else ordered
        for finding in shown:
            table.add_row(*(self._cell(finding, column) for column in columns))
        self.out.print(table)
        hidden = len(ordered) - len(shown)
        if hidden > 0:
            self.out.print(
                f"… and {hidden} more finding(s) in this group "
                "(export with -o for the full set).",
                style="" if self.no_color else "dim")
        self.out.print()


def count_lines(files: Sequence[str]) -> int:
    """Fast, constant-memory count of newlines across files for the progress bar.

    Reads bytes in chunks (no decode/parse), so it is far cheaper than the
    hunt itself and does not load logs into memory.
    """
    total = 0
    for path in files:
        try:
            with open(path, "rb") as handle:
                for chunk in iter(lambda: handle.read(1 << 20), b""):
                    total += chunk.count(b"\n")
        except OSError:
            continue
    return total
