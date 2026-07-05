"""Interactive prompt mode for W3CSaw.

Launched by running ``w3csaw`` with no arguments (in a terminal) or
``w3csaw interactive``. Shows the banner, then walks the analyst through a
scan with sensible defaults instead of requiring command-line flags.
"""

from __future__ import annotations

import argparse
import os
from typing import Optional

from rich.prompt import Confirm, IntPrompt, Prompt

from . import console as console_mod
from .utils import LEVELS, default_rules_dir, expand_inputs

# Assigned by cli.py to avoid a circular import at module load time.
run_scan = None  # type: ignore[assignment]

_FORMATS = ("jsonl", "csv", "md")


def _default_input() -> Optional[str]:
    sample = os.path.join("examples", "sample_iis.log")
    return sample if os.path.isfile(sample) else None


def _ask_input(console) -> str:
    """Prompt for an input path, re-asking until it resolves to real files."""
    default = _default_input()
    while True:
        path = Prompt.ask(
            "Path to IIS log file (.log or .csv), directory, or glob",
            default=default, console=console).strip()
        try:
            files = expand_inputs(path)
        except (FileNotFoundError, ValueError) as exc:
            console.print(f"  [!] {exc}", style="red")
            continue
        console.print(f"  [+] Found {len(files)} log file(s)", style="green")
        return path


def _resolve_rules(console) -> str:
    """Use the bundled rule pack automatically; only prompt if it's missing."""
    rules_path = default_rules_dir()
    if rules_path:
        try:
            count = len(expand_rules(rules_path))
        except Exception:  # pragma: no cover - display only
            count = 0
        console.print(f"  [+] Using bundled rule pack ({count} rule files)",
                      style="green")
        return rules_path
    while True:
        path = Prompt.ask("Path to detection rules", console=console).strip()
        if os.path.exists(path):
            return path
        console.print(f"  [!] Rules path not found: {path}", style="red")


def expand_rules(rules_path: str):
    import glob
    if os.path.isfile(rules_path):
        return [rules_path]
    files = []
    for pattern in ("**/*.yml", "**/*.yaml"):
        files.extend(glob.glob(os.path.join(rules_path, pattern), recursive=True))
    return files


def _build_scan_args(console) -> argparse.Namespace:
    input_path = _ask_input(console)
    rules_path = _resolve_rules(console)
    group_by = Prompt.ask("Group findings by",
                          choices=["category", "level", "rule", "src_ip", "host"],
                          default="category", console=console)
    min_level = Prompt.ask("Minimum severity to report",
                           choices=list(LEVELS), default="low", console=console)
    full = Confirm.ask("Show full (untruncated) field values?",
                       default=False, console=console)

    output = None
    fmt = "jsonl"
    if Confirm.ask("Also save machine output to a file?",
                   default=False, console=console):
        fmt = Prompt.ask("Output format", choices=list(_FORMATS),
                         default="jsonl", console=console)
        output = Prompt.ask("Output file path",
                            default=f"findings.{fmt if fmt != 'md' else 'md'}",
                            console=console).strip() or None

    return argparse.Namespace(
        input=input_path, rules=rules_path, output=output, format=fmt,
        include_raw=False, cli=True, full=full, group_by=group_by,
        max_table_width=None, no_color=False, no_banner=True, quiet=False,
        min_level=min_level, timezone="UTC", fail_open=True, summary=False)


def run_interactive() -> int:
    """Drive one or more scans interactively; returns the last exit code."""
    if run_scan is None:  # pragma: no cover - wired up by cli.py
        raise RuntimeError("interactive mode not initialized")

    reporter = console_mod.ConsoleReporter(no_color=False)
    reporter.banner()
    console = reporter.err
    console.print("Interactive mode — press Ctrl-C to quit.\n",
                  style="cyan")

    last_code = 0
    try:
        while True:
            args = _build_scan_args(console)
            console.print()
            last_code = run_scan(args)
            if not Confirm.ask("\nRun another scan?", default=False,
                               console=console):
                break
    except (KeyboardInterrupt, EOFError):
        console.print("\nGoodbye.", style="cyan")
    return last_code
