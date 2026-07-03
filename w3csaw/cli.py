"""W3CSaw command-line interface."""

from __future__ import annotations

import argparse
import heapq
import logging
import sys
import time
from collections import Counter
from typing import Any, Dict, Iterator, List, Optional

from . import __tool_name__, __version__
from . import console as console_mod
from . import interactive as interactive_mod
from .aggregations import AggregationEngine
from .engine import Finding, scan_record
from .normalizer import normalize
from .outputs import (format_table, top_counts, write_findings_csv,
                      write_findings_jsonl, write_timeline_csv)
from .parser import ParseError, parse_file
from .report import write_markdown_report
from .rules import load_rules
from .utils import (LEVELS, default_rules_dir, expand_inputs, level_at_least,
                    parse_timezone)

logger = logging.getLogger("w3csaw")

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_FINDINGS = 2

TOP_FIELDS = ("src_ip", "uri_path", "user_agent", "status", "method",
              "extension", "host")
GROUP_BY_FIELDS = ("category", "level", "rule", "src_ip", "host")

EXIT_CODE_HELP = """\
exit codes:
  0  completed successfully, no findings
  1  runtime or validation error
  2  completed successfully AND findings were detected

Exit code 2 is not a failure. It means the scan finished cleanly and matched
one or more detections -- useful for CI, SOAR, and shell automation.
"""

_MAIN_EPILOG = """\
examples:
  w3csaw scan -i examples/sample_iis.log -r rules/ --cli
  w3csaw scan -i logs/ -r rules/ --format jsonl -o findings.jsonl
  w3csaw timeline -i logs/ -o timeline.csv
  w3csaw top -i logs/ --by src_ip --limit 20
  w3csaw validate-rules -r rules/

""" + EXIT_CODE_HELP

_SCAN_EPILOG = """\
examples:
  # Analyst-friendly terminal review
  w3csaw scan -i examples/sample_iis.log -r rules/ --cli

  # Terminal review with full, untruncated field values
  w3csaw scan -i examples/sample_iis.log -r rules/ --cli --full

  # Group the terminal findings by severity instead of category
  w3csaw scan -i examples/sample_iis.log -r rules/ --cli --group-by level

  # Machine output to a file AND a terminal review at the same time
  w3csaw scan -i logs/ -r rules/ --format jsonl -o findings.jsonl --cli

  # Pure machine output for automation (unchanged default behavior)
  w3csaw scan -i logs/ -r rules/ --format jsonl -o findings.jsonl

""" + EXIT_CODE_HELP


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="w3csaw",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=(
            f"{__tool_name__} - Chainsaw-style DFIR hunting for IIS W3C logs.\n\n"
            "Parse IIS W3C access logs, apply Sigma-inspired YAML detection\n"
            "rules, and produce analyst-friendly findings, timelines, and reports."
        ),
        epilog=_MAIN_EPILOG,
    )
    parser.add_argument("--version", action="version",
                        version=f"{__tool_name__} {__version__}")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="enable debug logging")
    sub = parser.add_subparsers(dest="command", required=True, metavar="<command>")

    scan = sub.add_parser(
        "scan", help="hunt IIS logs with detection rules",
        description="Hunt IIS W3C logs with detection rules and report findings.",
        epilog=_SCAN_EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    req = scan.add_argument_group("input and rules")
    req.add_argument("-i", "--input", required=True,
                     help="log file, directory (recursive *.log), or glob pattern")
    req.add_argument("-r", "--rules", default=None,
                     help="rules directory or a single rule file "
                          "(default: the bundled W3CSaw rule pack)")

    out = scan.add_argument_group("machine output (unchanged formats)")
    out.add_argument("-o", "--output",
                     help="write machine output to this file (default: stdout)")
    out.add_argument("--format", choices=("jsonl", "csv", "md"), default="jsonl",
                     help="machine output format: jsonl, csv, or md (default: jsonl)")
    out.add_argument("--include-raw", action="store_true",
                     help="include the raw log line in JSONL/CSV output")

    term = scan.add_argument_group("terminal output mode")
    term.add_argument("--cli", action="store_true",
                      help="show human-friendly grouped findings in the terminal")
    term.add_argument("--full", action="store_true",
                      help="show full field values instead of truncating long ones")
    term.add_argument("--group-by", choices=GROUP_BY_FIELDS, default="category",
                      help="group terminal findings by this field (default: category)")
    term.add_argument("--max-table-width", type=int, default=None, metavar="N",
                      help="truncate long field values to N characters (default: 40)")
    term.add_argument("--no-color", action="store_true",
                      help="disable ANSI colors in terminal output")
    term.add_argument("--no-banner", action="store_true",
                      help="suppress the ASCII banner only")
    term.add_argument("--quiet", action="store_true",
                      help="suppress banner, progress, and status lines")

    tune = scan.add_argument_group("hunting options")
    tune.add_argument("--min-level", choices=LEVELS, default="low",
                      help="minimum severity to report (default: low)")
    tune.add_argument("--timezone", default="UTC",
                      help="timezone of log timestamps, e.g. UTC or +03:00 (default: UTC)")
    tune.add_argument("--fail-open", action="store_true",
                      help="skip malformed lines instead of stopping the scan")
    tune.add_argument("--summary", action="store_true",
                      help="print a plain-text summary to stderr after the scan")
    scan.set_defaults(func=cmd_scan)

    timeline = sub.add_parser(
        "timeline", help="build a chronological CSV timeline of all requests",
        description="Merge all input logs into one chronological CSV timeline.",
        epilog="examples:\n  w3csaw timeline -i logs/ -o timeline.csv\n",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    timeline.add_argument("-i", "--input", required=True,
                          help="log file, directory, or glob pattern")
    timeline.add_argument("-o", "--output",
                          help="output CSV file (default: stdout)")
    timeline.add_argument("--timezone", default="UTC",
                          help="timezone of log timestamps (default: UTC)")
    timeline.add_argument("--fail-open", action="store_true",
                          help="skip malformed lines instead of stopping")
    timeline.set_defaults(func=cmd_timeline)

    top = sub.add_parser(
        "top", help="show most common values of a field",
        description="Rank the most frequent values of a normalized field.",
        epilog="examples:\n  w3csaw top -i logs/ --by src_ip --limit 20\n",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    top.add_argument("-i", "--input", required=True,
                     help="log file, directory, or glob pattern")
    top.add_argument("--by", required=True, choices=TOP_FIELDS,
                     help="field to count")
    top.add_argument("--limit", type=int, default=20,
                     help="number of values to show (default: 20)")
    top.add_argument("--fail-open", action="store_true",
                     help="skip malformed lines instead of stopping")
    top.set_defaults(func=cmd_top)

    validate = sub.add_parser(
        "validate-rules", help="validate YAML detection rules",
        description="Validate native W3CSaw YAML rules and report any errors.",
        epilog="examples:\n  w3csaw validate-rules\n  w3csaw validate-rules -r my-rules/\n",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    validate.add_argument("-r", "--rules", default=None,
                          help="rules directory or a single rule file "
                               "(default: the bundled W3CSaw rule pack)")
    validate.set_defaults(func=cmd_validate_rules)

    info = sub.add_parser(
        "rule-info", help="list loaded rules and their metadata",
        description="List rule ids, levels, types, tags, and titles.",
        epilog="examples:\n  w3csaw rule-info\n  w3csaw rule-info -r my-rules/\n",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    info.add_argument("-r", "--rules", default=None,
                      help="rules directory or a single rule file "
                           "(default: the bundled W3CSaw rule pack)")
    info.set_defaults(func=cmd_rule_info)

    interactive = sub.add_parser(
        "interactive", aliases=["shell"],
        help="launch a guided, prompt-driven scan session",
        description="Guided scan: show the banner, then prompt for inputs.",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    interactive.set_defaults(func=cmd_interactive)
    return parser


def cmd_interactive(args: argparse.Namespace) -> int:
    return interactive_mod.run_interactive()


def _iter_records(files: List[str], tz, fail_open: bool,
                  stats: Optional[Dict[str, Any]] = None,
                  on_skip=None) -> Iterator[Dict[str, Any]]:
    for path in files:
        for raw in parse_file(path, fail_open=fail_open, on_skip=on_skip):
            if stats is not None:
                stats["lines_parsed"] += 1
            yield normalize(raw, tz)


def cmd_scan(args: argparse.Namespace) -> int:
    started = time.perf_counter()
    tz = parse_timezone(args.timezone)
    files = expand_inputs(args.input)

    if not args.rules:
        args.rules = default_rules_dir()
        if not args.rules:
            logger.error("no rules found; specify one with -r/--rules")
            return EXIT_ERROR

    reporter = None
    if args.cli:
        reporter = console_mod.ConsoleReporter(
            no_color=args.no_color, quiet=args.quiet, no_banner=args.no_banner,
            full=args.full, group_by=args.group_by,
            max_table_width=args.max_table_width)
        reporter.banner()
        reporter.status(f"Loading detection rules from: {args.rules}")

    rules, rule_errors = load_rules(args.rules)
    for error in rule_errors:
        logger.warning("rule skipped: %s", error)
    if not rules:
        logger.error("no valid rules loaded from %s", args.rules)
        return EXIT_ERROR

    line_rules = [r for r in rules if not r.is_aggregation]
    agg_engine = AggregationEngine(rules)
    stats: Dict[str, Any] = {
        "input": args.input,
        "rules_path": args.rules,
        "rules_loaded": len(rules),
        "files_parsed": len(files),
        "lines_parsed": 0,
        "skipped": 0,
        "output": args.output,
    }

    def on_skip() -> None:
        stats["skipped"] += 1

    if reporter is not None:
        reporter.category_map = console_mod.build_category_map(rules)
        reporter.status(f"Loaded {len(rules)} detection rules")
        reporter.status(f"Loading IIS W3C logs from: {args.input}")

    total_lines = console_mod.count_lines(files) if reporter and not args.quiet else None

    findings: List[Finding] = []

    def hunt(advance) -> None:
        for record in _iter_records(files, tz, args.fail_open, stats, on_skip):
            advance(1)
            for finding in scan_record(line_rules, record):
                if level_at_least(finding.level, args.min_level):
                    findings.append(finding)
            for finding in agg_engine.process(record):
                if level_at_least(finding.level, args.min_level):
                    findings.append(finding)
        for finding in agg_engine.finalize():
            if level_at_least(finding.level, args.min_level):
                findings.append(finding)

    if reporter is not None:
        with reporter.progress(total_lines) as advance:
            hunt(advance)
    else:
        hunt(lambda n=1: None)

    stats["runtime"] = time.perf_counter() - started

    # Machine output is written unless the user asked only for a terminal
    # review (--cli with no -o); this keeps JSONL/CSV/MD behavior unchanged
    # for automation while avoiding mixing raw output with the pretty tables.
    if args.output is not None or not args.cli:
        _write_findings(args, findings, stats)

    if reporter is not None:
        reporter.status(
            f"Parsed {stats['lines_parsed']} log records from {len(files)} file(s)")
        reporter.summary(findings, stats)
        reporter.results(findings)

    if args.summary and not args.cli:
        _print_summary(findings, stats)
    return EXIT_FINDINGS if findings else EXIT_OK


def _write_findings(args: argparse.Namespace, findings: List[Finding],
                    stats: Dict[str, Any]) -> None:
    handle = open(args.output, "w", encoding="utf-8", newline="") \
        if args.output else sys.stdout
    try:
        if args.format == "jsonl":
            write_findings_jsonl(findings, handle, include_raw=args.include_raw)
        elif args.format == "csv":
            write_findings_csv(findings, handle, include_raw=args.include_raw)
        else:
            write_markdown_report(handle, findings, stats)
    finally:
        if args.output:
            handle.close()
    if args.output:
        logger.info("wrote %d findings to %s", len(findings), args.output)


def _print_summary(findings: List[Finding], stats: Dict[str, Any]) -> None:
    by_level = Counter(f.level for f in findings)
    by_rule = Counter((f.rule_id, f.level) for f in findings)
    print(f"\n{__tool_name__} v{__version__} scan summary", file=sys.stderr)
    print(f"  Files parsed:   {stats['files_parsed']}", file=sys.stderr)
    print(f"  Lines parsed:   {stats['lines_parsed']}", file=sys.stderr)
    print(f"  Total findings: {len(findings)}", file=sys.stderr)
    for level in reversed(LEVELS):
        if by_level.get(level):
            print(f"    {level:>8}: {by_level[level]}", file=sys.stderr)
    if by_rule:
        print("  Rule hits:", file=sys.stderr)
        for (rule_id, level), count in by_rule.most_common():
            print(f"    [{level:>8}] {rule_id}: {count}", file=sys.stderr)


def cmd_timeline(args: argparse.Namespace) -> int:
    tz = parse_timezone(args.timezone)
    files = expand_inputs(args.input)
    # Each IIS file is internally chronological, so a heap merge across
    # per-file streams yields a global timeline without loading everything.
    streams = [_iter_records([path], tz, args.fail_open) for path in files]
    merged = heapq.merge(*streams, key=lambda r: (r.get("timestamp") or "",
                                                  r.get("line_number") or 0))
    handle = open(args.output, "w", encoding="utf-8", newline="") \
        if args.output else sys.stdout
    try:
        count = write_timeline_csv(merged, handle)
    finally:
        if args.output:
            handle.close()
    logger.info("wrote %d timeline rows", count)
    return EXIT_OK


def cmd_top(args: argparse.Namespace) -> int:
    files = expand_inputs(args.input)
    records = _iter_records(files, parse_timezone("UTC"), args.fail_open)
    ranked = top_counts(records, args.by, args.limit)
    print(format_table((args.by, "count"), ranked))
    return EXIT_OK


def _resolve_rules_arg(args: argparse.Namespace) -> Optional[str]:
    if args.rules:
        return args.rules
    resolved = default_rules_dir()
    if not resolved:
        logger.error("no rules found; specify one with -r/--rules")
    return resolved


def cmd_validate_rules(args: argparse.Namespace) -> int:
    rules_path = _resolve_rules_arg(args)
    if not rules_path:
        return EXIT_ERROR
    rules, errors = load_rules(rules_path)
    for error in errors:
        print(f"[FAIL] {error}")
    print(f"\n{len(rules)} valid rule(s), {len(errors)} error(s)")
    return EXIT_ERROR if errors else EXIT_OK


def cmd_rule_info(args: argparse.Namespace) -> int:
    rules_path = _resolve_rules_arg(args)
    if not rules_path:
        return EXIT_ERROR
    rules, errors = load_rules(rules_path)
    for error in errors:
        logger.warning("rule skipped: %s", error)
    rows = [
        (rule.id, rule.level, rule.type, ",".join(rule.tags) or "-",
         rule.title)
        for rule in sorted(rules, key=lambda r: r.id)
    ]
    print(format_table(("id", "level", "type", "tags", "title"), rows))
    print(f"\n{len(rules)} rule(s) loaded")
    return EXIT_OK


# Let interactive mode drive a scan without importing cli.py (avoids a cycle).
interactive_mod.run_scan = lambda args: cmd_scan(args)


def main(argv: Optional[List[str]] = None) -> int:
    raw = sys.argv[1:] if argv is None else list(argv)
    # Bare `w3csaw` in a terminal launches the guided interactive session;
    # in a non-interactive context we fall back to help so nothing hangs.
    if not raw:
        if sys.stdin.isatty() and sys.stdout.isatty():
            return interactive_mod.run_interactive()
        build_parser().print_help()
        return EXIT_ERROR

    parser = build_parser()
    args = parser.parse_args(raw)
    if args.verbose:
        level = logging.DEBUG
    elif getattr(args, "quiet", False):
        level = logging.ERROR
    else:
        level = logging.INFO
    logging.basicConfig(
        level=level,
        format="%(levelname)s %(message)s",
        stream=sys.stderr,
    )
    try:
        return args.func(args)
    except (FileNotFoundError, ParseError, ValueError) as exc:
        logger.error("%s", exc)
        return EXIT_ERROR
    except KeyboardInterrupt:
        logger.error("interrupted")
        return EXIT_ERROR


if __name__ == "__main__":
    sys.exit(main())
