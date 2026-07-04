"""Command-line interface for IIS Hunter."""

from __future__ import annotations

import argparse
import csv
import json
import logging
import sys
from datetime import datetime
from typing import Any, Dict, List, Optional

from . import __version__
from .engine import Engine, Stats
from .parser import ParseError, detect_format, parse, parse_record_time
from .rules import active_rules

logger = logging.getLogger("iis_hunter")

SEVERITY_COLORS = {"critical": "\033[95m", "high": "\033[91m",
                   "medium": "\033[93m", "low": "\033[96m"}
RESET = "\033[0m"


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="iis-hunter",
        description="Real-time threat hunting and forensics for IIS logs.")
    ap.add_argument("--file", "-f", help="Input log file (.log/.txt/.csv; "
                    "format is auto-detected from content)")
    ap.add_argument("--json", action="store_true",
                    help="Emit detections as JSON lines")
    ap.add_argument("--csv-out", metavar="PATH",
                    help="Also write detections to a CSV file")
    ap.add_argument("--top", type=int, metavar="N",
                    help="Print top-N statistics after the scan")
    ap.add_argument("--threshold-404", type=int, default=50, metavar="N",
                    help="404s per IP per 5 min before alerting (default 50)")
    ap.add_argument("--threshold-500", type=int, default=25, metavar="N",
                    help="5xx per IP per 5 min before alerting (default 25)")
    ap.add_argument("--threshold-rate", type=int, default=300, metavar="N",
                    help="Requests per IP per minute before alerting "
                         "(default 300)")
    ap.add_argument("--follow", action="store_true",
                    help="Keep watching the file for appended lines (tail -f)")
    ap.add_argument("--since", metavar="ISO",
                    help="Only analyze records at/after this time "
                         "(e.g. 2026-07-01T00:00:00)")
    ap.add_argument("--until", metavar="ISO",
                    help="Only analyze records at/before this time")
    ap.add_argument("--output", "-o", metavar="PATH",
                    help="Write detection output to a file instead of stdout")
    ap.add_argument("--verbose", "-v", action="store_true",
                    help="Verbose logging (parse warnings, progress)")
    ap.add_argument("--web", action="store_true",
                    help="Launch the web interface instead of a CLI scan")
    ap.add_argument("--host", default="127.0.0.1",
                    help="Web interface bind address (default 127.0.0.1)")
    ap.add_argument("--port", type=int, default=8787,
                    help="Web interface port (default 8787)")
    ap.add_argument("--version", action="version",
                    version=f"iis-hunter {__version__}")
    return ap


def _parse_when(value: Optional[str], flag: str) -> Optional[datetime]:
    if not value:
        return None
    for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S", "%Y-%m-%d"):
        try:
            return datetime.strptime(value, fmt)
        except ValueError:
            continue
    raise SystemExit(f"error: invalid {flag} value {value!r} "
                     "(use YYYY-MM-DD or YYYY-MM-DDTHH:MM:SS)")


def _format_text(det: Dict[str, Any], color: bool) -> str:
    sev = det["severity"]
    tag = f"[{sev.upper():>8}]"
    if color:
        tag = f"{SEVERITY_COLORS.get(sev, '')}{tag}{RESET}"
    return (f"{tag} {det.get('timestamp') or '-':19} {det['detection']:28} "
            f"ip={det.get('c_ip') or '-'} {det.get('method') or '-'} "
            f"{(det.get('uri') or '-')[:120]} status={det.get('status') or '-'}"
            f" [{det.get('field')}={str(det.get('value'))[:80]}]")


def run_scan(args: argparse.Namespace) -> int:
    since = _parse_when(args.since, "--since")
    until = _parse_when(args.until, "--until")

    try:
        fmt = detect_format(args.file)
    except (ParseError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    if args.verbose:
        print(f"[*] Detected format: {fmt}", file=sys.stderr)

    engine = Engine(active_rules(), threshold_404=args.threshold_404,
                    threshold_500=args.threshold_500,
                    threshold_rate=args.threshold_rate)
    stats = Stats()

    out = sys.stdout
    if args.output:
        try:
            out = open(args.output, "w", encoding="utf-8")
        except OSError as exc:
            print(f"error: cannot write {args.output}: {exc}", file=sys.stderr)
            return 1
    csv_handle = csv_writer = None
    if args.csv_out:
        try:
            csv_handle = open(args.csv_out, "w", encoding="utf-8", newline="")
        except OSError as exc:
            print(f"error: cannot write {args.csv_out}: {exc}", file=sys.stderr)
            return 1
        csv_writer = csv.writer(csv_handle)
        csv_writer.writerow(["detection", "severity", "description",
                             "timestamp", "c_ip", "method", "uri", "status",
                             "field", "value", "line"])

    color = out.isatty() and not args.json
    found = 0
    try:
        for record in parse(args.file, fmt=fmt, follow=args.follow):
            when = parse_record_time(record.get("timestamp"))
            if since and (when is None or when < since):
                continue
            if until and when is not None and when > until:
                if args.follow:
                    continue
                break
            stats.add_record(record)
            detections = list(engine.scan(record))
            stats.add_detections(detections)
            for det in detections:
                found += 1
                if args.json:
                    out.write(json.dumps(det) + "\n")
                else:
                    out.write(_format_text(det, color) + "\n")
                if csv_writer:
                    csv_writer.writerow([det.get(k) for k in (
                        "detection", "severity", "description", "timestamp",
                        "c_ip", "method", "uri", "status", "field", "value",
                        "line")])
            if args.follow:
                out.flush()
    except KeyboardInterrupt:
        print("\n[!] interrupted", file=sys.stderr)
    finally:
        if csv_handle:
            csv_handle.close()
        if out is not sys.stdout:
            out.close()

    if args.top:
        _print_top(stats, args.top)
    print(f"\n[*] {stats.total} requests analyzed, {found} detections "
          f"({stats.suspicious} suspicious requests, "
          f"{len(stats.ips)} unique IPs)", file=sys.stderr)
    return 2 if found else 0


def _print_top(stats: Stats, n: int) -> None:
    summary = stats.summary(n)
    sections = (("Top Source IPs", "top_source_ips"),
                ("Top Status Codes", "top_status_codes"),
                ("Top Methods", "top_methods"),
                ("Top URIs", "top_uris"),
                ("Top User Agents", "top_user_agents"))
    for title, key in sections:
        print(f"\n=== {title} ===")
        for item in summary[key]:
            print(f"{item['count']:>10}  {item['value'][:100]}")
    if summary["detections_by_type"]:
        print("\n=== Detections by Type ===")
        for name, count in summary["detections_by_type"].items():
            print(f"{count:>10}  {name}")


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.ERROR,
        format="%(levelname)s %(message)s", stream=sys.stderr)

    if args.web:
        from .web.app import serve
        serve(host=args.host, port=args.port)
        return 0
    if not args.file:
        build_parser().print_help()
        return 1
    return run_scan(args)


if __name__ == "__main__":
    sys.exit(main())
