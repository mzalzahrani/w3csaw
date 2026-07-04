# IIS Hunter

**Real-time threat hunting and forensic analysis for IIS logs** — a shared
streaming parser + detection engine exposed through both a CLI and a modern
web interface.

## Features

- **Content-based format detection** — accepts IIS W3C logs (`.log`/`.txt`),
  CSV exports, and plain text with IIS-like lines. The format is decided by
  inspecting the file contents, never just the extension.
- **Streaming parser** — logs are processed line by line; multi-GB files are
  fine. W3C `#Fields:` headers are honored dynamically, CSV delimiters are
  auto-detected, and common column-name variants are normalized.
- **Modular detection engine** — 30+ built-in detections: SQL/command
  injection, directory & encoded traversal, LFI/RFI, web shells, suspicious
  ASPX/ASHX/ASMX handlers, `.config` access, backup-file discovery,
  PowerShell/cmd/certutil/bitsadmin/curl/wget abuse, scanner user agents
  (nikto, sqlmap, nmap, acunetix, gobuster, ffuf, python-requests), long
  URLs/queries, encoded payloads, Exchange/SharePoint/ASP.NET exploits, and
  threshold detections (excessive 404/500, high request rate, brute force).
- **Custom rules** — create regex or literal rules from the web UI (or edit
  `~/.iis_hunter/rules.json`); built-in rules can be individually disabled.
- **Backend filtering** — all filters run server-side against SQLite:
  contains / exact / regex / starts with / ends with / not contains, plus
  range filters, combinable, with pagination.

## Install

```bash
pip install .
```

## CLI

```bash
iis-hunter --file access.log                       # scan, human-readable output
iis-hunter --file export.csv --json -o out.jsonl   # JSON lines to a file
iis-hunter --file u_ex.log --csv-out detections.csv --top 10
iis-hunter --file live.log --follow                # tail the log in real time
iis-hunter --file u_ex.log --since 2026-07-01 --until 2026-07-02T12:00:00
iis-hunter --file u_ex.log --threshold-404 100 --threshold-rate 500 -v
```

Exit codes: `0` clean, `1` error, `2` detections found.

## Web interface

```bash
iis-hunter --web              # http://127.0.0.1:8787
iis-hunter --web --port 9000 --host 0.0.0.0
```

Upload a log, watch live parsing progress (speed, ETA, line counts), then
explore the dashboard: totals, unique IPs, top status codes / methods /
URIs / user agents, detections by severity and type, and paginated,
filterable tables for both detections and parsed logs. Custom detection
rules and built-in rule toggles are managed from the same page.

Job data lives under `~/.iis_hunter/jobs/` (one SQLite database per upload);
delete an analysis from the UI to remove it.

## Development

```bash
pip install -e ".[dev]"
pytest
```
