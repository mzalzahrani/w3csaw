# W3CSaw

**Chainsaw-style DFIR hunting for IIS W3C logs.**

W3CSaw is a DFIR-focused command-line tool for hunting suspicious activity in
IIS W3C logs. It is inspired by the offline hunting workflow of tools like
Chainsaw, but instead of scanning Windows EVTX, it parses IIS web access logs
and applies web-focused detection rules.

```
w3csaw scan -i "C:\inetpub\logs\LogFiles\W3SVC1\*.log" -r rules/ -o findings.jsonl --summary
```

## Why W3CSaw exists

When a Windows web server is suspected of compromise, the IIS access logs are
often the first — and sometimes the only — artifact available. Grepping
gigabytes of W3C logs by hand is slow and error-prone, and generic log tools
don't understand the `#Fields:` header, changing field layouts, URL-encoded
payloads, or what a web shell interaction actually looks like.

W3CSaw gives incident responders the same workflow Chainsaw gives for event
logs: point it at a folder of logs and a folder of rules, get back ranked,
evidence-rich findings in minutes.

## How it differs from Chainsaw

| | Chainsaw | W3CSaw |
|---|---|---|
| Input | Windows EVTX event logs | IIS W3C web access logs |
| Rules | Sigma + Chainsaw rules | Native Sigma-inspired YAML for web fields |
| Detects | Process, logon, persistence activity | Suspicious HTTP activity (web shells, exploits, scanning, brute force) |
| Confirms execution | Often yes (process events) | **No** — HTTP evidence only; correlate with host telemetry |

They are complementary: run Chainsaw on the EVTX and W3CSaw on the IIS logs
from the same server, then join the timelines.

## Installation

Requires Python 3.9+.

```
git clone https://github.com/mzalzahrani/w3csaw.git
cd w3csaw
pip install .
```

The only runtime dependency is PyYAML. For development:

```
pip install -e ".[dev]"
pytest
```

## Usage

### Interactive mode (easiest way to start)

Just run `w3csaw` with no arguments in a terminal. It shows the banner and then
prompts you for the log path, grouping, and severity — no flags to remember.
The bundled rule pack is loaded automatically:

```
w3csaw
```

You can also launch it explicitly:

```
w3csaw interactive
```

It defaults the input to `examples/sample_iis.log` (if present), auto-loads the
built-in rules, re-asks on a bad path, runs the scan in terminal mode, and
offers to run another. Press Ctrl-C to quit. Everything below is the equivalent
flag-driven usage for scripting and automation.

### scan — hunt with detection rules

```
w3csaw scan -i "C:\inetpub\logs\LogFiles\W3SVC1\*.log" -r rules/ -o findings.jsonl --format jsonl
w3csaw scan -i logs/ -r rules/ -o report.md --format md --min-level medium --summary
```

| Option | Meaning |
|---|---|
| `-i, --input` | Log file, directory (recursive `*.log`), or glob |
| `-r, --rules` | Rules directory or single rule file (default: the bundled W3CSaw rule pack) |
| `-o, --output` | Output file (default: stdout) |
| `--format` | `jsonl`, `csv`, or `md` (default: jsonl) |
| `--min-level` | `low`, `medium`, `high`, `critical` |
| `--include-raw` | Include the raw log line in JSONL/CSV findings |
| `--timezone` | Timezone of log timestamps, e.g. `UTC` or `+03:00` (IIS logs UTC by default) |
| `--fail-open` | Skip malformed lines instead of stopping |
| `--summary` | Print a console summary after the scan |

Exit codes: `0` no findings, `1` error, `2` findings reported — handy for
automation.

### Terminal output mode

By default `scan` writes machine output (JSONL/CSV/Markdown). Add `--cli` for
an analyst-friendly terminal review: an ASCII banner, rule/log loading status,
a hunting progress bar, a scan summary panel, and findings grouped into
severity-aware tables. It is purely presentational — the JSONL, CSV, timeline,
and Markdown formats are unchanged.

```
# Terminal review (findings grouped by category)
w3csaw scan -i examples/sample_iis.log -r rules/ --cli

# Show full, untruncated field values
w3csaw scan -i examples/sample_iis.log -r rules/ --cli --full

# Machine output to a file AND a terminal review at the same time
w3csaw scan -i logs/ -r rules/ --format jsonl -o findings.jsonl --cli

# Group the terminal findings by severity instead of category
w3csaw scan -i examples/sample_iis.log -r rules/ --cli --group-by level
```

Example (colors shown here as plain text):

```
██╗    ██╗██████╗  ██████╗███████╗ █████╗ ██╗    ██╗
██║    ██║╚════██╗██╔════╝██╔════╝██╔══██╗██║    ██║
██║ █╗ ██║ █████╔╝██║     ███████╗███████║██║ █╗ ██║
██║███╗██║ ╚═══██╗██║     ╚════██║██╔══██║██║███╗██║
╚███╔███╔╝██████╔╝╚██████╗███████║██║  ██║╚███╔███╔╝
 ╚══╝╚══╝ ╚═════╝  ╚═════╝╚══════╝╚═╝  ╚═╝ ╚══╝╚══╝
W3CSaw — Chainsaw-style DFIR hunting for IIS W3C logs
By TruePositive / Mohammed Alzahrani (@mzalzahrani)

[+] Loading detection rules from: rules/
[+] Loaded 72 detection rules
[+] Loading IIS W3C logs from: examples/sample_iis.log
[+] Parsed 342 log records from 1 file(s)
╭─────── W3CSaw v0.1.0 scan summary ────────╮
│            Input  examples/sample_iis.log │
│            Rules  rules/ (72 loaded)      │
│     Files parsed  1                       │
│     Lines parsed  342                     │
│         Findings  162                     │
│ Highest severity  critical                │
╰───────────────────────────────────────────╯
[+] Findings: 162 matches across 17 rules
[+] Group: Webshell  (5)
╭───────────┬────────┬──────────────────────────────────────┬───────────────┬────────┬───────────────────────┬────────┬────────────╮
│ timestamp │ level  │ rule                                 │ src_ip        │ method │ uri_path              │ status │ user_agent │
├───────────┼────────┼──────────────────────────────────────┼───────────────┼────────┼───────────────────────┼────────┼────────────┤
│ 2026-07-… │ high   │ iis_webshell_command_execution_query │ 198.51.100.23 │ GET    │ /uploads/profile.ashx │    200 │ curl/8.4.0 │
╰───────────┴────────┴──────────────────────────────────────┴───────────────┴────────┴───────────────────────┴────────┴────────────╯
```

Terminal-mode options for `scan`:

| Option | Meaning |
|---|---|
| `--cli` | Show human-friendly grouped findings in the terminal |
| `--full` | Show full field values instead of truncating long ones |
| `--group-by` | Group findings by `category` (default), `level`, `rule`, `src_ip`, or `host` |
| `--max-table-width N` | Truncate long field values to `N` characters (default: 40) |
| `--no-color` | Disable ANSI colors |
| `--no-banner` | Suppress the ASCII banner only |
| `--quiet` | Suppress banner, progress, and status lines (findings/output still work) |

Notes:
- Severity colors: critical = bold red, high = red, medium = yellow, low = blue.
- `--cli` keeps findings (not raw logs) in memory for rendering; log parsing
  stays streaming, so memory use tracks the number of findings, not log size.
- When `--cli` is used **with** `-o`, machine output goes to the file and the
  tables go to the terminal. When `--cli` is used **without** `-o`, the raw
  machine dump to stdout is suppressed so it doesn't mix with the tables.
- Colors are emitted only on a real terminal; redirected/piped output is always
  plain text.

### timeline — chronological CSV of all requests

```
w3csaw timeline -i logs/ -o timeline.csv
```

### top — quick frequency analysis

```
w3csaw top -i logs/ --by src_ip --limit 20
```

Supported fields: `src_ip`, `uri_path`, `user_agent`, `status`, `method`,
`extension`, `host`.

### validate-rules / rule-info

```
w3csaw validate-rules -r rules/
w3csaw rule-info -r rules/
```

## Help and exit codes

Every command has detailed `--help` with examples:

```
w3csaw --help
w3csaw scan --help
w3csaw timeline --help
w3csaw top --help
w3csaw validate-rules --help
w3csaw rule-info --help
```

- `--cli` is for interactive, analyst-friendly terminal review.
- JSONL / CSV / Markdown remain the right choice for automation, ingestion,
  and reporting — they are stable and machine-parseable.
- `--full` disables field truncation when you need the complete value.
- `--quiet` suppresses banner/progress/status (useful for CI and SOAR while
  still writing output files).

Exit codes:

| Code | Meaning |
|---|---|
| `0` | Completed successfully, no findings |
| `1` | Runtime or validation error |
| `2` | Completed successfully **and** findings were detected |

Exit code `2` is **not** a crash or failure. It means the scan finished
cleanly and matched one or more detections. This is intentional so CI/CD, SOAR
playbooks, and shell scripts can branch on "were there findings?" without
parsing output. For example:

```bash
w3csaw scan -i logs/ -r rules/ -o findings.jsonl
case $? in
  0) echo "clean" ;;
  2) echo "findings detected — escalate" ;;
  *) echo "scan error" ;;
esac
```

## Rule format

Rules are Sigma-inspired YAML tailored to normalized IIS W3C fields:

```yaml
id: iis_webshell_command_execution_query
title: IIS Possible Web Shell Command Execution via Query String
status: experimental
description: Detects command-execution keywords in query strings targeting dynamic IIS script endpoints.
level: high
tags:
  - attack.t1505.003
  - attack.t1059
logsource:
  product: iis
  service: w3c
detection:
  selection:
    status:
      gte: 200
      lt: 300
    uri_path|endswith_any:
      - ".aspx"
      - ".ashx"
    uri_query_decoded|contains_any:
      - "cmd="
      - "whoami"
      - "powershell"
  condition: selection
falsepositives:
  - Internal diagnostics
references:
  - https://attack.mitre.org/techniques/T1505/003/
```

### Fields available to rules

Normalized: `timestamp`, `date`, `time`, `site_name`, `server_ip`, `method`,
`uri_path`, `uri_query`, `src_ip`, `username`, `user_agent`, `referer`,
`status`, `substatus`, `win32_status`, `bytes_sent`, `bytes_received`,
`time_taken`, `host` — plus any raw W3C field present in the log.

Derived helpers: `url_original`, `url_decoded`, `uri_path_decoded`,
`uri_query_decoded` (recursively URL-decoded, so double encoding is
transparent), `is_success_status`, `is_error_status`, `extension`.

### Operators

| Operator | Example |
|---|---|
| exact equals | `method: POST` (a list means any-of) |
| `contains` / `contains_any` | `uri_query_decoded\|contains_any: ["cmd=", "whoami"]` |
| `startswith` / `startswith_any` | `uri_path\|startswith: "/owa"` |
| `endswith` / `endswith_any` | `uri_path\|endswith_any: [".aspx", ".ashx"]` |
| `re` | `uri_query\|re: "(?:url\|target)=https?://"` |
| `in` | `extension\|in: [".aspx", ".svc"]` |
| `exists` / `not_exists` | `referer\|not_exists: true` |
| numeric `gte` `gt` `lte` `lt` | `status: {gte: 200, lt: 300}` |

String matching is case-insensitive. Conditions supported: `selection`,
`a and b`, `a or b`, `selection and not filter`.

### Aggregation rules

For behaviors that only emerge across many requests, set `type: aggregation`:

```yaml
id: iis_high_404_single_source
title: IIS High 404 Volume From Single Source
level: medium
type: aggregation
aggregation:
  group_by:
    - src_ip
  filter:
    status: 404
  count_gte: 100
  window_minutes: 60
```

Three variants:

- **Threshold** (`count_gte`): fires when a group exceeds a count within a
  sliding time window.
- **Sequence** (`count_gte` + `followed_by`): counts precondition events,
  fires when the follow-up event arrives — e.g. 401/403 brute force followed
  by a 200.
- **Rarity** (`count_lte`): evaluated at end of scan; fires for groups seen at
  most N times — e.g. a dynamic script that succeeded only once.

## Bundled rule pack

21 starter rules under `rules/` covering web shell interaction, known shell
filenames, suspicious POSTs, path traversal, double encoding, SQLi/XSS/LDAP
injection, SSTI, Log4Shell, Struts OGNL, Jolokia, OFBiz, Tomcat/JSP uploads,
Exchange/OWA exploitation, SharePoint uploads, MinIO SSRF, scanner user
agents, 404 floods, brute-force-then-success, and rare successful dynamic
extensions.

## Output example

```json
{
  "rule_id": "iis_webshell_command_execution_query",
  "rule_title": "IIS Possible Web Shell Command Execution via Query String",
  "level": "high",
  "timestamp": "2026-07-03T12:15:41Z",
  "src_ip": "198.51.100.23",
  "method": "GET",
  "uri_path": "/uploads/profile.ashx",
  "uri_query": "cmd=whoami",
  "status_code": 200,
  "user_agent": "curl/8.4.0",
  "tags": ["attack.t1505.003", "attack.t1059"],
  "matched_fields": ["status", "uri_path", "uri_query_decoded"],
  "log_file": "examples/sample_iis.log",
  "line_number": 320
}
```

Try it yourself: `examples/sample_iis.log` contains benign traffic plus six
attack scenarios, and `examples/sample_report.md` is the Markdown report
W3CSaw produced from it.

## DFIR workflow

1. Collect `C:\inetpub\logs\LogFiles\W3SVC*\*.log` from the suspect server.
2. `w3csaw scan -i logs/ -r rules/ -o findings.jsonl --summary`
3. Triage by severity, then pivot: `w3csaw top -i logs/ --by src_ip` and
   `w3csaw timeline -i logs/ -o timeline.csv` around finding timestamps.
4. **Correlate every hit with host telemetry** before calling it execution:
   - `Security.evtx` (logons 4624/4625/4672 around the timestamps)
   - `System.evtx` / `Application.evtx` (service installs, IIS worker events)
   - `Microsoft-Windows-PowerShell/Operational.evtx` (script blocks, 4104)
   - `Microsoft-Windows-Sysmon/Operational.evtx` (process/network events)
   - `w3wp.exe` child processes in EDR process trees (cmd/powershell spawned
     by the IIS worker is a strong web shell signal)
   - Web root file changes (new `.aspx`/`.ashx` files, $MFT/USN timestamps)
   - IIS configuration changes, new services, scheduled tasks, local users,
     and outbound connections from the web server

## Limitations

- **IIS logs do not show process execution.** W3CSaw detects suspicious HTTP
  activity; it cannot confirm code execution on its own.
- POST body content is not present in default IIS logs — a web shell
  controlled entirely via POST bodies may only surface as anomalous POST
  patterns, sizes, or rare endpoints.
- W3C fields are configurable per server. Missing fields are handled
  gracefully (rules touching them simply don't match), so review which fields
  your logs actually contain.
- Timestamps depend on the server's IIS logging configuration (UTC by
  default; use `--timezone` for local-time logs).
- Signature rules inherit signature blind spots: encrypted, novel, or heavily
  obfuscated payloads may not match. Use `timeline`, `top`, and the rarity
  aggregation to hunt beyond signatures.

## Roadmap

- Sigma web/proxy rule importer (`sigma convert` compatible subset)
- More aggregation primitives (distinct-count, ratio, first-seen)
- Additional log formats (IIS ODBC, NCSA, ARR proxy logs)
- Findings deduplication and clustering
- JSON output for `top` and machine-readable scan stats

## License

MIT — see [LICENSE](LICENSE).
