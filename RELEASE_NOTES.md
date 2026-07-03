# W3CSaw v0.1.1 (Unreleased)

### Added
- Interactive mode: running `w3csaw` with no arguments (or `w3csaw
  interactive`) shows the banner and guides the analyst through a scan with
  prompts and sensible defaults — no flags required.
- `scan --rules` is now optional and defaults to the bundled W3CSaw rule pack,
  so `w3csaw scan -i logs/` works out of the box; interactive mode auto-loads
  it without prompting.
- Rich terminal output mode for scan results (`--cli`), inspired by offline
  DFIR hunting tools but with W3CSaw's own identity (banner, layout, styling).
- Findings grouped into severity-aware tables, grouped by category, level,
  rule, source IP, or host (`--group-by`).
- Scan summary panel (input, rules, files/lines parsed, findings, highest
  severity, runtime, output file, malformed-lines skipped).
- Optional ASCII banner and hunting progress bar.
- New scan flags: `--full`, `--no-color`, `--quiet`, `--no-banner`,
  `--group-by`, and `--max-table-width`.
- Improved global and per-subcommand `--help` with examples and a documented
  exit-code reference.
- Parser now reports skipped-line counts (surfaced in the `--cli` summary).

### Changed
- Added `rich` as a runtime dependency.
- Exit-code behavior is unchanged (`0` clean, `1` error, `2` findings) and now
  explicitly documented in help and README; exit `2` is a successful scan with
  findings, not a failure.

### Unchanged
- JSONL, CSV, timeline, and Markdown outputs are byte-for-byte the same.
- Streaming, memory-efficient log parsing; only findings are held in memory
  for rendering.

---

# W3CSaw v0.1.0

Initial release — Chainsaw-style DFIR hunting for IIS W3C logs.

## Highlights

- **Streaming W3C parser**: respects `#Fields:` headers, tolerates field-order
  changes mid-file and across files, preserves raw lines with file/line
  provenance, and handles malformed lines (strict by default, `--fail-open`
  to skip).
- **Stable normalized schema** with derived hunting helpers: recursive URL
  decoding (`uri_query_decoded`, `url_decoded`) surfaces double-encoded
  payloads while originals are preserved.
- **Sigma-inspired native rule engine**: equals/contains/startswith/endswith
  (+ `_any` variants), `re`, `in`, `exists`/`not_exists`, numeric
  `gte/gt/lte/lt`, conditions `A`, `A and B`, `A or B`, `A and not B`.
- **Aggregation engine** (single streaming pass, bounded memory): threshold
  (`count_gte` per group per time window), sequence (`followed_by`, e.g.
  401/403 brute force then 200), and rarity (`count_lte`, e.g. rarely-hit
  successful dynamic scripts).
- **Five commands**: `scan`, `timeline`, `top`, `validate-rules`, `rule-info`.
- **Outputs**: JSONL, CSV, and a full Markdown DFIR report with severity
  breakdown, top talkers, rule hit summary, and correlation guidance.
- **21 starter rules** across webshell, RCE, traversal, scanning, auth, and
  upload categories with MITRE ATT&CK tags.
- 81 unit/integration tests; example IIS log and generated example report.

## Known limitations

- IIS logs cannot confirm code execution — correlate with EVTX/Sysmon/EDR.
- POST bodies are not logged by default IIS configurations.
- Condition grammar is intentionally minimal (no parentheses/3+ selections).
