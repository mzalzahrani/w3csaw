"""End-to-end CLI tests running against fixtures and bundled rules."""

import csv
import json

from w3csaw.cli import main
from tests.conftest import FIXTURES, RULES_DIR, fixture


def test_scan_jsonl_end_to_end(tmp_path):
    out = tmp_path / "findings.jsonl"
    code = main(["scan", "-i", fixture("attack.log"), "-r", RULES_DIR,
                 "-o", str(out), "--format", "jsonl", "--include-raw"])
    assert code == 2  # findings present
    findings = [json.loads(line) for line in out.read_text().splitlines()]
    rule_ids = {f["rule_id"] for f in findings}
    assert "iis_webshell_command_execution_query" in rule_ids
    assert "iis_sql_injection_keywords" in rule_ids
    assert "iis_scanner_user_agent" in rule_ids
    assert "iis_path_traversal" in rule_ids
    assert "iis_log4shell_payload" in rule_ids
    webshell = next(f for f in findings
                    if f["rule_id"] == "iis_webshell_command_execution_query")
    assert webshell["src_ip"] == "185.10.20.30"
    assert webshell["uri_query"] == "cmd=whoami"
    assert webshell["line_number"] == 4
    assert webshell["raw_line"].startswith("2026-07-03 10:22:01")


def test_scan_min_level_filters(tmp_path):
    out = tmp_path / "findings.jsonl"
    main(["scan", "-i", fixture("attack.log"), "-r", RULES_DIR,
          "-o", str(out), "--min-level", "critical"])
    findings = [json.loads(line) for line in out.read_text().splitlines()]
    assert findings
    assert all(f["level"] == "critical" for f in findings)


def test_scan_markdown_report(tmp_path):
    out = tmp_path / "report.md"
    main(["scan", "-i", fixture("attack.log"), "-r", RULES_DIR,
          "-o", str(out), "--format", "md"])
    text = out.read_text()
    assert "# W3CSaw Scan Report" in text
    assert "iis_webshell_command_execution_query" in text


def test_scan_csv(tmp_path):
    out = tmp_path / "findings.csv"
    main(["scan", "-i", fixture("attack.log"), "-r", RULES_DIR,
          "-o", str(out), "--format", "csv"])
    rows = list(csv.DictReader(out.open()))
    assert rows
    assert "rule_id" in rows[0]


def test_scan_clean_log_exits_zero(tmp_path):
    out = tmp_path / "findings.jsonl"
    code = main(["scan", "-i", fixture("clean.log"), "-r", RULES_DIR,
                 "-o", str(out)])
    assert code == 0
    assert out.read_text() == ""


def test_timeline(tmp_path):
    out = tmp_path / "timeline.csv"
    code = main(["timeline", "-i", FIXTURES, "-o", str(out), "--fail-open"])
    assert code == 0
    rows = list(csv.DictReader(out.open()))
    timestamps = [r["timestamp"] for r in rows]
    assert timestamps == sorted(timestamps)
    assert len(rows) > 5


def test_validate_rules_ok(capsys):
    assert main(["validate-rules", "-r", RULES_DIR]) == 0
    assert "0 error(s)" in capsys.readouterr().out


def test_validate_rules_broken(capsys):
    import os
    code = main(["validate-rules", "-r", os.path.join(FIXTURES, "broken_rules")])
    assert code == 1
    out = capsys.readouterr().out
    assert "[FAIL]" in out


def test_rule_info(capsys):
    assert main(["rule-info", "-r", RULES_DIR]) == 0
    out = capsys.readouterr().out
    assert "iis_high_404_single_source" in out
    assert "aggregation" in out


def test_top(capsys):
    assert main(["top", "-i", fixture("attack.log"), "--by", "src_ip",
                 "--limit", "2"]) == 0
    out = capsys.readouterr().out
    assert "185.10.20.30" in out


def test_scan_without_rules_uses_bundled_pack(tmp_path):
    out = tmp_path / "findings.jsonl"
    code = main(["scan", "-i", fixture("attack.log"), "-o", str(out)])
    assert code == 2
    findings = [json.loads(line) for line in out.read_text().splitlines()]
    assert any(f["rule_id"] == "iis_webshell_command_execution_query"
               for f in findings)


def test_missing_input_errors():
    assert main(["scan", "-i", "/nonexistent/path/*.log", "-r", RULES_DIR]) == 1
