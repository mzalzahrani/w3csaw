"""Output writer tests: JSONL, CSV, timeline, Markdown report."""

import csv
import io
import json

from w3csaw.engine import Finding
from w3csaw.outputs import (top_counts, write_findings_csv,
                            write_findings_jsonl, write_timeline_csv)
from w3csaw.report import write_markdown_report


def _finding(**overrides) -> Finding:
    base = dict(
        rule_id="iis_test", rule_title="Test Rule", level="high",
        status="experimental", description="desc",
        timestamp="2026-07-03T10:22:01Z", src_ip="185.10.20.30",
        method="GET", uri_path="/upload/test.aspx", uri_query="cmd=whoami",
        status_code=200, user_agent="curl/8.0", referer=None, host=None,
        matched_fields=["uri_query_decoded"], matched_values=["cmd=whoami"],
        tags=["attack.t1505.003"], falsepositives=["testing"],
        references=["https://example.com"], log_file="u_ex260703.log",
        line_number=421, raw_line="2026-07-03 10:22:01 ...",
    )
    base.update(overrides)
    return Finding(**base)


def test_jsonl_roundtrip():
    buffer = io.StringIO()
    count = write_findings_jsonl([_finding()], buffer, include_raw=True)
    assert count == 1
    data = json.loads(buffer.getvalue().strip())
    assert data["rule_id"] == "iis_test"
    assert data["status_code"] == 200
    assert data["tags"] == ["attack.t1505.003"]
    assert data["raw_line"].startswith("2026-07-03")


def test_jsonl_raw_excluded_by_default():
    buffer = io.StringIO()
    write_findings_jsonl([_finding()], buffer)
    assert "raw_line" not in json.loads(buffer.getvalue())


def test_csv_columns_and_list_joining():
    buffer = io.StringIO()
    count = write_findings_csv([_finding(tags=["a", "b"])], buffer,
                               include_raw=True)
    assert count == 1
    rows = list(csv.DictReader(io.StringIO(buffer.getvalue())))
    assert rows[0]["rule_id"] == "iis_test"
    assert rows[0]["tags"] == "a;b"
    assert rows[0]["raw_line"].startswith("2026-07-03")


def test_timeline_csv():
    records = [
        {"timestamp": "2026-07-03T10:00:01Z", "date": "2026-07-03",
         "time": "10:00:01", "method": "GET", "uri_path": "/a",
         "src_ip": "1.2.3.4", "status": 200, "log_file": "x.log",
         "line_number": 5},
    ]
    buffer = io.StringIO()
    count = write_timeline_csv(records, buffer)
    assert count == 1
    rows = list(csv.DictReader(io.StringIO(buffer.getvalue())))
    assert rows[0]["timestamp"] == "2026-07-03T10:00:01Z"
    assert rows[0]["src_ip"] == "1.2.3.4"


def test_top_counts():
    records = [{"src_ip": ip} for ip in
               ("1.1.1.1", "2.2.2.2", "1.1.1.1", "1.1.1.1", "2.2.2.2")]
    ranked = top_counts(records, "src_ip", limit=1)
    assert ranked == [("1.1.1.1", 3)]


def test_markdown_report_sections():
    buffer = io.StringIO()
    stats = {"input": "logs/", "rules_path": "rules/", "rules_loaded": 21,
             "files_parsed": 2, "lines_parsed": 100}
    write_markdown_report(buffer, [_finding(), _finding(level="critical")], stats)
    text = buffer.getvalue()
    for section in ("# W3CSaw Scan Report", "## Findings by Severity",
                    "## Top Source IPs", "## Top Suspicious URI Paths",
                    "## Top User Agents", "## Rule Hit Summary",
                    "## Detailed Findings", "## Analyst Notes",
                    "## Recommended Next Hunting Steps"):
        assert section in text
    assert "185.10.20.30" in text
    assert "w3wp.exe" in text
