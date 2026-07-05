"""Detection engine tests: operators, conditions, finding assembly."""

import pytest

from w3csaw.engine import evaluate_field, evaluate_rule, scan_record
from w3csaw.rules import Rule

RECORD = {
    "timestamp": "2026-07-03T10:22:01Z",
    "date": "2026-07-03",
    "time": "10:22:01",
    "src_ip": "185.10.20.30",
    "method": "GET",
    "uri_path": "/upload/test.aspx",
    "uri_query": "cmd=whoami",
    "uri_path_decoded": "/upload/test.aspx",
    "uri_query_decoded": "cmd=whoami",
    "url_original": "/upload/test.aspx?cmd=whoami",
    "url_decoded": "/upload/test.aspx?cmd=whoami",
    "status": 200,
    "user_agent": "curl/8.0",
    "referer": None,
    "host": None,
    "extension": ".aspx",
    "raw_line": "2026-07-03 10:22:01 ...",
    "log_file": "u_ex260703.log",
    "line_number": 421,
}


@pytest.mark.parametrize("key,expected,hit", [
    ("method", "GET", True),
    ("method", "get", True),               # case-insensitive
    ("method", "POST", False),
    ("method", ["POST", "GET"], True),     # list equals = any-of
    ("uri_path|contains", "upload", True),
    ("uri_path|contains", "nope", False),
    ("uri_query_decoded|contains_any", ["exec=", "whoami"], True),
    ("uri_path|startswith", "/upload", True),
    ("uri_path|startswith_any", ["/api", "/upload"], True),
    ("uri_path|endswith", ".ASPX", True),
    ("uri_path|endswith_any", [".php", ".aspx"], True),
    ("uri_query|re", r"cmd=\w+", True),
    ("uri_query|re", r"^nomatch$", False),
    ("method|in", ["GET", "HEAD"], True),
    ("method|in", ["PUT", "DELETE"], False),
    ("user_agent|exists", True, True),
    ("referer|exists", True, False),
    ("referer|not_exists", True, True),
    ("status", {"gte": 200, "lt": 300}, True),
    ("status", {"gte": 400}, False),
    ("status", {"gt": 199, "lte": 200}, True),
    ("missing_field|contains", "x", False),
])
def test_operators(key, expected, hit):
    assert evaluate_field(RECORD, key, expected) is hit


def _rule(detection) -> Rule:
    return Rule(id="r", title="R", level="high", detection=detection)


def test_condition_single_selection():
    rule = _rule({"selection": {"method": "GET"}, "condition": "selection"})
    assert evaluate_rule(rule, RECORD) is not None


def test_condition_and():
    rule = _rule({"a": {"method": "GET"}, "b": {"status": {"gte": 200}},
                  "condition": "a and b"})
    assert evaluate_rule(rule, RECORD) is not None
    rule = _rule({"a": {"method": "POST"}, "b": {"status": {"gte": 200}},
                  "condition": "a and b"})
    assert evaluate_rule(rule, RECORD) is None


def test_condition_or():
    rule = _rule({"a": {"method": "POST"}, "b": {"uri_path|contains": "upload"},
                  "condition": "a or b"})
    assert evaluate_rule(rule, RECORD) is not None


def test_condition_and_not():
    rule = _rule({"selection": {"method": "GET"},
                  "filter": {"src_ip": "185.10.20.30"},
                  "condition": "selection and not filter"})
    assert evaluate_rule(rule, RECORD) is None
    rule = _rule({"selection": {"method": "GET"},
                  "filter": {"src_ip": "10.0.0.1"},
                  "condition": "selection and not filter"})
    assert evaluate_rule(rule, RECORD) is not None


def test_finding_contents():
    rule = Rule(
        id="iis_webshell_command_execution_query",
        title="IIS Possible Web Shell Command Execution via Query String",
        level="high",
        tags=["attack.t1505.003"],
        detection={"selection": {
            "uri_query_decoded|contains_any": ["cmd=", "whoami"],
            "uri_path|endswith_any": [".aspx"],
            "status": {"gte": 200, "lt": 300},
        }, "condition": "selection"},
    )
    findings = scan_record([rule], RECORD)
    assert len(findings) == 1
    finding = findings[0]
    assert finding.rule_id == "iis_webshell_command_execution_query"
    assert finding.level == "high"
    assert finding.src_ip == "185.10.20.30"
    assert finding.status_code == 200
    assert finding.line_number == 421
    assert set(finding.matched_fields) == {"uri_query_decoded", "uri_path", "status"}
    assert "cmd=whoami" in finding.matched_values
    data = finding.to_dict(include_raw=True)
    assert data["raw_line"].startswith("2026-07-03")
    assert "raw_line" not in finding.to_dict(include_raw=False)


def test_aggregation_rules_skipped_in_line_scan():
    rule = Rule(id="agg", title="A", level="low", type="aggregation",
                aggregation={"group_by": ["src_ip"], "count_gte": 1,
                             "window_minutes": 1})
    assert scan_record([rule], RECORD) == []
