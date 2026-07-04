"""Core tests: format detection, parsers, detections, store filters, CLI."""

import json

import pytest

from iis_hunter.cli import main
from iis_hunter.engine import Engine, Stats
from iis_hunter.parser import ParseError, detect_format, parse
from iis_hunter.rules import BUILTIN_RULES, custom_rule_from_dict
from iis_hunter.store import Store

W3C = """#Software: Microsoft Internet Information Services 10.0
#Fields: date time s-ip cs-method cs-uri-stem cs-uri-query s-port c-ip cs(User-Agent) sc-status time-taken
2026-07-01 10:00:00 10.0.0.1 GET /index.html - 443 203.0.113.5 Mozilla/5.0 200 12
2026-07-01 10:00:01 10.0.0.1 GET /login.aspx user=admin'%20or%20'1'='1 443 203.0.113.9 sqlmap/1.7 500 40
2026-07-01 10:00:02 10.0.0.1 GET /files/../../web.config - 443 203.0.113.9 Mozilla/5.0 404 3
2026-07-01 10:00:03 10.0.0.1 POST /uploads/shell.aspx cmd=whoami 443 203.0.113.9 - 200 55
"""

CSV_LOG = (
    "date,time,c-ip,cs-method,cs-uri-stem,cs-uri-query,sc-status,User-Agent\n"
    "2026-07-01,10:00:00,203.0.113.5,GET,/index.html,-,200,Mozilla/5.0\n"
    '2026-07-01,10:00:01,203.0.113.9,GET,/a.aspx,"q=union select 1,2",500,nikto/2.5\n'
)

PLAIN = (
    "2026-07-01 10:00:00 10.0.0.1 GET /site/backup.zip - 443 - 203.0.113.7 "
    "gobuster/3.6 - 404 0 2 15\n"
)


def _write(tmp_path, name, text):
    path = tmp_path / name
    path.write_text(text, encoding="utf-8")
    return str(path)


# ---------------------------------------------------------------- formats

def test_detect_w3c_regardless_of_extension(tmp_path):
    assert detect_format(_write(tmp_path, "log.csv", W3C)) == "w3c"


def test_detect_csv_regardless_of_extension(tmp_path):
    assert detect_format(_write(tmp_path, "export.log", CSV_LOG)) == "csv"


def test_detect_plain(tmp_path):
    assert detect_format(_write(tmp_path, "lines.txt", PLAIN)) == "plain"


def test_detect_empty_raises(tmp_path):
    with pytest.raises(ParseError):
        detect_format(_write(tmp_path, "empty.log", ""))


# ---------------------------------------------------------------- parsers

def test_w3c_parse_and_normalize(tmp_path):
    rows = list(parse(_write(tmp_path, "a.log", W3C)))
    assert len(rows) == 4
    assert rows[0]["method"] == "GET"
    assert rows[0]["status"] == 200
    assert rows[0]["c_ip"] == "203.0.113.5"
    assert rows[0]["timestamp"] == "2026-07-01T10:00:00"
    assert rows[1]["url"] == "/login.aspx?user=admin' or '1'='1"
    assert rows[3]["user_agent"] is None


def test_csv_parse(tmp_path):
    rows = list(parse(_write(tmp_path, "a.csv", CSV_LOG)))
    assert len(rows) == 2
    assert rows[1]["uri_query"] == "q=union select 1,2"
    assert rows[1]["user_agent"] == "nikto/2.5"
    assert rows[1]["status"] == 500


def test_plain_parse(tmp_path):
    rows = list(parse(_write(tmp_path, "a.txt", PLAIN)))
    assert len(rows) == 1
    assert rows[0]["method"] == "GET"
    assert rows[0]["uri_stem"] == "/site/backup.zip"
    assert rows[0]["c_ip"] == "203.0.113.7"
    assert rows[0]["status"] == 404


# ---------------------------------------------------------------- rules

def test_builtin_rules_compile_unique():
    names = [rule.name for rule in BUILTIN_RULES]
    assert len(names) == len(set(names))
    assert all(rule.match_type != "regex" or rule._compiled
               for rule in BUILTIN_RULES)


def _detections_for(tmp_path, log_text):
    engine = Engine()
    found = []
    for record in parse(_write(tmp_path, "d.log", log_text)):
        found.extend(engine.scan(record))
    return found


def test_detections_fire(tmp_path):
    names = {d["detection"] for d in _detections_for(tmp_path, W3C)}
    assert {"sql_injection", "scanner_sqlmap", "directory_traversal",
            "config_file_access", "web_shell_name", "command_execution",
            "missing_user_agent"} <= names


def test_detection_shape(tmp_path):
    det = _detections_for(tmp_path, W3C)[0]
    for key in ("detection", "severity", "description", "timestamp", "c_ip",
                "method", "uri", "status", "field", "value"):
        assert key in det


def test_threshold_404(tmp_path):
    lines = [
        "#Fields: date time c-ip cs-method cs-uri-stem sc-status",
    ] + [f"2026-07-01 10:00:{i:02d} 203.0.113.9 GET /x{i} 404"
         for i in range(30)]
    engine = Engine(rules=[], threshold_404=20)
    found = []
    for record in parse(_write(tmp_path, "n.log", "\n".join(lines) + "\n")):
        found.extend(engine.scan(record))
    assert any(d["detection"] == "excessive_404" for d in found)


def test_custom_rule_validation():
    rule = custom_rule_from_dict({
        "name": "ioc_ip", "severity": "critical", "field": "c_ip",
        "match_type": "literal", "pattern": "198.51.100.77",
        "description": "known C2"})
    assert rule.match({"c_ip": "198.51.100.77"}) == "198.51.100.77"
    with pytest.raises(ValueError):
        custom_rule_from_dict({"name": "bad", "severity": "urgent",
                               "pattern": "x"})
    with pytest.raises(Exception):
        custom_rule_from_dict({"name": "bad", "severity": "low",
                               "match_type": "regex", "pattern": "("})


# ---------------------------------------------------------------- store

@pytest.fixture()
def loaded_store(tmp_path):
    store = Store(str(tmp_path / "job.db"))
    rows = list(parse(_write(tmp_path, "s.log", W3C)))
    engine = Engine()
    dets = [d for r in rows for d in engine.scan(r)]
    store.insert_records(rows)
    store.insert_detections(dets)
    store.commit()
    store.create_indexes()
    yield store
    store.close()


def test_store_pagination(loaded_store):
    page = loaded_store.query_logs([], page=1, size=2)
    assert page["total"] == 4 and page["pages"] == 2 and len(page["rows"]) == 2


def test_store_filters(loaded_store):
    hit = loaded_store.query_logs(
        [{"field": "uri_stem", "mode": "contains", "value": "shell"}], 1, 50)
    assert hit["total"] == 1
    excl = loaded_store.query_logs(
        [{"field": "uri_stem", "mode": "not_contains", "value": ".aspx"}], 1, 50)
    assert excl["total"] == 2
    rx = loaded_store.query_logs(
        [{"field": "_regex", "mode": "regex", "value": r"or\s+'1'='1"}], 1, 50)
    assert rx["total"] == 1
    combo = loaded_store.query_logs(
        [{"field": "c_ip", "mode": "exact", "value": "203.0.113.9"},
         {"field": "status", "mode": "gte", "value": 400}], 1, 50)
    assert combo["total"] == 2  # the 500 on /login.aspx and the 404 traversal
    sev = loaded_store.query_detections(
        [{"field": "severity", "mode": "exact", "value": "critical"}], 1, 50)
    assert sev["total"] >= 1
    with pytest.raises(ValueError):
        loaded_store.query_logs(
            [{"field": "raw; DROP TABLE", "mode": "exact", "value": "x"}], 1, 5)


# ---------------------------------------------------------------- cli

def test_cli_json_and_exit_code(tmp_path, capsys):
    log = _write(tmp_path, "cli.log", W3C)
    out_file = tmp_path / "out.jsonl"
    code = main(["--file", log, "--json", "--output", str(out_file),
                 "--csv-out", str(tmp_path / "det.csv")])
    assert code == 2
    lines = out_file.read_text().strip().splitlines()
    assert lines and all(json.loads(ln)["detection"] for ln in lines)
    assert (tmp_path / "det.csv").read_text().count("\n") == len(lines) + 1


def test_cli_since_until(tmp_path):
    log = _write(tmp_path, "cli.log", W3C)
    code = main(["--file", log, "--json", "--since", "2027-01-01",
                 "--output", str(tmp_path / "o.jsonl")])
    assert code == 0
    assert (tmp_path / "o.jsonl").read_text() == ""


def test_stats_summary(tmp_path):
    stats = Stats()
    for record in parse(_write(tmp_path, "s.log", W3C)):
        stats.add_record(record)
        stats.add_detections(list(Engine().scan(record)))
    summary = stats.summary()
    assert summary["total_requests"] == 4
    assert summary["unique_source_ips"] == 2
    assert summary["top_methods"][0]["value"] == "GET"
