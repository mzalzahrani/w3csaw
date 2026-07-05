"""Aggregation engine tests: thresholds, windows, sequences, rarity."""

from typing import Any, Dict, List

from w3csaw.aggregations import AggregationEngine
from w3csaw.rules import Rule


def _record(time: str, src_ip: str = "185.10.20.30", status: int = 404,
            uri_path: str = "/probe", **extra) -> Dict[str, Any]:
    record = {
        "date": "2026-07-03", "time": time, "src_ip": src_ip,
        "status": status, "uri_path": uri_path, "method": "GET",
        "uri_query": None, "user_agent": "curl/8.0", "referer": None,
        "host": None, "extension": None, "raw_line": "raw",
        "log_file": "t.log", "line_number": 1,
        "timestamp": f"2026-07-03T{time}Z",
    }
    record.update(extra)
    return record


def _threshold_rule(count: int = 5, window: int = 10) -> Rule:
    return Rule(id="agg_404", title="High 404", level="medium",
                type="aggregation",
                aggregation={"group_by": ["src_ip"],
                             "filter": {"status": 404},
                             "count_gte": count, "window_minutes": window})


def test_threshold_fires_at_count():
    engine = AggregationEngine([_threshold_rule(count=5)])
    findings: List = []
    for i in range(6):
        findings += engine.process(_record(f"10:00:0{i}"))
    assert len(findings) == 1
    assert findings[0].rule_id == "agg_404"
    assert "event_count" in findings[0].matched_fields


def test_threshold_respects_window():
    engine = AggregationEngine([_threshold_rule(count=5, window=10)])
    findings: List = []
    # 4 events, then a long gap that expires them, then 4 more: never fires
    for minute in (0, 1, 2, 3, 30, 31, 32, 33):
        findings += engine.process(_record(f"10:{minute:02d}:00"))
    assert findings == []


def test_threshold_ignores_non_matching_filter():
    engine = AggregationEngine([_threshold_rule(count=3)])
    findings: List = []
    for i in range(5):
        findings += engine.process(_record(f"10:00:0{i}", status=200))
    assert findings == []


def test_threshold_groups_by_key():
    engine = AggregationEngine([_threshold_rule(count=3)])
    findings: List = []
    for i in range(4):
        findings += engine.process(_record(f"10:00:0{i}", src_ip=f"10.0.0.{i}"))
    assert findings == []


def _sequence_rule() -> Rule:
    return Rule(id="agg_brute", title="Brute then success", level="high",
                type="aggregation",
                aggregation={"group_by": ["src_ip"],
                             "filter": {"status|in": ["401", "403"]},
                             "followed_by": {"status": {"gte": 200, "lt": 300}},
                             "count_gte": 3, "window_minutes": 30})


def test_sequence_fires_on_success_after_failures():
    engine = AggregationEngine([_sequence_rule()])
    findings: List = []
    for i in range(3):
        findings += engine.process(_record(f"10:00:0{i}", status=401))
    assert findings == []
    findings += engine.process(_record("10:00:05", status=200))
    assert len(findings) == 1
    assert findings[0].rule_id == "agg_brute"
    assert findings[0].status_code == 200


def test_sequence_needs_enough_failures():
    engine = AggregationEngine([_sequence_rule()])
    findings: List = []
    findings += engine.process(_record("10:00:00", status=401))
    findings += engine.process(_record("10:00:01", status=200))
    assert findings == []


def test_rarity_rule_fires_at_finalize():
    rule = Rule(id="agg_rare", title="Rare dynamic ext", level="medium",
                type="aggregation",
                aggregation={"group_by": ["uri_path"],
                             "filter": {"extension|in": [".aspx"],
                                        "status": {"gte": 200, "lt": 300}},
                             "count_lte": 2, "window_minutes": 1440})
    engine = AggregationEngine([rule])
    # /common.aspx hit 5 times, /shell.aspx hit once
    for i in range(5):
        engine.process(_record(f"10:00:0{i}", status=200,
                               uri_path="/common.aspx", extension=".aspx"))
    engine.process(_record("10:01:00", status=200,
                           uri_path="/shell.aspx", extension=".aspx"))
    findings = engine.finalize()
    assert len(findings) == 1
    assert findings[0].uri_path == "/shell.aspx"


def test_records_without_timestamp_ignored():
    engine = AggregationEngine([_threshold_rule(count=1)])
    record = _record("10:00:00")
    record["date"] = None
    assert engine.process(record) == []
