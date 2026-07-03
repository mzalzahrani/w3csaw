"""Parser tests: #Fields handling, layout changes, malformed lines."""

import pytest

from w3csaw.parser import ParseError, parse_file, parse_files
from tests.conftest import fixture


def test_fields_header_parsed():
    records = list(parse_file(fixture("basic.log")))
    assert len(records) == 4
    first = records[0].fields
    assert first["cs-method"] == "GET"
    assert first["cs-uri-stem"] == "/index.html"
    assert first["sc-status"] == "200"
    assert first["c-ip"] == "192.168.1.10"


def test_raw_line_and_provenance_preserved():
    records = list(parse_file(fixture("basic.log")))
    assert records[0].line_number == 5
    assert records[0].log_file.endswith("basic.log")
    assert records[0].raw_line.startswith("2026-07-03 10:00:01")


def test_field_order_change_mid_file():
    records = list(parse_file(fixture("reorder.log")))
    assert len(records) == 4
    # first layout: c-ip in position 3
    assert records[0].fields["c-ip"] == "172.16.0.9"
    assert "cs-uri-query" not in records[0].fields
    # second layout: different order, extra field
    assert records[2].fields["c-ip"] == "172.16.0.10"
    assert records[2].fields["cs-uri-query"] == "id=5"
    assert records[2].fields["sc-status"] == "200"


def test_malformed_lines_fail_open():
    records = list(parse_file(fixture("malformed.log"), fail_open=True))
    assert len(records) == 2
    assert records[0].fields["cs-uri-stem"] == "/ok.html"
    assert records[1].fields["cs-uri-stem"] == "/also-ok.html"


def test_malformed_lines_strict_raises():
    with pytest.raises(ParseError):
        list(parse_file(fixture("malformed.log"), fail_open=False))


def test_multiple_files_different_layouts():
    records = list(parse_files([fixture("basic.log"), fixture("reorder.log")]))
    assert len(records) == 8


def test_missing_file_fail_open_continues():
    records = list(parse_files([fixture("nope.log"), fixture("basic.log")],
                               fail_open=True))
    assert len(records) == 4
