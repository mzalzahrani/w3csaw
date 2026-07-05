"""CSV input tests: header canonicalization, quoting, malformed rows."""

import pytest

from w3csaw.normalizer import normalize
from w3csaw.parser import ParseError, parse_file
from w3csaw.utils import expand_inputs


def _write(tmp_path, name, text):
    path = tmp_path / name
    path.write_text(text, encoding="utf-8")
    return str(path)


BASIC_CSV = (
    "date,time,c-ip,cs-method,cs-uri-stem,cs-uri-query,sc-status,cs(User-Agent)\n"
    "2026-07-03,10:00:01,192.168.1.10,GET,/index.html,-,200,Mozilla/5.0\n"
    "2026-07-03,10:00:02,10.0.0.5,POST,/upload.aspx,cmd=whoami,200,curl/8.0\n"
)


def test_basic_csv_parsed(tmp_path):
    records = list(parse_file(_write(tmp_path, "basic.csv", BASIC_CSV)))
    assert len(records) == 2
    first = records[0].fields
    assert first["cs-method"] == "GET"
    assert first["cs-uri-stem"] == "/index.html"
    assert first["sc-status"] == "200"
    assert first["c-ip"] == "192.168.1.10"
    assert records[0].line_number == 2
    assert records[0].log_file.endswith("basic.csv")


def test_header_aliases_canonicalized(tmp_path):
    text = (
        "Date,Time,client_ip,Method,cs_uri_stem,cs_uri_query,SC_Status,User-Agent\n"
        "2026-07-03,10:00:01,192.168.1.10,GET,/a.aspx,x=1,200,sqlmap/1.7\n"
    )
    records = list(parse_file(_write(tmp_path, "alias.csv", text)))
    fields = records[0].fields
    assert fields["cs-method"] == "GET"
    assert fields["cs-uri-stem"] == "/a.aspx"
    assert fields["sc-status"] == "200"
    assert fields["cs(User-Agent)"] == "sqlmap/1.7"
    row = normalize(records[0])
    assert row["method"] == "GET"
    assert row["uri_path"] == "/a.aspx"
    assert row["status"] == 200
    assert row["user_agent"] == "sqlmap/1.7"
    assert row["timestamp"] == "2026-07-03T10:00:01Z"


def test_quoted_commas_and_empty_cells(tmp_path):
    text = (
        "date,time,c-ip,cs-method,cs-uri-stem,cs-uri-query,sc-status,cs(User-Agent)\n"
        '2026-07-03,10:00:01,1.2.3.4,GET,/x.aspx,"a=1,b=2",200,\n'
    )
    records = list(parse_file(_write(tmp_path, "quoted.csv", text)))
    fields = records[0].fields
    assert fields["cs-uri-query"] == "a=1,b=2"
    assert fields["cs(User-Agent)"] == "-"
    row = normalize(records[0])
    assert row["user_agent"] is None


def test_bom_header_handled(tmp_path):
    text = "﻿date,time,c-ip,sc-status\n2026-07-03,10:00:01,1.2.3.4,404\n"
    records = list(parse_file(_write(tmp_path, "bom.csv", text)))
    assert records[0].fields["date"] == "2026-07-03"
    assert records[0].fields["sc-status"] == "404"


def test_column_mismatch_skipped_fail_open(tmp_path):
    text = (
        "date,time,c-ip,sc-status\n"
        "2026-07-03,10:00:01,1.2.3.4\n"
        "2026-07-03,10:00:02,1.2.3.4,200\n"
    )
    skips = []
    records = list(parse_file(_write(tmp_path, "bad.csv", text),
                              on_skip=lambda: skips.append(1)))
    assert len(records) == 1
    assert len(skips) == 1


def test_column_mismatch_raises_strict(tmp_path):
    text = "date,time\n2026-07-03\n"
    with pytest.raises(ParseError):
        list(parse_file(_write(tmp_path, "bad.csv", text), fail_open=False))


def test_empty_csv_fails(tmp_path):
    with pytest.raises(ParseError):
        list(parse_file(_write(tmp_path, "empty.csv", ""), fail_open=False))


def test_expand_inputs_finds_csv_in_directory(tmp_path):
    _write(tmp_path, "a.log", "#Fields: date time\n2026-07-03 10:00:01\n")
    _write(tmp_path, "b.csv", BASIC_CSV)
    _write(tmp_path, "c.txt", "ignored")
    files = expand_inputs(str(tmp_path))
    assert [f.split("/")[-1] for f in files] == ["a.log", "b.csv"]
