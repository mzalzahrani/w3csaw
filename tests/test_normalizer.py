"""Normalizer tests: field mapping, typing, decoding, derived fields."""

from w3csaw.normalizer import normalize
from w3csaw.parser import RawRecord, parse_file
from tests.conftest import fixture


def _record(**fields) -> RawRecord:
    base = {
        "date": "2026-07-03", "time": "10:22:01", "c-ip": "185.10.20.30",
        "cs-method": "GET", "cs-uri-stem": "/upload/test.aspx",
        "cs-uri-query": "cmd=whoami", "sc-status": "200",
    }
    base.update(fields)
    return RawRecord(fields=base, raw_line="raw", log_file="x.log", line_number=7)


def test_field_mapping_and_types():
    row = normalize(_record())
    assert row["src_ip"] == "185.10.20.30"
    assert row["method"] == "GET"
    assert row["uri_path"] == "/upload/test.aspx"
    assert row["uri_query"] == "cmd=whoami"
    assert row["status"] == 200
    assert isinstance(row["status"], int)


def test_timestamp_iso_utc():
    row = normalize(_record())
    assert row["timestamp"] == "2026-07-03T10:22:01Z"


def test_dash_becomes_none_and_missing_fields_none():
    row = normalize(_record(**{"cs-uri-query": "-"}))
    assert row["uri_query"] is None
    assert row["user_agent"] is None
    assert row["host"] is None


def test_url_decoding_single_and_double():
    row = normalize(_record(**{"cs-uri-query": "q=%27%20or%201%3D1"}))
    assert row["uri_query_decoded"] == "q=' or 1=1"
    # doubly encoded ../
    row = normalize(_record(**{"cs-uri-query": "file=%252e%252e%252fweb.config"}))
    assert "../web.config" in row["uri_query_decoded"]
    # original value preserved
    assert row["uri_query"] == "file=%252e%252e%252fweb.config"


def test_derived_helpers():
    row = normalize(_record())
    assert row["url_original"] == "/upload/test.aspx?cmd=whoami"
    assert row["url_decoded"] == "/upload/test.aspx?cmd=whoami"
    assert row["extension"] == ".aspx"
    assert row["is_success_status"] is True
    assert row["is_error_status"] is False


def test_error_status_flags():
    row = normalize(_record(**{"sc-status": "404"}))
    assert row["is_success_status"] is False
    assert row["is_error_status"] is True


def test_unknown_fields_kept():
    row = normalize(_record(**{"s-port": "443"}))
    assert row["s-port"] == "443"


def test_provenance_carried_over():
    row = normalize(_record())
    assert row["log_file"] == "x.log"
    assert row["line_number"] == 7
    assert row["raw_line"] == "raw"


def test_end_to_end_fixture():
    records = [normalize(r) for r in parse_file(fixture("basic.log"))]
    assert records[2]["username"] == "jdoe"
    assert records[2]["status"] == 302
    assert records[3]["is_error_status"] is True
