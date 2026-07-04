"""Web API tests against a temporary config/data directory."""

import importlib
import time

import pytest


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("IIS_HUNTER_HOME", str(tmp_path))
    import iis_hunter.rules as rules
    import iis_hunter.web.app as webapp
    importlib.reload(rules)
    importlib.reload(webapp)
    from fastapi.testclient import TestClient
    return TestClient(webapp.app, raise_server_exceptions=True)


W3C = """#Fields: date time c-ip cs-method cs-uri-stem cs-uri-query sc-status cs(User-Agent)
2026-07-01 10:00:00 203.0.113.5 GET /index.html - 200 Mozilla/5.0
2026-07-01 10:00:01 203.0.113.9 GET /shell.aspx cmd=whoami 200 sqlmap/1.7
"""


def _upload_and_wait(client):
    res = client.post("/api/upload",
                      files={"file": ("test.log", W3C.encode(), "text/plain")})
    assert res.status_code == 200
    job_id = res.json()["job_id"]
    for _ in range(100):
        status = client.get(f"/api/jobs/{job_id}").json()
        if status["state"] in ("done", "error"):
            break
        time.sleep(0.05)
    assert status["state"] == "done", status
    return job_id


def test_upload_stats_and_queries(client):
    job_id = _upload_and_wait(client)

    stats = client.get(f"/api/jobs/{job_id}/stats").json()
    assert stats["total_requests"] == 2
    assert stats["suspicious_requests"] == 1
    assert stats["detections_by_severity"].get("critical", 0) >= 1

    logs = client.get(f"/api/jobs/{job_id}/logs",
                      params={"filters": '[{"field":"c_ip","mode":"exact",'
                                         '"value":"203.0.113.9"}]'}).json()
    assert logs["total"] == 1
    assert logs["rows"][0]["uri_stem"] == "/shell.aspx"

    dets = client.get(f"/api/jobs/{job_id}/detections",
                      params={"filters": '[{"field":"severity","mode":"exact",'
                                         '"value":"critical"}]'}).json()
    assert dets["total"] >= 1

    bad = client.get(f"/api/jobs/{job_id}/logs",
                     params={"filters": '[{"field":"evil","mode":"exact",'
                                        '"value":"x"}]'})
    assert bad.status_code == 400


def test_rules_crud(client):
    listing = client.get("/api/rules").json()
    assert len(listing["builtin"]) > 25

    created = client.post("/api/rules", json={
        "name": "my_ioc", "severity": "high", "field": "url",
        "match_type": "literal", "pattern": "evil.example",
        "description": "test IOC"})
    assert created.status_code == 200
    assert client.post("/api/rules", json={
        "name": "my_ioc", "severity": "high", "pattern": "x"}).status_code == 409
    assert client.post("/api/rules", json={
        "name": "bad", "severity": "high", "match_type": "regex",
        "pattern": "("}).status_code == 400

    toggled = client.put("/api/rules/sql_injection", json={"enabled": False})
    assert toggled.status_code == 200
    listing = client.get("/api/rules").json()
    sqli = next(r for r in listing["builtin"] if r["name"] == "sql_injection")
    assert sqli["enabled"] is False
    client.put("/api/rules/sql_injection", json={"enabled": True})

    assert client.delete("/api/rules/my_ioc").status_code == 200
    assert client.delete("/api/rules/my_ioc").status_code == 404
    assert client.delete("/api/rules/sql_injection").status_code == 404


def test_job_delete(client):
    job_id = _upload_and_wait(client)
    assert client.delete(f"/api/jobs/{job_id}").status_code == 200
    assert client.get(f"/api/jobs/{job_id}/stats").status_code == 404
    assert client.get("/api/jobs/deadbeef/logs").status_code == 400
