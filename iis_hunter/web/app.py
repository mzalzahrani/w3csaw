"""FastAPI backend for the IIS Hunter web interface.

Uploads stream to disk, then a background thread parses + scans into a
per-job SQLite database while the browser polls progress. All filtering
and pagination happen server-side against SQLite.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import threading
import time
import uuid
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.responses import FileResponse, JSONResponse

from .. import __version__
from ..engine import Engine, Stats
from ..parser import ParseError, detect_format, parse
from ..rules import (BUILTIN_RULES, CONFIG_DIR, custom_rule_from_dict,
                     active_rules, load_config, save_config)
from ..store import Store

DATA_DIR = os.path.join(CONFIG_DIR, "jobs")
BATCH = 2000

app = FastAPI(title="IIS Hunter", version=__version__)

_jobs: Dict[str, Dict[str, Any]] = {}
_jobs_lock = threading.Lock()


def _job_dir(job_id: str) -> str:
    if not re.fullmatch(r"[0-9a-f]{32}", job_id):
        raise HTTPException(status_code=400, detail="Invalid job id")
    return os.path.join(DATA_DIR, job_id)


def _job_store(job_id: str) -> Store:
    db = os.path.join(_job_dir(job_id), "job.db")
    if not os.path.isfile(db):
        raise HTTPException(status_code=404, detail="Job not found")
    return Store(db)


def _run_job(job_id: str, path: str, filename: str) -> None:
    progress = _jobs[job_id]
    store = Store(os.path.join(_job_dir(job_id), "job.db"))
    engine = Engine(active_rules())
    stats = Stats()
    started = time.time()
    total_bytes = os.path.getsize(path)
    records: List[Dict[str, Any]] = []
    detections: List[Dict[str, Any]] = []
    bytes_seen = 0
    try:
        fmt = detect_format(path)
        progress.update(state="running", format=fmt)
        for record in parse(path, fmt=fmt):
            bytes_seen += len(record["raw"]) + 1
            stats.add_record(record)
            found = list(engine.scan(record))
            stats.add_detections(found)
            records.append(record)
            detections.extend(found)
            if len(records) >= BATCH:
                store.insert_records(records)
                store.insert_detections(detections)
                store.commit()
                records, detections = [], []
                elapsed = max(time.time() - started, 0.001)
                speed = bytes_seen / elapsed
                progress.update(
                    lines=stats.total,
                    detections=sum(stats.by_severity.values()),
                    bytes_read=bytes_seen, total_bytes=total_bytes,
                    percent=round(min(bytes_seen / total_bytes, 1.0) * 100, 1),
                    lines_per_sec=int(stats.total / elapsed),
                    mb_per_sec=round(speed / 1048576, 2),
                    eta_seconds=int(max(total_bytes - bytes_seen, 0) / speed))
        store.insert_records(records)
        store.insert_detections(detections)
        store.commit()
        store.create_indexes()
        summary = stats.summary()
        store.set_meta("stats", summary)
        store.set_meta("info", {
            "filename": filename, "format": fmt,
            "uploaded": progress["uploaded"],
            "duration_seconds": round(time.time() - started, 1)})
        progress.update(
            state="done", lines=stats.total,
            detections=sum(stats.by_severity.values()),
            bytes_read=total_bytes, total_bytes=total_bytes, percent=100.0,
            eta_seconds=0,
            lines_per_sec=int(stats.total / max(time.time() - started, 0.001)))
    except (ParseError, OSError) as exc:
        progress.update(state="error", error=str(exc))
    finally:
        store.close()


@app.post("/api/upload")
async def upload(file: UploadFile = File(...)) -> Dict[str, str]:
    job_id = uuid.uuid4().hex
    job_dir = os.path.join(DATA_DIR, job_id)
    os.makedirs(job_dir, exist_ok=True)
    path = os.path.join(job_dir, "input.log")
    with open(path, "wb") as handle:
        while True:
            chunk = await file.read(1048576)
            if not chunk:
                break
            handle.write(chunk)
    with _jobs_lock:
        _jobs[job_id] = {
            "job_id": job_id, "filename": file.filename, "state": "queued",
            "uploaded": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "lines": 0, "detections": 0, "bytes_read": 0,
            "total_bytes": os.path.getsize(path), "percent": 0.0,
            "lines_per_sec": 0, "mb_per_sec": 0.0, "eta_seconds": None,
            "format": None, "error": None,
        }
    thread = threading.Thread(target=_run_job,
                              args=(job_id, path, file.filename), daemon=True)
    thread.start()
    return {"job_id": job_id}


@app.get("/api/jobs")
def list_jobs() -> List[Dict[str, Any]]:
    with _jobs_lock:
        live = {job_id: dict(job) for job_id, job in _jobs.items()}
    if os.path.isdir(DATA_DIR):
        for job_id in os.listdir(DATA_DIR):
            db = os.path.join(DATA_DIR, job_id, "job.db")
            if job_id in live or not os.path.isfile(db):
                continue
            store = Store(db)
            info = store.get_meta("info") or {}
            summary = store.get_meta("stats") or {}
            store.close()
            live[job_id] = {
                "job_id": job_id, "state": "done",
                "filename": info.get("filename"),
                "uploaded": info.get("uploaded"), "percent": 100.0,
                "lines": summary.get("total_requests", 0),
                "detections": sum(
                    summary.get("detections_by_severity", {}).values()),
            }
    return sorted(live.values(),
                  key=lambda j: j.get("uploaded") or "", reverse=True)


@app.get("/api/jobs/{job_id}")
def job_status(job_id: str) -> Dict[str, Any]:
    _job_dir(job_id)
    with _jobs_lock:
        if job_id in _jobs:
            return dict(_jobs[job_id])
    for job in list_jobs():
        if job["job_id"] == job_id:
            return job
    raise HTTPException(status_code=404, detail="Job not found")


@app.delete("/api/jobs/{job_id}")
def delete_job(job_id: str) -> Dict[str, str]:
    job_dir = _job_dir(job_id)
    with _jobs_lock:
        job = _jobs.get(job_id)
        if job and job.get("state") in ("queued", "running"):
            raise HTTPException(status_code=409,
                                detail="Job is still running")
        _jobs.pop(job_id, None)
    if os.path.isdir(job_dir):
        shutil.rmtree(job_dir)
    return {"status": "deleted"}


@app.get("/api/jobs/{job_id}/stats")
def job_stats(job_id: str) -> Dict[str, Any]:
    store = _job_store(job_id)
    try:
        summary = store.get_meta("stats")
        if summary is None:
            raise HTTPException(status_code=409,
                                detail="Job still processing")
        return summary
    finally:
        store.close()


def _parse_filters(filters: Optional[str]) -> List[Dict[str, Any]]:
    if not filters:
        return []
    try:
        parsed = json.loads(filters)
    except json.JSONDecodeError:
        raise HTTPException(status_code=400, detail="filters must be JSON")
    if not isinstance(parsed, list):
        raise HTTPException(status_code=400,
                            detail="filters must be a JSON array")
    return parsed


@app.get("/api/jobs/{job_id}/logs")
def job_logs(job_id: str, page: int = 1, size: int = 50,
             filters: Optional[str] = None) -> Dict[str, Any]:
    store = _job_store(job_id)
    try:
        return store.query_logs(_parse_filters(filters), page, size)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    finally:
        store.close()


@app.get("/api/jobs/{job_id}/detections")
def job_detections(job_id: str, page: int = 1, size: int = 50,
                   filters: Optional[str] = None) -> Dict[str, Any]:
    store = _job_store(job_id)
    try:
        return store.query_detections(_parse_filters(filters), page, size)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    finally:
        store.close()


# ----------------------------------------------------------------------
# rules management

@app.get("/api/rules")
def get_rules() -> Dict[str, Any]:
    config = load_config()
    disabled = set(config["disabled_builtins"])
    builtins = []
    for rule in BUILTIN_RULES:
        data = rule.to_dict()
        data["enabled"] = rule.name not in disabled
        builtins.append(data)
    return {"builtin": builtins, "custom": config["custom_rules"]}


@app.post("/api/rules")
def create_rule(rule: Dict[str, Any]) -> Dict[str, Any]:
    try:
        validated = custom_rule_from_dict(rule)
    except (ValueError, re.error) as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    config = load_config()
    names = {r["name"] for r in config["custom_rules"]}
    names.update(r.name for r in BUILTIN_RULES)
    if validated.name in names:
        raise HTTPException(status_code=409,
                            detail=f"Rule {validated.name!r} already exists")
    data = validated.to_dict()
    data.pop("builtin", None)
    config["custom_rules"].append(data)
    save_config(config)
    return data


@app.put("/api/rules/{name}")
def update_rule(name: str, patch: Dict[str, Any]) -> Dict[str, Any]:
    config = load_config()
    if any(rule.name == name for rule in BUILTIN_RULES):
        if set(patch) - {"enabled"}:
            raise HTTPException(status_code=400,
                                detail="Built-in rules only support "
                                       "enabling/disabling")
        disabled = set(config["disabled_builtins"])
        if patch.get("enabled", True):
            disabled.discard(name)
        else:
            disabled.add(name)
        config["disabled_builtins"] = sorted(disabled)
        save_config(config)
        return {"name": name, "enabled": patch.get("enabled", True)}
    for existing in config["custom_rules"]:
        if existing["name"] == name:
            merged = {**existing, **patch, "name": name}
            try:
                custom_rule_from_dict(merged)
            except (ValueError, re.error) as exc:
                raise HTTPException(status_code=400, detail=str(exc))
            existing.update(merged)
            save_config(config)
            return existing
    raise HTTPException(status_code=404, detail="Rule not found")


@app.delete("/api/rules/{name}")
def delete_rule(name: str) -> Dict[str, str]:
    config = load_config()
    before = len(config["custom_rules"])
    config["custom_rules"] = [rule for rule in config["custom_rules"]
                              if rule["name"] != name]
    if len(config["custom_rules"]) == before:
        raise HTTPException(status_code=404,
                            detail="Custom rule not found (built-in rules "
                                   "can only be disabled)")
    save_config(config)
    return {"status": "deleted"}


@app.get("/")
def index() -> FileResponse:
    return FileResponse(
        os.path.join(os.path.dirname(__file__), "static", "index.html"))


@app.exception_handler(Exception)
async def unhandled(request, exc):  # pragma: no cover - safety net
    return JSONResponse(status_code=500, content={"detail": str(exc)})


def serve(host: str = "127.0.0.1", port: int = 8787) -> None:
    os.makedirs(DATA_DIR, exist_ok=True)
    import uvicorn
    print(f"[*] IIS Hunter web interface: http://{host}:{port}")
    uvicorn.run(app, host=host, port=port, log_level="warning")
