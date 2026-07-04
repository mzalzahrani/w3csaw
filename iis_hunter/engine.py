"""Detection engine: per-record rule matching plus stateful thresholds.

The engine is fed one record at a time (streaming-friendly) and yields
detection dicts. Threshold detections (404/500 volume, request rate,
brute force) keep bounded per-IP sliding windows.
"""

from __future__ import annotations

from collections import defaultdict, deque
from typing import Any, Dict, Iterator, List, Optional

from .parser import parse_record_time
from .rules import Rule, active_rules

MISSING_UA_RULE = ("missing_user_agent", "low",
                   "Request without a User-Agent header")


def make_detection(record: Dict[str, Any], name: str, severity: str,
                   description: str, field: str, value: Any) -> Dict[str, Any]:
    return {
        "detection": name,
        "severity": severity,
        "description": description,
        "timestamp": record.get("timestamp"),
        "c_ip": record.get("c_ip"),
        "method": record.get("method"),
        "uri": record.get("url") or record.get("uri_stem"),
        "status": record.get("status"),
        "field": field,
        "value": None if value is None else str(value)[:500],
        "line": record.get("line"),
    }


class _Window:
    """Per-key sliding-window counter that fires once per window."""

    PRUNE_EVERY = 100000

    def __init__(self, threshold: int, window_seconds: int):
        self.threshold = threshold
        self.window = window_seconds
        self.events: Dict[str, deque] = defaultdict(deque)
        self.fired_at: Dict[str, float] = {}
        self._hits = 0

    def hit(self, key: Optional[str], ts) -> Optional[int]:
        """Record an event; return the count when the threshold is crossed."""
        if not key or ts is None:
            return None
        epoch = ts.timestamp()
        self._hits += 1
        if self._hits % self.PRUNE_EVERY == 0:
            stale = epoch - self.window
            for k in [k for k, ev in self.events.items()
                      if not ev or ev[-1] < stale]:
                del self.events[k]
                self.fired_at.pop(k, None)
        events = self.events[key]
        events.append(epoch)
        cutoff = epoch - self.window
        while events and events[0] < cutoff:
            events.popleft()
        if len(events) >= self.threshold:
            last = self.fired_at.get(key)
            if last is None or epoch - last >= self.window:
                self.fired_at[key] = epoch
                count = len(events)
                events.clear()
                return count
        return None


class Engine:
    def __init__(self, rules: Optional[List[Rule]] = None,
                 threshold_404: int = 50, threshold_500: int = 25,
                 threshold_rate: int = 300, threshold_auth: int = 15,
                 window_seconds: int = 60):
        self.rules = rules if rules is not None else active_rules()
        self.win_404 = _Window(threshold_404, window_seconds * 5)
        self.win_500 = _Window(threshold_500, window_seconds * 5)
        self.win_rate = _Window(threshold_rate, window_seconds)
        self.win_auth = _Window(threshold_auth, window_seconds * 5)

    def scan(self, record: Dict[str, Any]) -> Iterator[Dict[str, Any]]:
        for rule in self.rules:
            value = rule.match(record)
            if value is not None:
                yield make_detection(record, rule.name, rule.severity,
                                     rule.description, rule.field, value)

        if record.get("user_agent") is None and record.get("method"):
            name, severity, description = MISSING_UA_RULE
            yield make_detection(record, name, severity, description,
                                 "user_agent", None)

        yield from self._thresholds(record)

    def _thresholds(self, record: Dict[str, Any]) -> Iterator[Dict[str, Any]]:
        ip = record.get("c_ip")
        ts = parse_record_time(record.get("timestamp"))
        status = record.get("status")

        count = self.win_rate.hit(ip, ts)
        if count:
            yield make_detection(
                record, "high_request_rate", "medium",
                f"{count} requests from one IP within "
                f"{self.win_rate.window}s", "c_ip", ip)
        if status == 404:
            count = self.win_404.hit(ip, ts)
            if count:
                yield make_detection(
                    record, "excessive_404", "medium",
                    f"{count} HTTP 404 responses to one IP within "
                    f"{self.win_404.window}s (forced browsing/scanning)",
                    "status", status)
        if status is not None and status >= 500:
            count = self.win_500.hit(ip, ts)
            if count:
                yield make_detection(
                    record, "excessive_500", "high",
                    f"{count} HTTP 5xx responses to one IP within "
                    f"{self.win_500.window}s (exploitation attempts)",
                    "status", status)
        if status in (401, 403):
            count = self.win_auth.hit(ip, ts)
            if count:
                yield make_detection(
                    record, "brute_force", "high",
                    f"{count} HTTP 401/403 responses to one IP within "
                    f"{self.win_auth.window}s (password guessing)",
                    "status", status)


class Stats:
    """Running aggregate statistics over the scanned records."""

    TOP_N = 10

    def __init__(self):
        self.total = 0
        self.suspicious = 0
        self.ips = defaultdict(int)
        self.status = defaultdict(int)
        self.methods = defaultdict(int)
        self.uris = defaultdict(int)
        self.agents = defaultdict(int)
        self.by_severity = defaultdict(int)
        self.by_detection = defaultdict(int)

    def add_record(self, record: Dict[str, Any]) -> None:
        self.total += 1
        for counter, key in ((self.ips, "c_ip"), (self.status, "status"),
                             (self.methods, "method"), (self.uris, "uri_stem"),
                             (self.agents, "user_agent")):
            value = record.get(key)
            if value is not None:
                counter[value] += 1

    def add_detections(self, detections: List[Dict[str, Any]]) -> None:
        if detections:
            self.suspicious += 1
        for det in detections:
            self.by_severity[det["severity"]] += 1
            self.by_detection[det["detection"]] += 1

    @staticmethod
    def _top(counter: Dict, n: int) -> List[Dict[str, Any]]:
        items = sorted(counter.items(), key=lambda kv: kv[1], reverse=True)
        return [{"value": str(k), "count": v} for k, v in items[:n]]

    def summary(self, top_n: Optional[int] = None) -> Dict[str, Any]:
        n = top_n or self.TOP_N
        return {
            "total_requests": self.total,
            "suspicious_requests": self.suspicious,
            "unique_source_ips": len(self.ips),
            "top_status_codes": self._top(self.status, n),
            "top_methods": self._top(self.methods, n),
            "top_uris": self._top(self.uris, n),
            "top_user_agents": self._top(self.agents, n),
            "top_source_ips": self._top(self.ips, n),
            "detections_by_severity": dict(self.by_severity),
            "detections_by_type": dict(
                sorted(self.by_detection.items(),
                       key=lambda kv: kv[1], reverse=True)),
        }
