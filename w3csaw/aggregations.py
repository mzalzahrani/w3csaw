"""Aggregation engine: threshold, sequence, and rarity rules over grouped records.

Runs alongside the per-line pass so logs are still streamed once. Each
aggregation rule keeps bounded per-group state:

* threshold rules (count_gte): sliding time-window counters, e.g. many 404s
  from one source IP.
* sequence rules (count_gte + followed_by): precondition events counted in
  the window, finding emitted when the follow-up event arrives, e.g. 401/403
  brute force followed by a 200.
* rarity rules (count_lte): totals evaluated once at end of scan, e.g. a
  dynamic extension that succeeded only a handful of times.
"""

from __future__ import annotations

from collections import deque
from datetime import datetime, timedelta, timezone
from typing import Any, Deque, Dict, Iterable, List, Optional, Tuple

from .engine import Finding, MatchContext, build_finding, evaluate_selection
from .rules import Rule
from .utils import parse_datetime

# Safety cap so a hostile/huge log cannot grow one group's deque unbounded.
MAX_EVENTS_PER_GROUP = 100_000
# Cap on distinct groups tracked per rule; oldest-seen groups are dropped.
MAX_GROUPS_PER_RULE = 500_000


class AggregationTracker:
    """Tracks state for one aggregation rule across the record stream."""

    def __init__(self, rule: Rule) -> None:
        self.rule = rule
        agg = rule.aggregation
        self.group_by: List[str] = [str(f) for f in agg["group_by"]]
        self.filter: Dict[str, Any] = agg.get("filter") or {}
        self.followed_by: Optional[Dict[str, Any]] = agg.get("followed_by")
        self.count_gte: Optional[int] = agg.get("count_gte")
        self.count_lte: Optional[int] = agg.get("count_lte")
        self.window = timedelta(minutes=float(agg["window_minutes"]))

        # threshold/sequence state: group key -> event timestamps in window
        self.events: Dict[Tuple[Any, ...], Deque[datetime]] = {}
        self.last_fired: Dict[Tuple[Any, ...], datetime] = {}
        # rarity state: group key -> (total count, sample record)
        self.totals: Dict[Tuple[Any, ...], int] = {}
        self.samples: Dict[Tuple[Any, ...], Dict[str, Any]] = {}

    def process(self, record: Dict[str, Any]) -> Optional[Finding]:
        """Feed one record; may return a finding (threshold/sequence rules)."""
        ts = parse_datetime(record.get("date"), record.get("time"))
        if ts is None:
            return None
        key = tuple(record.get(f) for f in self.group_by)
        if None in key:
            return None

        if self.count_lte is not None:
            self._track_rarity(key, record)
            return None

        if self.followed_by is not None:
            return self._track_sequence(key, ts, record)
        return self._track_threshold(key, ts, record)

    def _matches_filter(self, record: Dict[str, Any],
                        ctx: Optional[MatchContext] = None) -> bool:
        return not self.filter or evaluate_selection(record, self.filter, ctx)

    def _track_threshold(self, key: Tuple[Any, ...], ts: datetime,
                         record: Dict[str, Any]) -> Optional[Finding]:
        if not self._matches_filter(record):
            return None
        bucket = self._bucket(key)
        bucket.append(ts)
        self._prune(bucket, ts)
        if len(bucket) < int(self.count_gte or 0):
            return None
        if not self._may_fire(key, ts):
            return None
        self.last_fired[key] = ts
        return self._finding(record, count=len(bucket))

    def _track_sequence(self, key: Tuple[Any, ...], ts: datetime,
                        record: Dict[str, Any]) -> Optional[Finding]:
        # The follow-up event (e.g. status 200) triggers; precondition
        # events (e.g. 401/403) only accumulate.
        if evaluate_selection(record, self.followed_by or {}):
            bucket = self.events.get(key)
            if bucket is None:
                return None
            self._prune(bucket, ts)
            if len(bucket) < int(self.count_gte or 0):
                return None
            if not self._may_fire(key, ts):
                return None
            self.last_fired[key] = ts
            return self._finding(record, count=len(bucket))
        if self._matches_filter(record):
            bucket = self._bucket(key)
            bucket.append(ts)
            self._prune(bucket, ts)
        return None

    def _track_rarity(self, key: Tuple[Any, ...], record: Dict[str, Any]) -> None:
        if not self._matches_filter(record):
            return
        if key not in self.totals and len(self.totals) >= MAX_GROUPS_PER_RULE:
            return
        self.totals[key] = self.totals.get(key, 0) + 1
        self.samples.setdefault(key, record)

    def finalize(self) -> List[Finding]:
        """Emit rarity findings once the whole stream has been processed."""
        if self.count_lte is None:
            return []
        findings: List[Finding] = []
        for key, count in sorted(self.totals.items(), key=lambda kv: str(kv[0])):
            if count <= int(self.count_lte):
                findings.append(self._finding(self.samples[key], count=count))
        return findings

    def _bucket(self, key: Tuple[Any, ...]) -> Deque[datetime]:
        bucket = self.events.get(key)
        if bucket is None:
            if len(self.events) >= MAX_GROUPS_PER_RULE:
                oldest = next(iter(self.events))
                del self.events[oldest]
            bucket = deque(maxlen=MAX_EVENTS_PER_GROUP)
            self.events[key] = bucket
        return bucket

    def _prune(self, bucket: Deque[datetime], now: datetime) -> None:
        cutoff = now - self.window
        while bucket and bucket[0] < cutoff:
            bucket.popleft()

    def _may_fire(self, key: Tuple[Any, ...], ts: datetime) -> bool:
        """Fire at most once per group per window to avoid finding floods."""
        fired = self.last_fired.get(key)
        return fired is None or ts - fired >= self.window

    def _finding(self, record: Dict[str, Any], count: int) -> Finding:
        ctx = MatchContext()
        for field_name in self.group_by:
            ctx.add(field_name, record.get(field_name))
        ctx.add("event_count", count)
        return build_finding(self.rule, record, ctx)


class AggregationEngine:
    """Runs all aggregation rules over the record stream."""

    def __init__(self, rules: Iterable[Rule]) -> None:
        self.trackers = [AggregationTracker(r) for r in rules if r.is_aggregation]

    def process(self, record: Dict[str, Any]) -> List[Finding]:
        findings: List[Finding] = []
        for tracker in self.trackers:
            finding = tracker.process(record)
            if finding is not None:
                findings.append(finding)
        return findings

    def finalize(self) -> List[Finding]:
        findings: List[Finding] = []
        for tracker in self.trackers:
            findings.extend(tracker.finalize())
        return findings
