"""Per-line detection engine: evaluates rules against normalized records."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Tuple

from .rules import CONDITION_RE, Rule


@dataclass
class Finding:
    """A single rule match against one log record (or aggregation group)."""

    rule_id: str
    rule_title: str
    level: str
    status: str
    description: str
    timestamp: Optional[str]
    src_ip: Optional[str]
    method: Optional[str]
    uri_path: Optional[str]
    uri_query: Optional[str]
    status_code: Optional[int]
    user_agent: Optional[str]
    referer: Optional[str]
    host: Optional[str]
    matched_fields: List[str] = field(default_factory=list)
    matched_values: List[Any] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    falsepositives: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)
    log_file: str = ""
    line_number: int = 0
    raw_line: str = ""

    def to_dict(self, include_raw: bool = True) -> Dict[str, Any]:
        data = {
            "rule_id": self.rule_id,
            "rule_title": self.rule_title,
            "level": self.level,
            "status": self.status,
            "description": self.description,
            "timestamp": self.timestamp,
            "src_ip": self.src_ip,
            "method": self.method,
            "uri_path": self.uri_path,
            "uri_query": self.uri_query,
            "status_code": self.status_code,
            "user_agent": self.user_agent,
            "referer": self.referer,
            "host": self.host,
            "matched_fields": self.matched_fields,
            "matched_values": self.matched_values,
            "tags": self.tags,
            "falsepositives": self.falsepositives,
            "references": self.references,
            "log_file": self.log_file,
            "line_number": self.line_number,
        }
        if include_raw:
            data["raw_line"] = self.raw_line
        return data


class MatchContext:
    """Collects which fields/values matched while evaluating a rule."""

    def __init__(self) -> None:
        self.fields: List[str] = []
        self.values: List[Any] = []

    def add(self, field_name: str, value: Any) -> None:
        if field_name not in self.fields:
            self.fields.append(field_name)
            self.values.append(value)


def evaluate_field(record: Dict[str, Any], key: str, expected: Any,
                   ctx: Optional[MatchContext] = None) -> bool:
    """Evaluate one `field` / `field|operator` spec against a record."""
    if "|" in key:
        field_name, op = key.split("|", 1)
    else:
        field_name, op = key, None

    value = record.get(field_name)

    if op == "exists":
        return value is not None
    if op == "not_exists":
        return value is None

    if op is None and isinstance(expected, dict):
        return _numeric_match(value, expected, field_name, ctx)

    if value is None:
        return False

    matched = _string_match(value, op, expected)
    if matched and ctx is not None:
        ctx.add(field_name, value)
    return matched


def _numeric_match(value: Any, comparisons: Dict[str, Any], field_name: str,
                   ctx: Optional[MatchContext]) -> bool:
    if value is None:
        return False
    try:
        number = float(value)
    except (TypeError, ValueError):
        return False
    for op, bound in comparisons.items():
        if op == "gte" and not number >= bound:
            return False
        if op == "gt" and not number > bound:
            return False
        if op == "lte" and not number <= bound:
            return False
        if op == "lt" and not number < bound:
            return False
    if ctx is not None:
        ctx.add(field_name, value)
    return True


def _string_match(value: Any, op: Optional[str], expected: Any) -> bool:
    """String operators are case-insensitive: attacker input varies in case."""
    text = str(value).lower()

    if op is None:
        if isinstance(expected, list):
            return any(text == str(item).lower() for item in expected)
        return text == str(expected).lower()
    if op == "contains":
        return str(expected).lower() in text
    if op == "contains_any":
        return any(str(item).lower() in text for item in expected)
    if op == "startswith":
        return text.startswith(str(expected).lower())
    if op == "startswith_any":
        return any(text.startswith(str(item).lower()) for item in expected)
    if op == "endswith":
        return text.endswith(str(expected).lower())
    if op == "endswith_any":
        return any(text.endswith(str(item).lower()) for item in expected)
    if op == "re":
        patterns = expected if isinstance(expected, list) else [expected]
        return any(re.search(str(p), str(value), re.IGNORECASE) for p in patterns)
    if op == "in":
        return text in {str(item).lower() for item in expected}
    return False


def evaluate_selection(record: Dict[str, Any], selection: Dict[str, Any],
                       ctx: Optional[MatchContext] = None) -> bool:
    """All field specs inside one selection must match (AND semantics)."""
    return all(evaluate_field(record, key, expected, ctx)
               for key, expected in selection.items())


def evaluate_rule(rule: Rule, record: Dict[str, Any]) -> Optional[MatchContext]:
    """Evaluate a per-line rule; return match context on hit, else None."""
    selections = {k: v for k, v in rule.detection.items() if k != "condition"}
    match = CONDITION_RE.match(rule.condition)
    if not match:  # validated at load time; defensive fallback
        return None
    left, joiner, negate, right = match.groups()

    ctx = MatchContext()
    left_hit = evaluate_selection(record, selections[left], ctx)

    if not joiner:
        return ctx if left_hit else None

    if joiner.lower() == "and":
        if not left_hit:
            return None
        right_hit = evaluate_selection(record, selections[right],
                                       None if negate else ctx)
        if negate:
            return None if right_hit else ctx
        return ctx if right_hit else None

    # or
    if left_hit:
        return ctx
    ctx = MatchContext()
    return ctx if evaluate_selection(record, selections[right], ctx) else None


def build_finding(rule: Rule, record: Dict[str, Any],
                  ctx: Optional[MatchContext] = None) -> Finding:
    """Assemble a Finding from a rule and the record that triggered it."""
    return Finding(
        rule_id=rule.id,
        rule_title=rule.title,
        level=rule.level,
        status=rule.status,
        description=rule.description,
        timestamp=record.get("timestamp"),
        src_ip=record.get("src_ip"),
        method=record.get("method"),
        uri_path=record.get("uri_path"),
        uri_query=record.get("uri_query"),
        status_code=record.get("status"),
        user_agent=record.get("user_agent"),
        referer=record.get("referer"),
        host=record.get("host"),
        matched_fields=list(ctx.fields) if ctx else [],
        matched_values=list(ctx.values) if ctx else [],
        tags=list(rule.tags),
        falsepositives=list(rule.falsepositives),
        references=list(rule.references),
        log_file=record.get("log_file", ""),
        line_number=record.get("line_number", 0),
        raw_line=record.get("raw_line", ""),
    )


def scan_record(rules: Iterable[Rule], record: Dict[str, Any]) -> List[Finding]:
    """Run every per-line rule against one normalized record."""
    findings: List[Finding] = []
    for rule in rules:
        if rule.is_aggregation:
            continue
        ctx = evaluate_rule(rule, record)
        if ctx is not None:
            findings.append(build_finding(rule, record, ctx))
    return findings
