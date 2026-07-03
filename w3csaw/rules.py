"""Load and validate native W3CSaw YAML detection rules."""

from __future__ import annotations

import glob
import logging
import os
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

import yaml

from .utils import LEVELS

logger = logging.getLogger("w3csaw")

STRING_OPERATORS = frozenset({
    "contains", "contains_any", "startswith", "startswith_any",
    "endswith", "endswith_any", "re", "in", "exists", "not_exists",
})
NUMERIC_OPERATORS = frozenset({"gte", "gt", "lte", "lt"})

CONDITION_RE = re.compile(
    r"^\s*(\w+)\s*(?:(and|or)\s+(not\s+)?(\w+)\s*)?$", re.IGNORECASE
)


class RuleError(Exception):
    """Raised when a rule file is structurally invalid."""


@dataclass
class Rule:
    """A parsed detection rule (per-line or aggregation)."""

    id: str
    title: str
    level: str
    status: str = "experimental"
    description: str = ""
    type: str = "detection"
    tags: List[str] = field(default_factory=list)
    logsource: Dict[str, Any] = field(default_factory=dict)
    detection: Dict[str, Any] = field(default_factory=dict)
    aggregation: Dict[str, Any] = field(default_factory=dict)
    fields: List[str] = field(default_factory=list)
    falsepositives: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)
    source_path: str = ""

    @property
    def is_aggregation(self) -> bool:
        return self.type == "aggregation"

    @property
    def condition(self) -> str:
        return str(self.detection.get("condition", "selection"))


def load_rules(rules_path: str) -> Tuple[List[Rule], List[str]]:
    """Load every YAML rule under a directory (or a single file).

    Returns (valid_rules, error_messages). Invalid rules are reported,
    not fatal, so one broken rule cannot block a hunt.
    """
    paths = _rule_files(rules_path)
    rules: List[Rule] = []
    errors: List[str] = []
    seen_ids: Dict[str, str] = {}

    for path in paths:
        try:
            with open(path, "r", encoding="utf-8") as handle:
                docs = list(yaml.safe_load_all(handle))
        except (OSError, yaml.YAMLError) as exc:
            errors.append(f"{path}: cannot parse YAML: {exc}")
            continue
        for doc in docs:
            if doc is None:
                continue
            try:
                rule = _build_rule(doc, path)
                validate_rule(rule)
            except RuleError as exc:
                errors.append(f"{path}: {exc}")
                continue
            if rule.id in seen_ids:
                errors.append(
                    f"{path}: duplicate rule id {rule.id!r} "
                    f"(first defined in {seen_ids[rule.id]})"
                )
                continue
            seen_ids[rule.id] = path
            rules.append(rule)
    return rules, errors


def _rule_files(rules_path: str) -> List[str]:
    if os.path.isfile(rules_path):
        return [rules_path]
    if os.path.isdir(rules_path):
        found: List[str] = []
        for pattern in ("**/*.yml", "**/*.yaml"):
            found.extend(glob.glob(os.path.join(rules_path, pattern), recursive=True))
        return sorted(set(found))
    raise FileNotFoundError(f"Rules path not found: {rules_path!r}")


def _build_rule(doc: Any, path: str) -> Rule:
    if not isinstance(doc, dict):
        raise RuleError("rule document must be a YAML mapping")
    try:
        rule = Rule(
            id=str(doc.get("id", "")),
            title=str(doc.get("title", "")),
            level=str(doc.get("level", "")),
            status=str(doc.get("status", "experimental")),
            description=str(doc.get("description", "")),
            type=str(doc.get("type", "detection")),
            tags=_str_list(doc.get("tags")),
            logsource=doc.get("logsource") or {},
            detection=doc.get("detection") or {},
            aggregation=doc.get("aggregation") or {},
            fields=_str_list(doc.get("fields")),
            falsepositives=_str_list(doc.get("falsepositives")),
            references=_str_list(doc.get("references")),
            source_path=path,
        )
    except (TypeError, ValueError) as exc:
        raise RuleError(f"malformed rule structure: {exc}") from exc
    return rule


def _str_list(value: Any) -> List[str]:
    if value is None:
        return []
    if isinstance(value, (str, int, float)):
        return [str(value)]
    if isinstance(value, list):
        return [str(item) for item in value]
    raise RuleError(f"expected a list of strings, got {type(value).__name__}")


def validate_rule(rule: Rule) -> None:
    """Raise RuleError describing the first structural problem found."""
    if not rule.id:
        raise RuleError("missing required key: id")
    if not rule.title:
        raise RuleError(f"rule {rule.id!r}: missing required key: title")
    if rule.level not in LEVELS:
        raise RuleError(
            f"rule {rule.id!r}: level must be one of {', '.join(LEVELS)} "
            f"(got {rule.level!r})"
        )
    if rule.is_aggregation:
        _validate_aggregation(rule)
    else:
        _validate_detection(rule)


def _validate_detection(rule: Rule) -> None:
    if not isinstance(rule.detection, dict) or not rule.detection:
        raise RuleError(f"rule {rule.id!r}: missing detection block")
    selections = {k: v for k, v in rule.detection.items() if k != "condition"}
    if not selections:
        raise RuleError(f"rule {rule.id!r}: detection has no selections")
    for name, block in selections.items():
        if not isinstance(block, dict) or not block:
            raise RuleError(
                f"rule {rule.id!r}: selection {name!r} must be a non-empty mapping"
            )
        for key, value in block.items():
            _validate_field_spec(rule, name, key, value)
    _validate_condition(rule, selections)


def _validate_field_spec(rule: Rule, selection: str, key: str, value: Any) -> None:
    where = f"rule {rule.id!r}: selection {selection!r}: field {key!r}"
    if "|" in key:
        field_name, op = key.split("|", 1)
        if not field_name:
            raise RuleError(f"{where}: empty field name")
        if op not in STRING_OPERATORS:
            raise RuleError(f"{where}: unknown operator {op!r}")
        if op == "re":
            for pattern in value if isinstance(value, list) else [value]:
                try:
                    re.compile(str(pattern))
                except re.error as exc:
                    raise RuleError(f"{where}: invalid regex {pattern!r}: {exc}")
        if op.endswith("_any") or op == "in":
            if not isinstance(value, list) or not value:
                raise RuleError(f"{where}: operator {op!r} requires a non-empty list")
    elif isinstance(value, dict):
        for op in value:
            if op not in NUMERIC_OPERATORS:
                raise RuleError(f"{where}: unknown numeric operator {op!r}")
            if not isinstance(value[op], (int, float)):
                raise RuleError(f"{where}: numeric operator {op!r} requires a number")


def _validate_condition(rule: Rule, selections: Dict[str, Any]) -> None:
    condition = rule.condition
    match = CONDITION_RE.match(condition)
    if not match:
        raise RuleError(
            f"rule {rule.id!r}: unsupported condition {condition!r} "
            "(supported: A | A and B | A or B | A and not B)"
        )
    left, joiner, negate, right = match.groups()
    if joiner and joiner.lower() == "or" and negate:
        raise RuleError(f"rule {rule.id!r}: 'or not' conditions are not supported")
    for name in filter(None, (left, right)):
        if name not in selections:
            raise RuleError(
                f"rule {rule.id!r}: condition references unknown selection {name!r}"
            )


def _validate_aggregation(rule: Rule) -> None:
    agg = rule.aggregation
    if not isinstance(agg, dict) or not agg:
        raise RuleError(f"rule {rule.id!r}: missing aggregation block")
    for key in ("group_by", "window_minutes"):
        if key not in agg:
            raise RuleError(f"rule {rule.id!r}: aggregation missing key {key!r}")
    if ("count_gte" in agg) == ("count_lte" in agg):
        raise RuleError(
            f"rule {rule.id!r}: aggregation needs exactly one of count_gte "
            "(threshold/sequence) or count_lte (rarity)"
        )
    if not isinstance(agg["group_by"], list) or not agg["group_by"]:
        raise RuleError(f"rule {rule.id!r}: aggregation group_by must be a non-empty list")
    for key in ("count_gte", "count_lte", "window_minutes"):
        if key not in agg:
            continue
        if not isinstance(agg[key], (int, float)) or agg[key] <= 0:
            raise RuleError(f"rule {rule.id!r}: aggregation {key} must be a positive number")
    if "followed_by" in agg and "count_lte" in agg:
        raise RuleError(f"rule {rule.id!r}: followed_by cannot be combined with count_lte")
    filter_block = agg.get("filter")
    if filter_block is not None:
        if not isinstance(filter_block, dict):
            raise RuleError(f"rule {rule.id!r}: aggregation filter must be a mapping")
        for key, value in filter_block.items():
            _validate_field_spec(rule, "filter", key, value)
    followed_by = agg.get("followed_by")
    if followed_by is not None:
        if not isinstance(followed_by, dict) or not followed_by:
            raise RuleError(f"rule {rule.id!r}: aggregation followed_by must be a mapping")
        for key, value in followed_by.items():
            _validate_field_spec(rule, "followed_by", key, value)
