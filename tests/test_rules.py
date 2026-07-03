"""Rule loading and validation tests."""

import os

import pytest

from w3csaw.rules import Rule, RuleError, load_rules, validate_rule
from tests.conftest import FIXTURES


def _rule(**overrides) -> Rule:
    base = dict(
        id="test_rule", title="Test Rule", level="high",
        detection={"selection": {"method": "GET"}, "condition": "selection"},
    )
    base.update(overrides)
    return Rule(**base)


def test_bundled_rules_all_valid(rules_dir):
    rules, errors = load_rules(rules_dir)
    assert errors == []
    assert len(rules) >= 20
    ids = [r.id for r in rules]
    assert len(ids) == len(set(ids))


def test_bundled_rules_have_metadata(rules_dir):
    rules, _ = load_rules(rules_dir)
    for rule in rules:
        assert rule.description, rule.id
        assert rule.tags, rule.id
        assert rule.falsepositives, rule.id
        assert rule.references, rule.id


def test_broken_rules_reported_valid_ones_kept():
    rules, errors = load_rules(os.path.join(FIXTURES, "broken_rules"))
    assert len(errors) == 3
    assert [r.id for r in rules] == ["valid_rule_in_broken_pack"]
    joined = " ".join(errors)
    assert "broken_bad_level" in joined
    assert "frobnicate" in joined
    assert "broken_bad_condition" in joined


def test_missing_id_rejected():
    with pytest.raises(RuleError, match="id"):
        validate_rule(_rule(id=""))


def test_invalid_level_rejected():
    with pytest.raises(RuleError, match="level"):
        validate_rule(_rule(level="urgent"))


def test_condition_unknown_selection_rejected():
    rule = _rule(detection={"selection": {"method": "GET"},
                            "condition": "selection and other"})
    with pytest.raises(RuleError, match="unknown selection"):
        validate_rule(rule)


def test_or_not_condition_rejected():
    rule = _rule(detection={"a": {"method": "GET"}, "b": {"method": "POST"},
                            "condition": "a or not b"})
    with pytest.raises(RuleError, match="or not"):
        validate_rule(rule)


def test_invalid_regex_rejected():
    rule = _rule(detection={"selection": {"uri_path|re": "["},
                            "condition": "selection"})
    with pytest.raises(RuleError, match="regex"):
        validate_rule(rule)


def test_any_operator_requires_list():
    rule = _rule(detection={"selection": {"uri_path|contains_any": "solo"},
                            "condition": "selection"})
    with pytest.raises(RuleError, match="non-empty list"):
        validate_rule(rule)


def test_aggregation_requires_exactly_one_count_bound():
    rule = _rule(type="aggregation", detection={},
                 aggregation={"group_by": ["src_ip"], "window_minutes": 60})
    with pytest.raises(RuleError, match="count_gte"):
        validate_rule(rule)


def test_valid_aggregation_accepted():
    rule = _rule(type="aggregation", detection={},
                 aggregation={"group_by": ["src_ip"], "window_minutes": 60,
                              "count_gte": 100, "filter": {"status": 404}})
    validate_rule(rule)


def test_duplicate_ids_reported(tmp_path):
    for name in ("a.yml", "b.yml"):
        (tmp_path / name).write_text(
            "id: dup\ntitle: T\nlevel: low\n"
            "detection:\n  selection:\n    method: GET\n  condition: selection\n"
        )
    rules, errors = load_rules(str(tmp_path))
    assert len(rules) == 1
    assert any("duplicate rule id" in e for e in errors)
