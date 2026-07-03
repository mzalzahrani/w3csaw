"""Shared test paths and helpers."""

import os

import pytest

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")
RULES_DIR = os.path.join(os.path.dirname(__file__), os.pardir, "w3csaw", "rules")


@pytest.fixture
def fixtures_dir() -> str:
    return FIXTURES


@pytest.fixture
def rules_dir() -> str:
    return os.path.normpath(RULES_DIR)


def fixture(name: str) -> str:
    return os.path.join(FIXTURES, name)
