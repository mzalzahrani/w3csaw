"""Tests for --help output across the CLI."""

import os

import pytest

from w3csaw.cli import main


@pytest.mark.parametrize("argv", [
    ["--help"],
    ["scan", "--help"],
    ["timeline", "--help"],
    ["top", "--help"],
    ["validate-rules", "--help"],
    ["rule-info", "--help"],
])
def test_help_exits_zero(argv, capsys):
    with pytest.raises(SystemExit) as exc:
        main(argv)
    assert exc.value.code == 0
    assert capsys.readouterr().out.strip()


def test_main_help_lists_commands_and_exit_codes(capsys):
    with pytest.raises(SystemExit):
        main(["--help"])
    out = capsys.readouterr().out
    for command in ("scan", "timeline", "top", "validate-rules", "rule-info"):
        assert command in out
    assert "exit codes" in out.lower()
    assert "2" in out


def test_scan_help_documents_terminal_options(capsys):
    with pytest.raises(SystemExit):
        main(["scan", "--help"])
    out = capsys.readouterr().out
    for option in ("--cli", "--full", "--no-color", "--quiet", "--no-banner",
                   "--group-by", "--max-table-width"):
        assert option in out


def test_scan_help_documents_exit_codes_and_examples(capsys):
    with pytest.raises(SystemExit):
        main(["scan", "--help"])
    out = capsys.readouterr().out
    assert "exit code" in out.lower()
    assert "findings were detected" in out
    assert "w3csaw scan -i" in out


def test_help_does_not_scan_or_create_files(tmp_path, capsys, monkeypatch):
    monkeypatch.chdir(tmp_path)
    with pytest.raises(SystemExit):
        main(["scan", "--help"])
    out = capsys.readouterr().out
    # Help renders without touching inputs/outputs.
    assert "usage:" in out.lower()
    assert os.listdir(tmp_path) == []
