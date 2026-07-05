"""Tests for the --cli terminal output mode."""

from w3csaw.cli import main
from w3csaw.console import (build_category_map, category_from_source,
                            truncate_value, highest_severity)
from w3csaw.engine import Finding
from w3csaw.rules import load_rules
from tests.conftest import RULES_DIR, fixture

SAMPLE = fixture("attack.log")


def _run(args):
    return main(args)


def test_cli_runs_and_returns_findings_exit_code(capsys):
    code = _run(["scan", "-i", SAMPLE, "-r", RULES_DIR, "--cli", "--quiet"])
    assert code == 2
    out = capsys.readouterr().out
    assert "iis_webshell_command_execution_query" in out


def test_cli_clean_log_returns_zero(capsys):
    code = _run(["scan", "-i", fixture("clean.log"), "-r", RULES_DIR, "--cli"])
    assert code == 0
    combined = capsys.readouterr()
    assert "No suspicious IIS activity" in (combined.out + combined.err)


def test_cli_truncates_long_values_by_default(capsys):
    _run(["scan", "-i", SAMPLE, "-r", RULES_DIR, "--cli", "--quiet"])
    out = capsys.readouterr().out
    assert "…" in out  # ellipsis inserted somewhere


def test_cli_full_shows_untruncated_values(capsys):
    _run(["scan", "-i", SAMPLE, "-r", RULES_DIR, "--cli", "--quiet"])
    default_out = capsys.readouterr().out
    _run(["scan", "-i", SAMPLE, "-r", RULES_DIR, "--cli", "--quiet", "--full"])
    full_out = capsys.readouterr().out
    # Long values (the encoded JNDI query) are ellipsized by default but not
    # with --full, which disables truncation entirely.
    assert "…" in default_out
    assert "…" not in full_out
    assert "iis_webshell_command_execution_query" in full_out


def test_cli_no_color_emits_no_ansi(capsys):
    _run(["scan", "-i", SAMPLE, "-r", RULES_DIR, "--cli", "--no-color"])
    captured = capsys.readouterr()
    assert "\x1b[" not in captured.out
    assert "\x1b[" not in captured.err


def test_cli_quiet_suppresses_banner_and_status(capsys):
    _run(["scan", "-i", SAMPLE, "-r", RULES_DIR, "--cli", "--quiet"])
    captured = capsys.readouterr()
    combined = captured.out + captured.err
    assert "█" not in combined      # no banner block characters
    assert "[+]" not in combined         # no status lines
    assert "iis_webshell_command_execution_query" in captured.out  # tables remain


def test_cli_no_banner_keeps_status(capsys):
    _run(["scan", "-i", SAMPLE, "-r", RULES_DIR, "--cli", "--no-banner"])
    captured = capsys.readouterr()
    combined = captured.out + captured.err
    assert "█" not in combined      # banner suppressed
    assert "[+]" in combined             # status lines still present


def test_cli_group_by_level(capsys):
    _run(["scan", "-i", SAMPLE, "-r", RULES_DIR, "--cli", "--group-by", "level"])
    combined = "".join(capsys.readouterr())
    assert "Group: critical" in combined or "Group: high" in combined


def test_cli_group_by_rule(capsys):
    _run(["scan", "-i", SAMPLE, "-r", RULES_DIR, "--cli", "--group-by", "rule"])
    combined = "".join(capsys.readouterr())
    assert "Group: iis_" in combined


def test_cli_with_output_file_still_writes_machine_output(tmp_path, capsys):
    out = tmp_path / "findings.jsonl"
    code = _run(["scan", "-i", SAMPLE, "-r", RULES_DIR, "--cli", "--quiet",
                 "-o", str(out), "--format", "jsonl"])
    assert code == 2
    lines = out.read_text().splitlines()
    assert lines and lines[0].startswith("{")
    # Terminal tables still rendered to stdout, JSONL only in the file.
    assert '"rule_id"' not in capsys.readouterr().out


def test_cli_without_output_suppresses_stdout_machine_dump(capsys):
    _run(["scan", "-i", SAMPLE, "-r", RULES_DIR, "--cli", "--quiet"])
    assert '"rule_id"' not in capsys.readouterr().out


def test_summary_reports_skipped_lines(capsys):
    _run(["scan", "-i", fixture("malformed.log"), "-r", RULES_DIR,
          "--cli", "--fail-open"])
    combined = "".join(capsys.readouterr())
    assert "Malformed lines skipped" in combined


# -- unit-level helpers -------------------------------------------------------

def test_truncate_value():
    assert truncate_value("short", 40, full=False) == "short"
    assert truncate_value(None, 40, full=False) == "-"
    long = "x" * 60
    assert truncate_value(long, 40, full=False).endswith("…")
    assert truncate_value(long, 40, full=True) == long


def test_category_from_source():
    assert category_from_source("rules/webshell/x.yml") == "Webshell"
    assert category_from_source("rules/rce/x.yml") == "RCE"
    assert category_from_source("rules/aggregation/x.yml") == "Aggregation"
    assert category_from_source("rules/unknown/x.yml") == "Other"


def test_build_category_map():
    rules, _ = load_rules(RULES_DIR)
    cat = build_category_map(rules)
    assert cat["iis_webshell_command_execution_query"] == "Webshell"
    assert cat["iis_high_404_single_source"] == "Aggregation"


def test_results_caps_rows_per_group():
    import io
    from rich.console import Console
    from w3csaw.console import ConsoleReporter

    def finding(i):
        return Finding(rule_id="iis_x", rule_title="t", level="high",
                       status="s", description="", timestamp=f"2026-07-03T00:00:{i:02d}Z",
                       src_ip="1.1.1.1", method="GET", uri_path="/a",
                       uri_query=None, status_code=200, user_agent="ua",
                       referer=None, host=None)

    reporter = ConsoleReporter(no_color=True, quiet=True, group_by="rule",
                               max_rows=2, category_map={"iis_x": "Other"})
    buffer = io.StringIO()
    reporter.out = Console(file=buffer, width=200, no_color=True)
    reporter.results([finding(i) for i in range(5)])
    text = buffer.getvalue()
    assert "and 3 more finding(s)" in text


def test_interactive_mode_runs_a_scan(monkeypatch, capsys):
    import w3csaw.interactive as interactive
    from w3csaw import cli  # noqa: F401 - wires interactive.run_scan

    # Rules are auto-loaded, so only input, group_by, and min_level are asked.
    answers = iter([SAMPLE, "category", "low"])
    confirms = iter([False, False, False])  # full? save? again?
    monkeypatch.setattr(interactive.Prompt, "ask",
                        staticmethod(lambda *a, **k: next(answers)))
    monkeypatch.setattr(interactive.Confirm, "ask",
                        staticmethod(lambda *a, **k: next(confirms)))

    code = interactive.run_interactive()
    assert code == 2  # sample log has findings
    combined = "".join(capsys.readouterr())
    assert "iis_webshell_command_execution_query" in combined
    assert "bundled rule pack" in combined


def test_interactive_reasks_on_bad_input(monkeypatch, capsys):
    import w3csaw.interactive as interactive
    from w3csaw import cli  # noqa: F401

    # First input is invalid, second resolves; rules auto-loaded.
    answers = iter(["/no/such/path/*.log", SAMPLE, "level", "low"])
    confirms = iter([False, False, False])
    monkeypatch.setattr(interactive.Prompt, "ask",
                        staticmethod(lambda *a, **k: next(answers)))
    monkeypatch.setattr(interactive.Confirm, "ask",
                        staticmethod(lambda *a, **k: next(confirms)))

    code = interactive.run_interactive()
    assert code == 2
    assert "log file(s)" in "".join(capsys.readouterr())


def test_interactive_clean_exit_on_keyboard_interrupt(monkeypatch, capsys):
    import w3csaw.interactive as interactive
    from w3csaw import cli  # noqa: F401

    def boom(*a, **k):
        raise KeyboardInterrupt

    monkeypatch.setattr(interactive.Prompt, "ask", staticmethod(boom))
    code = interactive.run_interactive()
    assert code == 0
    assert "Goodbye" in "".join(capsys.readouterr())


def test_highest_severity():
    def f(level):
        return Finding(rule_id="r", rule_title="t", level=level, status="s",
                       description="", timestamp=None, src_ip=None, method=None,
                       uri_path=None, uri_query=None, status_code=None,
                       user_agent=None, referer=None, host=None)
    assert highest_severity([f("low"), f("critical"), f("medium")]) == "critical"
    assert highest_severity([]) is None
