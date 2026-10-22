"""Tests for grader.error_line, the one pytest output line a gate error and a certificate keep (queue T28).

Helper-level tests and a certificate round trip. No sandbox, model or network.
"""

import pytest
from test_certify import cert_for, gate_failed_report, grade, with_before

from cheatproof.certify import load_certificate, write_certificate
from cheatproof.executor import Result
from cheatproof.grader import ERROR_LINE_CHARS, ERROR_TAIL_CHARS, GateReport, error_line, error_tail

USAGE_STDERR = (
    "ERROR: usage: pytest [options] [file_or_dir] [file_or_dir] [...]\n"
    "pytest: error: unrecognized arguments: --cov=foo -n\n"
    "  inifile: /testbed/setup.cfg\n"
    "  rootdir: /testbed\n"
)
USAGE_LINE = "pytest: error: unrecognized arguments: --cov=foo -n"


def test_usage_error_prefers_the_pytest_error_line_over_the_usage_line():
    assert error_line(USAGE_STDERR, "") == USAGE_LINE


def test_line_is_capped_at_error_line_chars_with_an_ellipsis():
    # Spaced words: an unbroken run of 32+ word characters is a long token, which sanitize redacts instead.
    long = "pytest: error: " + "word " * 100
    line = error_line("", long)
    assert len(line) == ERROR_LINE_CHARS
    assert line.endswith("...") and line.startswith("pytest: error: word word")


def test_ansi_escape_codes_are_stripped_before_matching_and_kept_out_of_the_line():
    assert error_line("", "\x1b[1m\x1b[31mpytest: error: boom\x1b[0m\n") == "pytest: error: boom"
    assert error_line("\x1b[31mERROR\x1b[0m: colored\n") == "ERROR: colored"


def test_e_prefix_line_is_the_fallback_when_there_is_no_error_line():
    assert (
        error_line("", "collected 1 item\nE   AssertionError: boom\nFAILED x\n") == "E   AssertionError: boom"
    )


def test_empty_output_gives_an_empty_line_and_no_crash():
    assert error_line("", "") == ""
    assert error_line("", "   \n\n") == ""
    assert error_line() == ""


def test_stdout_is_searched_when_stderr_has_no_error_line():
    assert error_line("plain stderr text", "ERROR: from stdout") == "ERROR: from stdout"


def test_only_the_last_200_lines_are_searched():
    output = "ERROR: old\n" + "noise\n" * 200
    assert error_line("", output) == "noise"


def test_root_and_tmp_paths_are_replaced_with_a_placeholder():
    line = error_line("", "ERROR: cannot open /root/.cache/x and /tmp/abc/def.py")
    assert line == "ERROR: cannot open <path> and <path>"


@pytest.mark.parametrize(
    "path",
    [
        "/root/.cache/x.py",
        "/tmp/abc/x.py",
        "/home/runner/x.py",
        "/private/tmp/abc/x.py",
        "/var/folders/zz/T/x.py",
    ],
)
def test_each_host_path_is_replaced_before_the_secret_check(path):
    line = error_line("", f"ERROR: cannot open {path} now")
    assert line == "ERROR: cannot open <path> now"


def test_a_secret_token_is_redacted_and_the_rest_of_the_line_kept():
    assert error_line("", "ERROR: token sk-TESTVALUE12345 failed") == "ERROR: token REDACTED failed"


def test_a_long_random_token_is_redacted_and_the_rest_of_the_line_kept():
    # No underscores and mixed case: not a pytest name, so the long-run check redacts it.
    line = error_line("", "ERROR: key AbCdEf0123456789GhIjKl0123456789MnOpQr is bad")
    assert line == "ERROR: key REDACTED is bad"


def test_a_long_test_name_survives():
    name = "test_a_really_long_function_name_here"
    line = error_line("", f"ERROR: file or directory not found: tests/{name}.py")
    assert line == f"ERROR: file or directory not found: tests/{name}.py"


def test_a_long_relative_path_survives():
    path = "tests/integration/sub_package/test_another_really_long_function_name_here.py"
    assert error_line("", f"ERROR: file or directory not found: {path}") == (
        f"ERROR: file or directory not found: {path}"
    )


def test_exit_4_takes_the_error_summary_line_before_an_e_line():
    output = "E   ImportError: nope\nERROR tests/a.py - ImportError\n"
    assert error_line("", output, exit_code=4) == "ERROR tests/a.py - ImportError"


def test_other_exit_codes_take_the_e_line_before_a_bare_error_line():
    output = "ERROR tests/a.py - ImportError\nE   ImportError: nope\n"
    assert error_line("", output, exit_code=1) == "E   ImportError: nope"
    assert error_line("", output, exit_code=2) == "E   ImportError: nope"


def test_pytest_usage_error_line_wins_over_e_and_error_lines_at_any_exit_code():
    output = "E   boom\nERROR: usage: pytest\npytest: error: unrecognized arguments: -n\n"
    assert error_line("", output, exit_code=4) == "pytest: error: unrecognized arguments: -n"
    assert error_line("", output, exit_code=1) == "pytest: error: unrecognized arguments: -n"


def test_error_tail_is_one_sanitized_line_and_keeps_the_end():
    tail = error_tail(Result(1, "", "fatal: first\n  \x1b[31mpytest: error: second\x1b[0m\n/root/x\n", 0.1))
    assert tail == "fatal: first | pytest: error: second | <path>"
    assert "\n" not in tail


def test_error_tail_is_capped_at_error_tail_chars_keeping_the_end():
    stderr = "\n".join(f"line {i} " + "word " * 10 for i in range(100)) + "\nlast line here\n"
    tail = error_tail(Result(1, "", stderr, 0.1))
    assert len(tail) == ERROR_TAIL_CHARS
    assert tail.startswith("...") and tail.endswith("| last line here")
    assert "\n" not in tail


def test_error_tail_uses_stdout_when_stderr_is_empty():
    assert error_tail(Result(1, "from stdout\n", "", 0.1)) == "from stdout"
    assert error_tail(Result(1, "", "", 0.1)) == ""


def test_gate_error_line_survives_a_certificate_write_and_load(tmp_path):
    gold_error = "pytest exited 4: pytest: error: unrecognized arguments: --cov=foo -n"
    report = with_before(
        gate_failed_report(), gates=GateReport(gold=grade(False, error=gold_error), empty=grade(False))
    )
    path = write_certificate(cert_for(report), tmp_path)
    gold = load_certificate(path)["harden"]["before"]["gates"]["gold"]
    assert gold["error_line"] == gold_error
    assert "unrecognized arguments" in gold["error_line"]
