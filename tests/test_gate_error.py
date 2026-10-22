"""Tests for grader.error_line, the one pytest output line a gate error and a certificate keep (queue T28).

Helper-level tests and a certificate round trip. No sandbox, model or network.
"""

from test_certify import cert_for, gate_failed_report, grade, with_before

from cheatproof.certify import load_certificate, write_certificate
from cheatproof.grader import ERROR_LINE_CHARS, GateReport, error_line

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


def test_secret_like_line_becomes_redacted():
    assert error_line("", "ERROR: token sk-TESTVALUE12345") == "REDACTED"


def test_gate_error_line_survives_a_certificate_write_and_load(tmp_path):
    gold_error = "pytest exited 4: pytest: error: unrecognized arguments: --cov=foo -n"
    report = with_before(
        gate_failed_report(), gates=GateReport(gold=grade(False, error=gold_error), empty=grade(False))
    )
    path = write_certificate(cert_for(report), tmp_path)
    gold = load_certificate(path)["harden"]["before"]["gates"]["gold"]
    assert gold["error_line"] == gold_error
    assert "unrecognized arguments" in gold["error_line"]
