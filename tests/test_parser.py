import pytest

from explainfail.parser import detect_exit_code, extract_traceback, find_error_lines, parse


@pytest.mark.parametrize(
    "text,expected",
    [
        ("Process finished with exit code 1", 1),
        ("exit code: 137", 137),
        ("worker exited with status 2", 2),
        ("command returned non-zero exit status 3", 3),
        ("job ended RC=4", 4),
        ("returncode=5", 5),
        ("nothing interesting here", None),
        ("exit code 1\nretrying\nexit code 0", 0),  # the last one wins
        ("exit code 999", None),  # not a real exit code
    ],
)
def test_detect_exit_code(text, expected):
    assert detect_exit_code(text) == expected


TB = """\
INFO starting
Traceback (most recent call last):
  File "a.py", line 3, in <module>
    run()
  File "a.py", line 7, in run
    1 / 0
ZeroDivisionError: division by zero
INFO done
"""


def test_extract_traceback_includes_exception_line():
    tb = extract_traceback(TB.splitlines())
    assert tb.startswith("Traceback (most recent call last):")
    assert tb.splitlines()[-1] == "ZeroDivisionError: division by zero"
    assert "INFO" not in tb


def test_extract_traceback_returns_last_block():
    text = TB + 'Traceback (most recent call last):\n  File "b.py", line 1, in <module>\nKeyError: \'x\'\n'
    tb = extract_traceback(text.splitlines())
    assert tb.splitlines()[-1] == "KeyError: 'x'"


def test_extract_traceback_with_log_prefix():
    lines = [
        "[etl] Traceback (most recent call last):",
        '[etl]   File "a.py", line 1, in <module>',
        "[etl] ValueError: boom",
    ]
    assert extract_traceback(lines).splitlines()[-1] == "[etl] ValueError: boom"


def test_no_traceback():
    assert extract_traceback(["just", "text"]) == ""


def test_error_lines_skip_noise_and_duplicates():
    lines = [
        "INFO all fine",
        "Finished with 0 errors",
        "ERROR disk problem",
        "ERROR disk problem",
        "WARNING retry failed",
    ]
    assert find_error_lines(lines) == ["ERROR disk problem", "WARNING retry failed"]


def test_error_lines_are_capped():
    lines = [f"ERROR number {i}" for i in range(500)]
    out = find_error_lines(lines)
    assert len(out) <= 41
    assert out[0] == "ERROR number 0" and out[-1] == "ERROR number 499"


def test_parse_collects_everything():
    p = parse(TB, tail_lines=2)
    assert p.total_lines == 8
    assert p.traceback.endswith("division by zero")
    assert p.tail.splitlines() == ["ZeroDivisionError: division by zero", "INFO done"]
    assert p.first_error.startswith("Traceback")


def test_explicit_exit_code_beats_detected():
    assert parse("exit code 1", exit_code=7).exit_code == 7
