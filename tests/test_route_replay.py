import json
from types import SimpleNamespace

import pytest

from rewardseal import attacker
from rewardseal.executor import Result
from scripts import route_replay as replay

OUTPUTS = ["65bf318 commit by person@example.com", "65bf318 stat", "commit 65bf318\n    " + replay.LINE]


def result(text, code=0):
    return Result(code, text, "", 0)


def trace(path, limit=3000):
    rows = [{"type": "header", "max_result_chars": limit}]
    for number, command, output in zip((12, 13, 14), replay.COMMANDS, OUTPUTS, strict=True):
        formatted = attacker._format_run(result(output))
        sha, chars = replay.digest(formatted)
        rows.append(
            {
                "type": "step",
                "step": number,
                "tool": "run",
                "ignored_calls": 0,
                "args": {"cmd": command},
                "result_digest": {"sha256": sha, "chars": chars, "head": output},
            }
        )
    path.write_text("\n".join(json.dumps(row) for row in rows))
    return path


class Session:
    def __init__(self, outputs):
        self.outputs = iter(outputs)
        self.resets = 0
        self.commands = []

    def reset(self):
        self.resets += 1

    def run(self, command, timeout):
        self.commands.append(command)
        return next(self.outputs)


def run(path, before=OUTPUTS):
    session = Session(
        [
            *(result(s) for s in before),
            result(""),
            result("bad object 65bf318", 128),
            result("unknown revision 65bf318", 128),
        ]
    )
    task = SimpleNamespace(instance_id="CycloneDX__cyclonedx-python-348")
    calls = []

    def patch(*args, **kwargs):
        calls.append((args, kwargs))
        return [SimpleNamespace(ok=True)]

    record = replay.run_replay(session, task, replay.read_trace(trace(path)), 120, apply_patches=patch)
    assert session.commands == list(replay.COMMANDS) * 2
    assert session.resets == record["sandbox_resets"] == 2
    assert calls[0][0][2] == (replay.audit.PATCH_NAME,)
    return record


def test_all_match_strip_and_no_output_text(tmp_path):
    record = run(tmp_path / "trace.jsonl")
    assert all(step["match"] for step in record["steps"])
    assert [step["step"] for step in record["steps"]] == [12, 13, 14]
    assert record["line_in_step14"] is True
    assert all(step["commit_unreachable"] for step in record["after_strip"])
    assert record["after_strip"][1]["exit_code"] == 128
    serialized = json.dumps(record)
    assert "@" not in serialized
    assert all(output not in serialized for output in OUTPUTS)
    assert "bad object" not in serialized


def test_mismatch(tmp_path):
    record = run(tmp_path / "trace.jsonl", ["different", *OUTPUTS[1:]])
    assert [step["match"] for step in record["steps"]] == [False, True, True]


def test_truncated_limit_refused(tmp_path):
    with pytest.raises(replay.ControlError, match="1085"):
        replay.read_trace(trace(tmp_path / "trace.jsonl", 1084))


def test_missing_and_ambiguous(tmp_path):
    path = trace(tmp_path / "trace.jsonl")
    lines = path.read_text().splitlines()
    path.write_text("\n".join(lines[:-1]))
    with pytest.raises(replay.ControlError, match="missing or ambiguous"):
        replay.read_trace(path)
    path.write_text("\n".join([*lines, lines[1]]))
    with pytest.raises(replay.ControlError, match="missing or ambiguous"):
        replay.read_trace(path)


def test_dry_run_never_creates_session(tmp_path, monkeypatch, capsys):
    def forbidden():
        raise AssertionError("session factory called")

    monkeypatch.setattr(replay, "make_executor", forbidden)
    path = trace(tmp_path / "trace.jsonl")
    assert replay.main(["--trace", str(path), "--dry-run"]) == 0
    assert replay.COMMANDS[0] in capsys.readouterr().out


def test_annotated_step_refused(tmp_path):
    path = trace(tmp_path / "t.jsonl")
    rows = [json.loads(line) for line in path.read_text().splitlines()]
    rows[1]["ignored_calls"] = 1
    path.write_text("\n".join(json.dumps(row) for row in rows))
    with pytest.raises(replay.ControlError, match="ignored calls"):
        replay.read_trace(path)


@pytest.mark.parametrize("code,text", [(124, ""), (137, ""), (1, "fatal: not a git repository")])
def test_unexpected_failure_is_not_unreachable(tmp_path, code, text):
    session = Session(
        [*(result(s) for s in OUTPUTS), result(""), result(text, code), result("bad object 65bf318", 128)]
    )
    task = SimpleNamespace(instance_id="CycloneDX__cyclonedx-python-348")
    ok = lambda *a, **k: [SimpleNamespace(ok=True)]
    steps = replay.read_trace(trace(tmp_path / "t.jsonl"))
    if code in (124, 137):
        with pytest.raises(replay.ControlError):
            replay.run_replay(session, task, steps, 120, apply_patches=ok)
    else:
        record = replay.run_replay(session, task, steps, 120, apply_patches=ok)
        assert record["after_strip"][1]["commit_unreachable"] is False
