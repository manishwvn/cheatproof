"""Rough cut tests: fake runner only. Nothing runs say or ffmpeg, and no model or paid API is called."""

import subprocess
from pathlib import Path

import pytest

from video import rough_cut as rc

SAMPLE = """# Sample

## Beat table

| Start | Dur (s) | On-screen | Voice-over | Caption |
|---|---|---|---|---|
| 0:00 | 10 | Title one | Hello there. | First |
| 0:10 | 5 | Terminal: model ID | Second line here. | Second: caption |
| 0:15 | 20 | Card | Third line of voice. | Third |

Notes after the table are not beats.
"""


def write_script(tmp_path: Path, text: str = SAMPLE) -> Path:
    path = tmp_path / "script.md"
    path.write_text(text, encoding="utf-8")
    return path


class FakeRunner:
    def __init__(self) -> None:
        self.calls: list[tuple[str, ...]] = []

    def __call__(self, command):
        self.calls.append(tuple(command))


def no_subprocess(*args, **kwargs):
    raise AssertionError(f"subprocess must not run: {args}")


def test_parse_sample_beats():
    beats = rc.parse_beats(SAMPLE)
    assert [b.number for b in beats] == [1, 2, 3]
    assert [b.start for b in beats] == [0, 10, 15]
    assert [b.duration for b in beats] == [10, 5, 20]
    assert beats[1].on_screen == "Terminal: model ID"
    assert beats[1].voice_over == "Second line here."
    assert beats[1].caption == "Second: caption"


def test_real_script_parses_under_limit_and_shows_model_id_early():
    beats = rc.parse_beats(rc.SCRIPT_PATH.read_text(encoding="utf-8"))
    assert beats[0].start == 0
    assert rc.check_total(beats) < rc.LIMIT_SECONDS
    early = [b for b in beats if b.start < 20]
    assert any("nvidia/nemotron-3-super-120b-a12b" in b.on_screen for b in early)
    model_beats = [b for b in beats if "nvidia/nemotron-3-super-120b-a12b" in b.on_screen]
    assert model_beats
    assert all(b.start + b.duration <= 20 for b in model_beats)


def test_parse_rejects_missing_heading():
    with pytest.raises(rc.ScriptError, match="Beat table"):
        rc.parse_beats("| Start | Dur (s) | On-screen | Voice-over | Caption |")


def test_parse_rejects_gap_between_beats():
    gap = SAMPLE.replace("| 0:10 | 5 |", "| 0:11 | 5 |")
    with pytest.raises(rc.ScriptError, match="starts at 0:11 but previous beat ends at 0:10"):
        rc.parse_beats(gap)


def test_parse_rejects_wrong_cell_count():
    short = SAMPLE.replace(
        "| 0:15 | 20 | Card | Third line of voice. | Third |", "| 0:15 | 20 | Card | Third |"
    )
    with pytest.raises(rc.ScriptError, match="need 5 cells"):
        rc.parse_beats(short)


def test_parse_rejects_bad_start_and_duration():
    with pytest.raises(rc.ScriptError, match="not m:ss"):
        rc.parse_beats(SAMPLE.replace("| 0:00 |", "| 00 |"))
    with pytest.raises(rc.ScriptError, match="positive integer"):
        rc.parse_beats(SAMPLE.replace("| 0:00 | 10 |", "| 0:00 | ten |"))


@pytest.mark.parametrize(
    ("seconds", "expected"),
    [(0, "00:00:00,000"), (9.5, "00:00:09,500"), (3661.25, "01:01:01,250"), (170, "00:02:50,000")],
)
def test_srt_timestamp_format(seconds, expected):
    assert rc.srt_timestamp(seconds) == expected


def test_build_srt_blocks():
    srt = rc.build_srt(rc.parse_beats(SAMPLE))
    assert srt == (
        "1\n00:00:00,000 --> 00:00:10,000\nFirst\n\n"
        "2\n00:00:10,000 --> 00:00:15,000\nSecond: caption\n\n"
        "3\n00:00:15,000 --> 00:00:35,000\nThird\n"
    )


def test_check_total_passes_under_limit():
    assert rc.check_total(rc.parse_beats(SAMPLE)) == 35


def test_check_total_fails_loudly_at_limit():
    at_limit = [rc.Beat(1, 0, 170, "a", "b", "c")]
    with pytest.raises(rc.ScriptError, match="170 s"):
        rc.check_total(at_limit)
    just_under = [rc.Beat(1, 0, 169, "a", "b", "c")]
    assert rc.check_total(just_under) == 169


def test_say_command_with_and_without_voice():
    aiff = Path("/x/beat01.aiff")
    assert rc.say_command("Hi there.", aiff, None) == ["say", "-o", "/x/beat01.aiff", "--", "Hi there."]
    assert rc.say_command("Hi there.", aiff, "Samantha") == [
        "say",
        "-v",
        "Samantha",
        "-o",
        "/x/beat01.aiff",
        "--",
        "Hi there.",
    ]


def test_say_voice_over_starting_with_dash_is_text_not_flag():
    command = rc.say_command("-5 degrees, then -v trap", Path("/x/a.aiff"), "Samantha")
    assert command[-2:] == ["--", "-5 degrees, then -v trap"]
    assert command.index("--") > command.index("-o")
    assert command.count("-v") == 1


def test_segment_command_pads_and_cuts_to_beat_length():
    visual = ["-f", "lavfi", "-i", "color=c=0x1d2330:s=1280x720:r=30"]
    command = rc.segment_command(visual, Path("/x/a.aiff"), 12, Path("/x/a.mp4"), "format=yuv420p")
    assert command[0] == "ffmpeg"
    assert command[command.index("-t") + 1] == "12"
    assert command[command.index("-af") + 1] == "apad"
    assert command[command.index("-map") + 1] == "0:v:0"
    assert command[-1] == "/x/a.mp4"


def test_concat_command_joins_every_segment():
    segments = [Path(f"/x/beat{n:02d}.mp4") for n in (1, 2, 3)]
    command = rc.concat_command(segments, Path("/x/rough_cut.mp4"))
    assert command.count("-i") == 3
    graph = command[command.index("-filter_complex") + 1]
    assert graph.startswith("[0:v:0][0:a:0][1:v:0][1:a:0][2:v:0][2:a:0]")
    assert graph.endswith("concat=n=3:v=1:a=1[v][a]")
    assert command[-1] == "/x/rough_cut.mp4"


def test_plan_uses_screenshot_when_present_and_card_otherwise(tmp_path):
    shots = tmp_path / "shots"
    shots.mkdir()
    (shots / "beat02.png").write_bytes(b"not really a png")
    beats = rc.parse_beats(SAMPLE)
    commands = rc.plan_commands(beats, tmp_path / "out", shots, None)
    assert len(commands) == 3 * 2 + 1
    beat2_segment = commands[3]
    assert beat2_segment[beat2_segment.index("-loop") + 1] == "1"
    assert str(shots / "beat02.png") in beat2_segment
    beat1_segment = commands[1]
    assert "lavfi" in beat1_segment
    assert any("textfile=" in part for part in beat1_segment)


def test_card_text_wraps_long_titles():
    text = rc.card_text("word " * 40)
    lines = text.split("\n")
    assert len(lines) > 1
    assert all(len(line) <= 40 for line in lines)


def test_drawtext_escape_protects_path_characters():
    assert rc.drawtext_escape("/a:b,c's") == "/a\\:b\\,c\\'s"


def test_overrun_warning_for_long_voice_over():
    long_vo = " ".join(["word"] * 30)
    beats = [rc.Beat(1, 0, 5, "a", long_vo, "c")]
    warnings = rc.overrun_warnings(beats)
    assert len(warnings) == 1
    assert "beat 1" in warnings[0]
    assert rc.overrun_warnings(rc.parse_beats(SAMPLE)) == []


def test_count_placeholders_in_sample():
    text = SAMPLE.replace("Third line of voice.", "Result [RESULT: n tasks, k holes - fill from results].")
    assert rc.count_placeholders(rc.parse_beats(text)) == 1


def make_font(tmp_path: Path) -> Path:
    font = tmp_path / "font.ttf"
    font.write_bytes(b"not a real font")
    return font


def test_make_rough_cut_runs_every_command_through_runner(tmp_path):
    runner = FakeRunner()
    out = tmp_path / "out"
    cut = rc.make_rough_cut(write_script(tmp_path), out, runner=runner, font=make_font(tmp_path))
    assert runner.calls == list(cut.commands)
    assert len(runner.calls) == 3 * 2 + 1
    assert runner.calls[-1][0] == "ffmpeg"
    assert (out / "rough_cut.srt").read_text(encoding="utf-8").startswith("1\n00:00:00,000 --> 00:00:10,000")
    assert (out / "work" / "beat01.txt").read_text(encoding="utf-8") == "Title one"


def test_dry_run_runs_nothing_and_writes_nothing(tmp_path):
    out = tmp_path / "never"
    cut = rc.make_rough_cut(write_script(tmp_path), out, dry_run=True)
    assert len(cut.commands) == 3 * 2 + 1
    assert not out.exists()


def test_main_dry_run_prints_commands_without_subprocess(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(rc.subprocess, "run", no_subprocess)
    script = write_script(tmp_path)
    code = rc.main(["--script", str(script), "--out", str(tmp_path / "out"), "--dry-run"])
    captured = capsys.readouterr()
    assert code == 0
    assert "say -o" in captured.out
    assert "rough_cut.mp4" in captured.out
    assert "nothing run" in captured.out
    assert not (tmp_path / "out").exists()


def test_main_refuses_script_at_limit(tmp_path, capsys):
    long_script = SAMPLE.replace("| 0:15 | 20 |", "| 0:15 | 155 |")
    code = rc.main(
        ["--script", str(write_script(tmp_path, long_script)), "--out", str(tmp_path / "o")], FakeRunner()
    )
    assert code == 1
    assert "170 s" in capsys.readouterr().err


def test_main_real_run_with_fake_runner_writes_outputs(tmp_path, capsys):
    runner = FakeRunner()
    out = tmp_path / "out"
    font = make_font(tmp_path)
    code = rc.main(["--script", str(write_script(tmp_path)), "--out", str(out), "--font", str(font)], runner)
    assert code == 0
    assert len(runner.calls) == 3 * 2 + 1
    assert (out / "rough_cut.srt").exists()
    assert "rough_cut.mp4" in capsys.readouterr().out


def test_default_out_dir_is_outside_repo():
    out = rc.default_out_dir(dry_run=True)
    assert not out.resolve().is_relative_to(rc.REPO_ROOT)


def test_default_out_dir_refuses_temp_inside_repo(monkeypatch):
    monkeypatch.setattr(rc.tempfile, "gettempdir", lambda: str(rc.REPO_ROOT))
    with pytest.raises(rc.ScriptError, match="inside the repo"):
        rc.default_out_dir(dry_run=True)


def test_run_subprocess_passes_argv_list(monkeypatch):
    seen = {}

    def fake_run(command, check):
        seen["command"] = command
        seen["check"] = check
        return subprocess.CompletedProcess(command, 0)

    monkeypatch.setattr(rc.subprocess, "run", fake_run)
    rc.run_subprocess(("say", "-o", "/x/a.aiff", "Hi"))
    assert seen == {"command": ["say", "-o", "/x/a.aiff", "Hi"], "check": True}


def test_card_text_keeps_percent_literal_for_expansion_none(tmp_path):
    assert rc.card_text("Done 100%, %{pts}") == "Done 100%, %{pts}"
    vf = rc.card_filter(tmp_path / "beat01.txt", tmp_path / "font.ttf")
    assert ":expansion=none:" in vf
    assert vf.index("expansion=none") < vf.index("fontcolor")


def test_percent_in_on_screen_text_reaches_card_file_verbatim(tmp_path):
    runner = FakeRunner()
    out = tmp_path / "out"
    script = write_script(tmp_path, SAMPLE.replace("Title one", "Speed 100% then %{pts}"))
    rc.make_rough_cut(script, out, runner=runner, font=make_font(tmp_path))
    assert (out / "work" / "beat01.txt").read_text(encoding="utf-8") == "Speed 100% then %{pts}"
    beat1_segment = runner.calls[1]
    assert "expansion=none" in beat1_segment[beat1_segment.index("-vf") + 1]


def test_check_out_path_rejects_quote_and_backslash(tmp_path):
    for bad in ("/x/it's", "/x/a\\b"):
        with pytest.raises(rc.ScriptError, match="has ' or"):
            rc.check_out_path(Path(bad))
    assert rc.check_out_path(Path("/x/ok folder")) == Path("/x/ok folder")


def test_main_refuses_quote_in_out_before_creating_anything(tmp_path, capsys):
    out = tmp_path / "bad'dir"
    runner = FakeRunner()
    code = rc.main(["--script", str(write_script(tmp_path)), "--out", str(out)], runner)
    assert code == 1
    assert "has ' or" in capsys.readouterr().err
    assert runner.calls == []
    assert not out.exists()


def test_main_refuses_temp_inside_repo_without_creating_dir(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(rc.tempfile, "gettempdir", lambda: str(rc.REPO_ROOT))

    def no_mkdtemp(*args, **kwargs):
        raise AssertionError("a temp dir must not be created")

    monkeypatch.setattr(rc.tempfile, "mkdtemp", no_mkdtemp)
    runner = FakeRunner()
    code = rc.main(["--script", str(write_script(tmp_path))], runner)
    assert code == 1
    assert "inside the repo" in capsys.readouterr().err
    assert runner.calls == []


def test_missing_font_fails_before_any_command(tmp_path):
    runner = FakeRunner()
    out = tmp_path / "out"
    with pytest.raises(rc.ScriptError, match="font file not found"):
        rc.make_rough_cut(write_script(tmp_path), out, runner=runner, font=tmp_path / "nope.ttf")
    assert runner.calls == []
    assert not (out / "work").exists()


def test_missing_font_is_fine_when_every_beat_has_a_shot(tmp_path):
    shots = tmp_path / "shots"
    shots.mkdir()
    for number in (1, 2, 3):
        (shots / f"beat{number:02d}.png").write_bytes(b"not really a png")
    runner = FakeRunner()
    rc.make_rough_cut(
        write_script(tmp_path), tmp_path / "out", shots_dir=shots, runner=runner, font=tmp_path / "nope.ttf"
    )
    assert len(runner.calls) == 3 * 2 + 1


def test_font_option_reaches_drawtext_filter(tmp_path):
    font = make_font(tmp_path)
    commands = rc.plan_commands(rc.parse_beats(SAMPLE), tmp_path / "out", None, None, font)
    beat1_vf = commands[1][commands[1].index("-vf") + 1]
    assert f"fontfile={font}" in beat1_vf


def test_main_missing_font_errors_clearly_and_dry_run_skips_check(tmp_path, capsys):
    script = str(write_script(tmp_path))
    missing = str(tmp_path / "nope.ttf")
    out = tmp_path / "out"
    code = rc.main(["--script", script, "--out", str(out), "--font", missing], FakeRunner())
    assert code == 1
    assert "--font" in capsys.readouterr().err
    assert not out.exists()
    assert rc.main(["--script", script, "--out", str(out), "--font", missing, "--dry-run"]) == 0
