"""Automated rough cut of the demo video from the beat table in docs/video/script.md.

Per beat: a macOS `say` voice-over (AIFF), a visual (a screenshot named beatNN.*, else an ffmpeg colour card with
the On-screen text as a drawtext title), and a timed segment. All segments join in one ffmpeg concat, and an SRT
file carries the Caption column. Subprocess calls go through one injectable runner; `--dry-run` prints them only.

Output: rough_cut.mp4 and rough_cut.srt under the output dir. With no --out the dir is a fresh temp dir; a
default temp dir inside this repo is refused. An explicit --out may be anywhere, except that its path must
not contain ' or \\ (ffmpeg parses the -vf string twice). Title cards need --font (default Helvetica) unless
every beat has a screenshot; a missing font fails before any command runs.

    uv run python video/rough_cut.py --dry-run
    uv run python video/rough_cut.py --shots DIR --out DIR
"""

from __future__ import annotations

import argparse
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import textwrap
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT_PATH = REPO_ROOT / "docs" / "video" / "script.md"
LIMIT_SECONDS = 170  # the video must stay under 2:50
WIDTH, HEIGHT, FPS = 1280, 720, 30
BACKGROUND = "0x1d2330"
FONT = "/System/Library/Fonts/Helvetica.ttc"
WORDS_PER_SECOND = 2.6  # rough speaking rate, used only to warn about overrun
SHOT_EXTS = (".png", ".jpg", ".jpeg")
HEADING = "## Beat table"
PLACEHOLDER = re.compile(r"\[(?:RESULT|PLACEHOLDER):[^\]]*\]")
TIME = re.compile(r"^(\d+):([0-5]\d)$")
STILL_VF = (
    f"scale={WIDTH}:{HEIGHT}:force_original_aspect_ratio=decrease,"
    f"pad={WIDTH}:{HEIGHT}:(ow-iw)/2:(oh-ih)/2,setsar=1,format=yuv420p"
)

Runner = Callable[[Sequence[str]], object]


class ScriptError(ValueError):
    """The beat table is malformed, or the video is too long."""


@dataclass(frozen=True)
class Beat:
    number: int  # 1-based
    start: int  # seconds
    duration: int  # seconds
    on_screen: str
    voice_over: str
    caption: str


@dataclass(frozen=True)
class RoughCut:
    beats: tuple[Beat, ...]
    total_seconds: int
    commands: tuple[tuple[str, ...], ...]
    out_dir: Path
    warnings: tuple[str, ...]
    placeholders: int


def clock(seconds: int) -> str:
    return f"{seconds // 60}:{seconds % 60:02d}"


def parse_beats(text: str) -> list[Beat]:
    """Read the table under the '## Beat table' heading. Beats must be contiguous from 0:00."""
    lines = text.splitlines()
    if HEADING not in lines:
        raise ScriptError(f"no '{HEADING}' heading in script")
    rows: list[list[str]] = []
    for line in lines[lines.index(HEADING) + 1 :]:
        stripped = line.strip()
        if not stripped.startswith("|"):
            if rows:
                break
            continue
        rows.append([cell.strip() for cell in stripped.strip("|").split("|")])
    if len(rows) < 3 or rows[0] != ["Start", "Dur (s)", "On-screen", "Voice-over", "Caption"]:
        raise ScriptError("beat table needs the header: Start | Dur (s) | On-screen | Voice-over | Caption")
    if not all(set(cell) <= set("-: ") and cell for cell in rows[1]):
        raise ScriptError("beat table needs a separator row after the header")

    beats: list[Beat] = []
    expected = 0
    for cells in rows[2:]:
        number = len(beats) + 1
        if len(cells) != 5:
            raise ScriptError(f"beat {number}: need 5 cells, got {len(cells)}")
        match = TIME.match(cells[0])
        if match is None:
            raise ScriptError(f"beat {number}: start {cells[0]!r} is not m:ss")
        start = int(match[1]) * 60 + int(match[2])
        if not cells[1].isdigit() or int(cells[1]) <= 0:
            raise ScriptError(f"beat {number}: duration {cells[1]!r} is not a positive integer")
        if not all(cells[2:]):
            raise ScriptError(f"beat {number}: on-screen, voice-over and caption must not be empty")
        if start != expected:
            raise ScriptError(
                f"beat {number}: starts at {cells[0]} but previous beat ends at {clock(expected)}"
            )
        duration = int(cells[1])
        beats.append(Beat(number, start, duration, cells[2], cells[3], cells[4]))
        expected = start + duration
    if not beats:
        raise ScriptError("beat table has no rows")
    return beats


def total_seconds(beats: Sequence[Beat]) -> int:
    return sum(beat.duration for beat in beats)


def check_total(beats: Sequence[Beat], limit: int = LIMIT_SECONDS) -> int:
    """Fail loudly unless the planned total is under `limit` seconds."""
    total = total_seconds(beats)
    if total >= limit:
        raise ScriptError(
            f"script totals {total} s ({clock(total)}); must be under {limit} s ({clock(limit)})"
        )
    return total


def srt_timestamp(seconds: float) -> str:
    """SRT time: HH:MM:SS,mmm."""
    total_ms = round(seconds * 1000)
    hours, rest = divmod(total_ms, 3_600_000)
    minutes, rest = divmod(rest, 60_000)
    secs, millis = divmod(rest, 1000)
    return f"{hours:02d}:{minutes:02d}:{secs:02d},{millis:03d}"


def build_srt(beats: Sequence[Beat]) -> str:
    blocks = []
    for beat in beats:
        start = srt_timestamp(beat.start)
        end = srt_timestamp(beat.start + beat.duration)
        blocks.append(f"{beat.number}\n{start} --> {end}\n{beat.caption}\n")
    return "\n".join(blocks)


def speech_seconds(text: str) -> float:
    return len(text.split()) / WORDS_PER_SECOND


def overrun_warnings(beats: Sequence[Beat]) -> list[str]:
    return [
        f"beat {beat.number}: voice-over needs about {speech_seconds(beat.voice_over):.0f} s,"
        f" beat is {beat.duration} s; audio will be cut"
        for beat in beats
        if speech_seconds(beat.voice_over) > beat.duration
    ]


def count_placeholders(beats: Sequence[Beat]) -> int:
    return sum(
        len(PLACEHOLDER.findall(field))
        for beat in beats
        for field in (beat.on_screen, beat.voice_over, beat.caption)
    )


def drawtext_escape(value: str) -> str:
    """Escape a path for an ffmpeg drawtext option (filtergraph and option syntax)."""
    for char in ("\\", ":", "'", "%", ",", ";", "[", "]"):
        value = value.replace(char, "\\" + char)
    return value


def check_out_path(out: Path) -> Path:
    """Refuse a path with ' or \\: ffmpeg parses the -vf string twice, so those cannot be escaped reliably."""
    text = str(out)
    if "'" in text or "\\" in text:
        raise ScriptError(f"output path {text!r} has ' or \\; pick a folder name without them")
    return out


def say_command(text: str, aiff: Path, voice: str | None) -> list[str]:
    """`--` ends option parsing, so a voice-over that starts with '-' is spoken, not read as a flag."""
    command = ["say"]
    if voice:
        command += ["-v", voice]
    return [*command, "-o", str(aiff), "--", text]


def find_shot(shots_dir: Path | None, number: int) -> Path | None:
    if shots_dir is None:
        return None
    for path in sorted(shots_dir.glob(f"beat{number:02d}.*")):
        if path.suffix.lower() in SHOT_EXTS:
            return path
    return None


def card_text(on_screen: str) -> str:
    """The On-screen text wrapped to lines, written to a text file that drawtext reads with expansion=none."""
    return "\n".join(textwrap.wrap(on_screen, 40) or [" "])


def card_filter(text_file: Path, font: Path = Path(FONT)) -> str:
    """Title card: the text file, centred, white on the background colour. expansion=none keeps % literal."""
    return (
        f"drawtext=fontfile={drawtext_escape(str(font))}:textfile={drawtext_escape(str(text_file))}"
        ":expansion=none:fontcolor=white:fontsize=44"
        ":line_spacing=12:x=(w-text_w)/2:y=(h-text_h)/2,format=yuv420p"
    )


def segment_command(visual: Sequence[str], audio: Path, duration: int, out: Path, vf: str) -> list[str]:
    """One beat: the visual input, then the voice-over. Audio is padded then cut to the beat length."""
    return [
        "ffmpeg",
        "-y",
        *visual,
        "-i",
        str(audio),
        "-map",
        "0:v:0",
        "-map",
        "1:a:0",
        "-vf",
        vf,
        "-af",
        "apad",
        "-t",
        str(duration),
        "-r",
        str(FPS),
        "-c:v",
        "libx264",
        "-pix_fmt",
        "yuv420p",
        "-c:a",
        "aac",
        str(out),
    ]


def concat_command(segments: Sequence[Path], out: Path) -> list[str]:
    command = ["ffmpeg", "-y"]
    for segment in segments:
        command += ["-i", str(segment)]
    pairs = "".join(f"[{index}:v:0][{index}:a:0]" for index in range(len(segments)))
    graph = f"{pairs}concat=n={len(segments)}:v=1:a=1[v][a]"
    return [
        *command,
        "-filter_complex",
        graph,
        "-map",
        "[v]",
        "-map",
        "[a]",
        "-c:v",
        "libx264",
        "-pix_fmt",
        "yuv420p",
        "-c:a",
        "aac",
        str(out),
    ]


def card_file(work: Path, number: int) -> Path:
    return work / f"beat{number:02d}.txt"


def plan_commands(
    beats: Sequence[Beat],
    out_dir: Path,
    shots_dir: Path | None,
    voice: str | None,
    font: Path = Path(FONT),
) -> list[tuple[str, ...]]:
    work = out_dir / "work"
    commands: list[tuple[str, ...]] = []
    segments: list[Path] = []
    for beat in beats:
        aiff = work / f"beat{beat.number:02d}.aiff"
        segment = work / f"beat{beat.number:02d}.mp4"
        commands.append(tuple(say_command(beat.voice_over, aiff, voice)))
        shot = find_shot(shots_dir, beat.number)
        if shot is not None:
            visual, vf = ["-loop", "1", "-i", str(shot)], STILL_VF
        else:
            visual = ["-f", "lavfi", "-i", f"color=c={BACKGROUND}:s={WIDTH}x{HEIGHT}:r={FPS}"]
            vf = card_filter(card_file(work, beat.number), font)
        commands.append(tuple(segment_command(visual, aiff, beat.duration, segment, vf)))
        segments.append(segment)
    commands.append(tuple(concat_command(segments, out_dir / "rough_cut.mp4")))
    return commands


def default_out_dir(dry_run: bool) -> Path:
    """A temp dir outside the repo. Refuses a temp dir inside the repo (use --out for that).

    The check runs on the temp base before any mkdtemp, so a refused run creates nothing.
    """
    base = Path(tempfile.gettempdir())
    if base.resolve().is_relative_to(REPO_ROOT):
        raise ScriptError(f"default output under {base} is inside the repo; pass --out to choose a folder")
    check_out_path(base)
    if dry_run:
        return base / "cheatproof-rough-cut"
    return Path(tempfile.mkdtemp(prefix="cheatproof-rough-cut-", dir=base))


def make_rough_cut(
    script_path: Path,
    out_dir: Path,
    *,
    shots_dir: Path | None = None,
    voice: str | None = None,
    dry_run: bool = False,
    runner: Runner | None = None,
    font: Path = Path(FONT),
) -> RoughCut:
    """Plan the cut; unless dry_run, check the font, write the SRT and run every command through `runner`."""
    beats = parse_beats(script_path.read_text(encoding="utf-8"))
    total = check_total(beats)
    commands = plan_commands(beats, out_dir, shots_dir, voice, font)
    cut = RoughCut(
        beats=tuple(beats),
        total_seconds=total,
        commands=tuple(commands),
        out_dir=out_dir,
        warnings=tuple(overrun_warnings(beats)),
        placeholders=count_placeholders(beats),
    )
    if dry_run:
        return cut
    if runner is None:
        raise ValueError("a runner is required unless dry_run is set")
    needs_font = any(find_shot(shots_dir, beat.number) is None for beat in beats)
    if needs_font and not font.is_file():
        raise ScriptError(f"font file not found: {font}; pass --font with a .ttf/.ttc path")
    work = out_dir / "work"
    work.mkdir(parents=True, exist_ok=True)
    for beat in beats:
        card_file(work, beat.number).write_text(card_text(beat.on_screen), encoding="utf-8")
    (out_dir / "rough_cut.srt").write_text(build_srt(beats), encoding="utf-8")
    for command in commands:
        runner(command)
    return cut


def run_subprocess(command: Sequence[str]) -> None:
    subprocess.run(list(command), check=True)


def main(argv: Sequence[str] | None = None, runner: Runner | None = None) -> int:
    parser = argparse.ArgumentParser(description="Build the rough cut of the demo video.")
    parser.add_argument(
        "--script", type=Path, default=SCRIPT_PATH, help="beat table (default: docs/video/script.md)"
    )
    parser.add_argument(
        "--out", type=Path, default=None, help="output dir (default: a temp dir outside the repo)"
    )
    parser.add_argument("--shots", type=Path, default=None, help="folder with beatNN.png/.jpg screenshots")
    parser.add_argument("--voice", default=None, help="macOS say voice (default: system voice)")
    parser.add_argument(
        "--font", type=Path, default=Path(FONT), help=f"font for title cards (default: {FONT})"
    )
    parser.add_argument("--dry-run", action="store_true", help="print the commands; run and write nothing")
    args = parser.parse_args(argv)
    try:
        out_dir = (
            check_out_path(args.out.expanduser().resolve()) if args.out else default_out_dir(args.dry_run)
        )
        if not args.dry_run and runner is None:
            missing = [tool for tool in ("say", "ffmpeg") if shutil.which(tool) is None]
            if missing:
                raise ScriptError(f"missing tool(s): {', '.join(missing)}")
        cut = make_rough_cut(
            args.script,
            out_dir,
            shots_dir=args.shots,
            voice=args.voice,
            dry_run=args.dry_run,
            runner=runner or run_subprocess,
            font=args.font.expanduser(),
        )
    except (ScriptError, OSError) as error:
        print(f"rough_cut: {error}", file=sys.stderr)
        return 1
    for warning in cut.warnings:
        print(f"warning: {warning}", file=sys.stderr)
    if cut.placeholders:
        print(f"warning: {cut.placeholders} placeholder(s) left in the script", file=sys.stderr)
    if args.dry_run:
        for command in cut.commands:
            print(shlex.join(command))
        print(f"# total {clock(cut.total_seconds)} ({cut.total_seconds} s), out {out_dir}, nothing run")
    else:
        print(f"rough cut: {out_dir / 'rough_cut.mp4'} ({clock(cut.total_seconds)})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
