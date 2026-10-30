"""Frozen evidence and offline browser/action proofs using small fixture copies only."""

import hashlib
import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

from rewardseal import audit, certify, manifest

ROOT = Path(__file__).resolve().parents[1]
STAMP = "2026-10-29T00:00:00+00:00"
MANIFEST = Path("results/manifest.json")
RECORD = "results/exposure/CycloneDX__cyclonedx-python-348-93d44b30.json"
CERT = "results/certificates/Algebra8__pyopenapi3-83-46d7abbd.json"


@pytest.fixture
def evidence(tmp_path):
    for name in (RECORD, CERT, "docs/claims.md"):
        target = tmp_path / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / name, target)
    return tmp_path


def freeze(root):
    return manifest.build(root, MANIFEST, STAMP)


def check(root, capsys):
    result = manifest.main(["verify", "--root", str(root)])
    return result, capsys.readouterr().out


def test_build_verify_and_report_totals(evidence, capsys):
    assert manifest.main(["build", "--root", str(evidence), "--fixed-time", STAMP]) == 0
    data = json.loads((evidence / MANIFEST).read_text())
    assert [file["path"] for file in data["files"]] == sorted((CERT, RECORD, "docs/claims.md"))
    assert data["repo_sha"] is None
    assert data["generated_utc"] == STAMP
    summary = audit.exposure_summary(evidence / "results/exposure")
    score = certify.score([certify.load_certificate(evidence / CERT)])
    assert all(data["totals"][key] == summary[key] for key in manifest.EXPOSURE_KEYS)
    assert data["totals"]["n"] == score["n"] == 1
    assert data["totals"]["certified"] == score["certified"]
    assert check(evidence, capsys)[0] == 0


def test_one_byte_change_names_file(evidence, capsys):
    freeze(evidence)
    path = evidence / "docs/claims.md"
    data = bytearray(path.read_bytes())
    data[0] ^= 1
    path.write_bytes(data)
    code, output = check(evidence, capsys)
    assert code == 1
    assert "hash changed: docs/claims.md" in output


def test_missing_and_extra_reported_together(evidence, capsys):
    freeze(evidence)
    # Rename a fixture created by this test; no existing project file is deleted.
    (evidence / "docs/claims.md").rename(evidence / "docs/renamed.md")
    extra = evidence / "results/exposure/extra.json"
    extra.write_text("{}")
    code, output = check(evidence, capsys)
    assert code == 1
    assert "missing file: docs/claims.md" in output
    assert "extra file: results/exposure/extra.json" in output
    assert "totals differ: cannot recompute" in output


@pytest.mark.parametrize("change", ["changed", "missing", "extra"])
def test_batch_changes_fail_verification(evidence, capsys, change):
    path = evidence / "results/batch.json"
    if change != "extra":
        path.write_text("{}\n")
    data = freeze(evidence)
    assert any(entry["path"] == "results/batch.json" for entry in data["files"]) == (change != "extra")
    if change == "missing":
        path.rename(path.with_suffix(".saved"))
    else:
        path.write_text('{"changed": true}\n')
    code, output = check(evidence, capsys)
    assert code == 1
    label = {"changed": "hash changed", "missing": "missing file", "extra": "extra file"}[change]
    assert f"{label}: results/batch.json" in output


def test_totals_mismatch(evidence, capsys):
    data = freeze(evidence)
    data["totals"]["N_fix"] += 1
    (evidence / MANIFEST).write_text(json.dumps(data))
    code, output = check(evidence, capsys)
    assert code == 1
    assert "totals differ: N_fix" in output


def test_changed_valid_record_recomputes_totals(evidence, capsys):
    freeze(evidence)
    path = evidence / RECORD
    record = json.loads(path.read_text())
    record["future_scan"]["gold_lines_in_future"] = 0
    record["fix_reachable"] = False
    record["fix_reachable_basis"] = audit.basis_text(0, 1)
    path.write_text(json.dumps(record))
    code, output = check(evidence, capsys)
    assert code == 1
    assert "hash changed: " + RECORD in output
    assert "totals differ: N_fix" in output
    assert "totals differ: N_full_overlap" in output


@pytest.mark.parametrize("kind", ["file", "directory", "optional-directory", "manifest"])
def test_symlinks_refused(evidence, kind, capsys):
    freeze(evidence)
    if kind == "file":
        (evidence / "results/evidence").mkdir()
        (evidence / "results/evidence/link.md").symlink_to(evidence / "docs/claims.md")
    elif kind == "directory":
        folder = evidence / "results/exposure"
        folder.rename(evidence / "results/saved-exposure")
        folder.symlink_to("saved-exposure", target_is_directory=True)
    elif kind == "optional-directory":
        (evidence / "results/web-exposure").symlink_to("absent", target_is_directory=True)
    else:
        (evidence / MANIFEST).rename(evidence / "results/saved-manifest.json")
        (evidence / MANIFEST).symlink_to("saved-manifest.json")
    code, output = check(evidence, capsys)
    assert code == 1 and "symlink refused" in output
    assert manifest.main(["build", "--root", str(evidence)]) == 1


def test_deterministic_build(evidence):
    freeze(evidence)
    first = (evidence / MANIFEST).read_bytes()
    freeze(evidence)
    assert (evidence / MANIFEST).read_bytes() == first
    manifest.build(evidence, MANIFEST)
    second = json.loads((evidence / MANIFEST).read_bytes())
    initial = json.loads(first)
    second.pop("generated_utc")
    initial.pop("generated_utc")
    assert second == initial


def test_coverage_optional_artifacts_old_and_page_text(evidence):
    added = (
        "results/exposure-sample/sample.json",
        "results/confirmations.json",
        "results/batch.json",
        "results/evidence/note.md",
        "results/replications/run.json",
        "results/ultra/run.json",
        "results/web-exposure/run.json",
        "results/replay-attempt/run.json",
        "results/diffs/task.before.diff.json",
        "results/combined.txt",
    )
    for name in added:
        path = evidence / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("{}\n")
    (evidence / "results/web-exposure/page.txt").write_text("never cover page text")
    (evidence / "results/certificates/previous.json.old").write_text("old")
    (evidence / "results/diffs/task.before.diff.json.old").write_text("old")
    (evidence / "results/diffs/plain.json").write_text("not a .diff.json file")
    data = freeze(evidence)
    paths = {entry["path"] for entry in data["files"]}
    assert paths == {CERT, RECORD, "docs/claims.md", *added}
    assert manifest.verify(evidence, MANIFEST) == []


def git(root, *args):
    subprocess.run(
        ["git", "-c", "user.name=t", "-c", "user.email=t@example.com", "-c", "commit.gpgsign=false", *args],
        cwd=root,
        check=True,
        capture_output=True,
    )


def test_repo_sha_is_null_when_covered_files_differ_from_head(evidence):
    git(evidence, "init", "-q")
    git(evidence, "add", "-A")
    git(evidence, "commit", "-q", "-m", "evidence")
    sha = freeze(evidence)["repo_sha"]
    assert sha and re.fullmatch(r"[0-9a-f]{40,64}", sha)
    (evidence / "README.md").write_text("not covered")  # untracked, outside coverage: HEAD still matches
    assert freeze(evidence)["repo_sha"] == sha
    claims = evidence / "docs/claims.md"
    claims.write_bytes(claims.read_bytes() + b"x")  # tracked covered file modified
    assert freeze(evidence)["repo_sha"] is None
    git(evidence, "checkout", "--", "docs/claims.md")
    assert freeze(evidence)["repo_sha"] == sha
    new = evidence / "results/replay-attempt/new.json"  # untracked covered file
    new.parent.mkdir(parents=True)
    new.write_text("{}\n")
    assert freeze(evidence)["repo_sha"] is None


@pytest.fixture
def committed(evidence):
    """A git checkout of the evidence with the ignore rules a dev checkout has, HEAD matching every covered file."""
    (evidence / ".gitignore").write_text(
        "results/ultra/\nresults/control/*.json\n.venv/\nruns/\n**/traces/\n*.old\n"
    )
    git(evidence, "init", "-q")
    git(evidence, "add", "-A")
    git(evidence, "commit", "-q", "-m", "evidence")
    return evidence


def test_repo_sha_counts_untracked_covered_file_whatever_the_user_config(committed):
    sha = freeze(committed)["repo_sha"]
    assert sha and re.fullmatch(r"[0-9a-f]{40,64}", sha)
    # This setting hides untracked files from a plain git status.
    git(committed, "config", "status.showUntrackedFiles", "no")
    new = committed / "results/replay-attempt/new.json"
    new.parent.mkdir(parents=True)
    new.write_text("{}\n")
    assert freeze(committed)["repo_sha"] is None


@pytest.mark.parametrize("name", ["results/ultra/new.json", "results/control/new.json"])
def test_repo_sha_counts_ignored_covered_file(committed, name):
    sha = freeze(committed)["repo_sha"]
    assert sha
    new = committed / name  # gitignored, so HEAD does not hold these bytes, yet build() hashes them
    new.parent.mkdir(parents=True, exist_ok=True)
    new.write_text("{}\n")
    assert name in {file["path"] for file in freeze(committed)["files"]}
    assert freeze(committed)["repo_sha"] is None


def test_repo_sha_ignores_local_folders_outside_coverage(committed):
    sha = freeze(committed)["repo_sha"]
    assert sha
    for name in (
        ".venv/lib/module.py",
        "runs/ledger.json",
        "results/traces/run.json",
        "results/exposure/traces/run.json",  # **/traces/ is ignored under a covered folder too
        "results/certificates/stale.old",
    ):
        local = committed / name
        local.parent.mkdir(parents=True, exist_ok=True)
        local.write_text("local only\n")
    assert freeze(committed)["repo_sha"] == sha


def test_git_unavailable_leaves_null(evidence, monkeypatch):
    def unavailable(*args, **kwargs):
        raise FileNotFoundError("git")

    monkeypatch.setattr(manifest.subprocess, "run", unavailable)
    assert freeze(evidence)["repo_sha"] is None


@pytest.mark.parametrize(
    "name", ["../outside.md", "/outside.md", "docs/../claims.md", "other/docs/claims.md"]
)
def test_untrusted_manifest_cannot_read_outside_coverage(evidence, name, capsys):
    data = freeze(evidence)
    data["files"][0]["path"] = name
    (evidence / MANIFEST).write_text(json.dumps(data))
    code, output = check(evidence, capsys)
    assert code == 1 and "invalid or duplicate evidence path" in output


def test_usage_exit_two():
    with pytest.raises(SystemExit) as exc:
        manifest.main(["build", "--unknown"])
    assert exc.value.code == 2


def test_html_wording_csp_and_safe_text():
    html = (ROOT / "docs/verify/index.html").read_text()
    script = (ROOT / "docs/verify/verify.js").read_text()
    css = (ROOT / "docs/verify/verify.css").read_text()
    assert "Verifies artifact integrity and calculations, not historical execution or security." in html
    assert "innerHTML" not in html + script
    assert not re.search(r"<script(?![^>]*\bsrc=)[^>]*>", html, re.IGNORECASE)
    assert not re.search(r"<style\b|\sstyle\s*=|\son\w+\s*=", html, re.IGNORECASE)
    assert '<script src="verify.js" defer></script>' in html
    assert '<link rel="stylesheet" href="verify.css">' in html
    assert (
        "default-src 'none'; script-src 'self'; style-src 'self'; connect-src https://raw.githubusercontent.com 'self'"
        in html
    )
    assert 'name="viewport"' in html and "table-layout: fixed" in css
    assert 'crypto.subtle.digest("SHA-256"' in script


# Execute the real external JavaScript with a tiny DOM and fixture-only fetch. No HTTP server or network.
NODE_HARNESS = r"""
const vm = require('node:vm');
const assert = require('node:assert/strict');
const input = JSON.parse(require('node:fs').readFileSync(0, 'utf8'));
class Element {
  constructor() { this.children = []; this.textContent = ''; this.disabled = false; }
  appendChild(child) { this.children.push(child); }
  replaceChildren() { this.children = []; }
  get lastChild() { return this.children.at(-1); }
  addEventListener() {}
}
const elements = Object.fromEntries(['verify', 'tamper', 'status', 'totals', 'files'].map(id => [id, new Element()]));
let fetches = 0;
const context = vm.createContext({
  document: {getElementById: id => elements[id], createElement: () => new Element()},
  window: {location: {href: 'https://example.test/verify.html'}},
  crypto: require('node:crypto').webcrypto, TextDecoder, URL, Uint8Array,
  fetch: async (url, options) => {
    fetches += 1;
    assert.equal(options.credentials, 'omit');
    assert.equal(options.redirect, 'error');
    if (!(url in input.responses)) throw new Error('Unexpected URL; network disabled: ' + url);
    const buffer = Buffer.from(input.responses[url], 'base64');
    return {ok: true, arrayBuffer: async () => buffer.buffer.slice(buffer.byteOffset, buffer.byteOffset + buffer.byteLength)};
  }
});
vm.runInContext(input.script, context);
(async () => {
  await vm.runInContext('verifyEvidence()', context);
  if (input.expectedFailure) {
    assert.match(elements.status.textContent, /^FAIL:/);
    assert.match(elements.totals.textContent, /Totals FAIL/);
    assert.match(elements.totals.textContent, new RegExp(input.expectedFailure + ": expected .* FAIL"));
    process.stdout.write('Mismatch detection passed');
    return;
  }
  assert.match(elements.status.textContent, /^OK:/);
  assert.match(elements.totals.textContent, /^Totals OK/);
  for (const [key, value] of Object.entries(input.totals)) {
    if (key === 'unknown_total') {
      assert.ok(elements.totals.textContent.includes(key + ': stored ' + value + ' — not recomputed in the browser'));
      assert.ok(elements.status.textContent.includes('Not recomputed in the browser: unknown_total.'));
    } else {
      assert.ok(elements.totals.textContent.includes(key + ': expected ' + value + ', actual ' + value + ' OK'));
      assert.ok(elements.status.textContent.includes(key));
    }
  }
  assert.equal(elements.files.children.length, input.fileCount);
  const initialFetches = fetches;
  await vm.runInContext('tamperDemo()', context);
  assert.equal(fetches, initialFetches, 'tamper must not fetch or upload');
  assert.match(elements.status.textContent, /^FAIL:/);
  assert.match(elements.totals.textContent, /Totals FAIL/);
  assert.equal(elements.files.children.filter(row => row.lastChild.textContent === 'FAIL').length, 1);
  await vm.runInContext('verifyEvidence()', context);
  assert.match(elements.status.textContent, /^OK:/);
  assert.match(elements.totals.textContent, /^Totals OK/);
  process.stdout.write('Browser verify, tamper, and reset passed');
})().catch(error => { console.error(error); process.exitCode = 1; });
"""


def run_browser(evidence, data, expected_failure=None):
    import base64

    node = shutil.which("node")
    if node is None:
        pytest.skip("Node is required for offline external-JavaScript execution")
    responses = {
        "https://example.test/manifest.json": base64.b64encode((evidence / MANIFEST).read_bytes()).decode()
    }
    for entry in data["files"]:
        responses["https://raw.githubusercontent.com/manishwvn/rewardseal/main/" + entry["path"]] = (
            base64.b64encode((evidence / entry["path"]).read_bytes()).decode()
        )
    result = subprocess.run(
        [node, "-e", NODE_HARNESS],
        input=json.dumps(
            {
                "script": (ROOT / "docs/verify/verify.js").read_text(),
                "responses": responses,
                "fileCount": len(data["files"]),
                "totals": data["totals"],
                "expectedFailure": expected_failure,
            }
        ),
        text=True,
        capture_output=True,
        check=False,
        timeout=30,
        cwd=evidence,
    )
    assert result.returncode == 0, result.stderr
    assert "passed" in result.stdout


@pytest.mark.parametrize("found,gold", [(1, 1), (2, 5), (3, 5), (5, 5), (0, 0)])
def test_browser_verification_and_memory_only_tamper(evidence, found, gold):
    path = evidence / RECORD
    record = json.loads(path.read_text())
    record["future_scan"].update(gold_added_lines=gold, gold_lines_in_future=found)
    record["fix_reachable"] = found >= max(1, (gold + 1) // 2)
    record["fix_reachable_basis"] = audit.basis_text(found, gold)
    path.write_text(json.dumps(record))
    data = freeze(evidence)
    run_browser(evidence, data)
    assert manifest.verify(evidence, MANIFEST) == []  # the real fixture bytes never changed


def test_missing_empty_gate_error_is_refused_by_python_and_not_counted_by_the_browser(evidence):
    certified = ROOT / "results/certificates/12rambau__sepal_ui-518.json"
    shutil.copyfile(certified, evidence / CERT)
    data = freeze(evidence)
    assert data["totals"]["certified"] == 1
    path = evidence / CERT
    cert = json.loads(path.read_text())
    for gates in (cert["harden"]["before"]["gates"], cert["gates"]["before"]):
        del gates["empty"]["error"]
    with pytest.raises(ValueError, match="gates.ok is true but"):
        certify.validate_certificate(cert)
    path.write_text(json.dumps(cert))
    entry = next(file for file in data["files"] if file["path"] == CERT)
    entry.update(sha256=hashlib.sha256(path.read_bytes()).hexdigest(), bytes=len(path.read_bytes()))
    # The bytes now match the manifest, so only the stored certified count (1) disagrees with the browser's count.
    (evidence / MANIFEST).write_text(json.dumps(data))
    run_browser(evidence, data, expected_failure="certified")


@pytest.mark.parametrize("key", [*manifest.EXPOSURE_KEYS, "n", "certified", "exposure_source"])
def test_browser_rejects_each_changed_stored_total(evidence, key):
    data = freeze(evidence)
    data["totals"][key] = "wrong" if key == "exposure_source" else data["totals"][key] + 1
    (evidence / MANIFEST).write_text(json.dumps(data))
    run_browser(evidence, data, expected_failure=key)


@pytest.mark.parametrize("mode", ["certificates", "none", "no-future", "not-closed", "unknown-total"])
def test_browser_fallback_closure_and_unchecked_labels(evidence, mode):
    if mode in ("certificates", "none"):
        (evidence / RECORD).rename(evidence / "results/exposure/saved.old")
        if mode == "certificates":
            shutil.copyfile(ROOT / "results/certificates/12rambau__sepal_ui-518.json", evidence / CERT)
    elif mode in ("no-future", "not-closed"):
        path = evidence / RECORD
        record = json.loads(path.read_text())
        if mode == "no-future":
            record["future_commits_before"] = 0
            record["future_scan"].update(commits_scanned=0, commit_ids=[], gold_lines_in_future=0)
            record["fix_reachable"] = False
            record["fix_reachable_basis"] = audit.basis_text(0, record["future_scan"]["gold_added_lines"])
        else:
            record["patch"]["applied"] = False
            record["closed"] = False
            record["closed_reason"] = "patch_not_applied"
        path.write_text(json.dumps(record))
    data = freeze(evidence)
    if mode == "unknown-total":
        data["totals"]["unknown_total"] = 123
        (evidence / MANIFEST).write_text(json.dumps(data))
    else:
        assert manifest.verify(evidence, MANIFEST) == []
    run_browser(evidence, data)


def action_steps():
    return yaml.safe_load((ROOT / ".github/actions/rewardseal-gate/action.yml").read_text())["runs"]["steps"]


def test_action_validation_and_report_with_defaults(evidence, monkeypatch, capsys):
    from rewardseal import cli

    steps = action_steps()
    script = next(step["run"] for step in steps if step.get("name") == "Validate every exposure record")
    python = script.split("<<'PY'\n", 1)[1].rsplit("\nPY", 1)[0]
    monkeypatch.chdir(evidence)
    monkeypatch.setenv("RECORDS_DIR", "results/exposure")
    exec(compile(python, "action-record-validation", "exec"), {})  # noqa: S102 - reviewed local action
    assert "Validated 1" in capsys.readouterr().out
    monkeypatch.setattr("rewardseal.envfile.load_env", lambda: False)  # never read a real .env
    assert cli.main(["report", "--certs", "results/certificates"]) == 0
    assert capsys.readouterr().out.strip()
    freeze(evidence)
    assert manifest.main(["verify"]) == 0
    for name in ("first.json", "second.json"):
        (evidence / "results/exposure" / name).write_text("{}")
    with pytest.raises(SystemExit) as exc:
        exec(compile(python, "action-record-validation", "exec"), {})  # noqa: S102 - reviewed local action
    assert "first.json" in str(exc.value) and "second.json" in str(exc.value)


def test_action_and_example_contract():
    action = yaml.safe_load((ROOT / ".github/actions/rewardseal-gate/action.yml").read_text())
    assert action["inputs"]["records-dir"]["default"] == "results/exposure"
    assert action["inputs"]["certs-dir"]["default"] == "results/certificates"
    steps = action["runs"]["steps"]
    uses = [step["uses"] for step in steps if "uses" in step]
    assert any(item.startswith("astral-sh/setup-uv@") for item in uses)
    assert any(item.startswith("actions/upload-artifact@") for item in uses)
    for name in (".github/actions/rewardseal-gate/action.yml", ".github/workflows/gate-example.yml"):
        for line in (ROOT / name).read_text().splitlines():
            if "uses:" in line and "./" not in line:
                assert re.search(r"@[0-9a-f]{40}\b", line), (
                    f"{name}: action not pinned to a commit SHA: {line}"
                )
    for step in steps:
        if "run" in step:
            assert step["shell"] == "bash"
            assert "${{ inputs." not in step["run"]  # inputs pass through env, not shell source
    example = yaml.safe_load((ROOT / ".github/workflows/gate-example.yml").read_text())
    assert set(example[True]) == {"workflow_dispatch"}  # YAML 1.1 parses 'on' as True
    assert example["permissions"] == {"contents": "read"}
    assert example["jobs"]["gate"]["steps"][-1]["uses"] == "./.github/actions/rewardseal-gate"


def test_pages_copy_step_keeps_frozen_manifest():
    workflow = yaml.safe_load((ROOT / ".github/workflows/pages.yml").read_text())
    steps = workflow["jobs"]["build"]["steps"]
    copy = next(
        step for step in steps if step.get("name") == "Copy the evidence verifier and frozen manifest"
    )
    assert "cp docs/verify/index.html results/site/verify.html" in copy["run"]
    assert "cp results/manifest.json results/site/manifest.json" in copy["run"]
    assert "cp docs/verify/verify.js results/site/verify.js" in copy["run"]
    assert "cp docs/verify/verify.css results/site/verify.css" in copy["run"]
    assert "manifest build" not in copy["run"]


def test_browser_verifier_accepts_every_path_in_the_committed_manifest():
    import re as _re

    script = (ROOT / "docs/verify/verify.js").read_text()
    pattern = _re.search(r"const covered = /(.*)/;", script).group(1).replace("\\/", "/")
    regex = _re.compile(pattern)
    manifest_files = json.loads((ROOT / "results/manifest.json").read_text())["files"]
    rejected = [f["path"] for f in manifest_files if not regex.fullmatch(f["path"])]
    assert rejected == []


def test_browser_verifier_allow_list_matches_python_coverage():
    script = (ROOT / "docs/verify/verify.js").read_text()
    pattern = re.search(r"const covered = /(.*)/;", script).group(1).replace("\\/", "/")
    regex = re.compile(pattern)
    paths = [
        "results/replay-attempt/CycloneDX__cyclonedx-python-348-replay1.json",
        "results/diffs/12rambau__sepal_ui-518.before.diff.json",
        "results/combined.txt",
    ]
    for name in paths:
        assert regex.fullmatch(name) and manifest._covered(name), name
    for name in (
        "results/PINNED_SHA",
        "results/diffs/plain.json",
        "results/diffs/a.diff.json.old",
        "results/diffs/../batch.json",
        "results/replay-attempt/nested/x.json",
        "results/combined.txt.old",
    ):
        assert not regex.fullmatch(name) and not manifest._covered(name), name
    live = manifest.evidence_files(ROOT, ROOT / "results/manifest.json")
    names = [path.relative_to(ROOT).as_posix() for path in live]
    assert set(paths) <= set(names)
    assert [name for name in names if not regex.fullmatch(name)] == []
