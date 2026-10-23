"""Guards for .github/workflows/pages.yml and the site it builds from committed data (queue T39).

The workflow is read as text (no YAML library is a dependency). The build test runs cheatproof.site on the committed
certificates into tmp_path; no model, network or paid call.
"""

import re
from pathlib import Path

from cheatproof.site import NO_TRANSCRIPT, build_site

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "pages.yml"
PINNED_USES = re.compile(r"^\s*-?\s*uses: \S+@[0-9a-f]{40} # v\d+$")


def _lines():
    return WORKFLOW.read_text(encoding="utf-8").splitlines()


def _job_block(name: str) -> str:
    """The text of one job, from its key under jobs: to the next job key or the end of the file."""
    text = WORKFLOW.read_text(encoding="utf-8")
    head = f"\n  {name}:\n"
    start = text.index(head) + len(head)
    match = re.search(r"^  \w+:\n", text[start:], flags=re.MULTILINE)
    return text[start : start + match.start()] if match else text[start:]


def test_triggers_are_push_to_main_and_manual_only():
    text = WORKFLOW.read_text(encoding="utf-8")
    assert re.search(
        r"^on:\n  push:\n    branches: \[main\]\n  workflow_dispatch:\n", text, flags=re.MULTILINE
    )
    assert "pull_request" not in text


def test_top_level_permissions_are_minimal():
    text = WORKFLOW.read_text(encoding="utf-8")
    top = re.search(r"^permissions:\n((?:  .+\n)+)", text, flags=re.MULTILINE)
    assert top is not None
    assert set(re.findall(r"^  (\w[\w-]*): (\w+)$", top.group(1), flags=re.MULTILINE)) == {
        ("contents", "read"),
        ("pages", "write"),
        ("id-token", "write"),
    }


def test_every_action_is_pinned_by_full_sha_with_a_version_comment():
    uses = [line for line in _lines() if line.strip().startswith(("- uses:", "uses:"))]
    assert len(uses) == 4  # checkout, setup-uv, upload-pages-artifact, deploy-pages
    for line in uses:
        assert PINNED_USES.match(line), line


def test_deploy_is_skipped_on_a_private_repo_and_fails_softly():
    deploy = _job_block("deploy")
    assert "if: ${{ !github.event.repository.private }}" in deploy
    assert "continue-on-error: true" in deploy
    assert "continue-on-error" not in _job_block("build")


def test_build_does_not_enable_pages_or_call_a_model():
    text = WORKFLOW.read_text(encoding="utf-8")
    assert "configure-pages" not in text
    assert "secrets." not in text
    assert "results/certificates" in text


def test_site_builds_every_committed_certificate_without_traces(tmp_path):
    certs = ROOT / "results" / "certificates"
    result = build_site(certs, tmp_path / "site", batch_file=ROOT / "results" / "batch.json")
    assert result.index.is_file()
    assert len(result.pages) == len(list(certs.glob("*.json")))
    for page in result.pages:
        assert NO_TRANSCRIPT in page.read_text(encoding="utf-8")
