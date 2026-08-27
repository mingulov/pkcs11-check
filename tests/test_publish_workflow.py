"""Contract tests for the manual production publishing workflow."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any, cast

import pytest
import yaml  # type: ignore[import-untyped]

REPO_ROOT = Path(__file__).resolve().parents[1]
WORKFLOW_PATH = REPO_ROOT / ".github/workflows/publish.yml"
TESTPYPI_WORKFLOW_PATH = REPO_ROOT / ".github/workflows/publish-testpypi.yml"
DOWNLOAD_ARTIFACT_ACTION = "actions/download-artifact"
PYPI_PUBLISH_ACTION = "pypa/gh-action-pypi-publish"


def _workflow(path: Path = WORKFLOW_PATH) -> dict[str, Any]:
    loaded = yaml.load(path.read_text(encoding="utf-8"), Loader=yaml.BaseLoader)
    assert isinstance(loaded, dict)
    return loaded


def _assert_publish_action_pins_match_testpypi(
    production: dict[str, Any], testpypi: dict[str, Any]
) -> None:
    for action in (DOWNLOAD_ARTIFACT_ACTION, PYPI_PUBLISH_ACTION):
        production_step = _publish_action_step(production, action)
        testpypi_step = _publish_action_step(testpypi, action)
        assert production_step["uses"] == testpypi_step["uses"]


def _publish_action_step(workflow: dict[str, Any], action: str) -> dict[str, Any]:
    matches = [
        step
        for step in workflow["jobs"]["publish"]["steps"]
        if step.get("uses", "").startswith(f"{action}@")
    ]
    assert len(matches) == 1
    ref = matches[0]["uses"].removeprefix(f"{action}@")
    assert re.fullmatch(r"[0-9a-f]{40}", ref)
    return cast(dict[str, Any], matches[0])


@pytest.mark.parametrize("path", [WORKFLOW_PATH, TESTPYPI_WORKFLOW_PATH])
def test_publish_verify_is_bounded_and_waits_for_the_exact_ci_condition(path: Path) -> None:
    """Both publishers wait for the exact push CI run through GitHub's CLI."""
    verify = _workflow(path)["jobs"]["verify"]

    assert verify["timeout-minutes"] == "35"
    assert verify["permissions"] == {"contents": "read", "actions": "read"}
    gate = next(
        step for step in verify["steps"] if step.get("name") == "Require green CI on this commit"
    )
    assert gate["env"] == {"GH_TOKEN": "${{ github.token }}"}
    command = gate["run"]
    assert "for _ in {1..12}" in command
    assert "sleep 10" in command
    for argument in (
        "gh run list",
        "--workflow ci.yml",
        '--commit "$GITHUB_SHA"',
        '--branch "$GITHUB_REF_NAME"',
        "--event push",
        "gh run watch",
        "--exit-status",
    ):
        assert argument in command


def test_release_keeps_stable_version_build_and_manual_dry_run_boundaries() -> None:
    """Candidate staging or bypassing the stable manual release sequence must fail."""
    workflow = _workflow()
    verify = workflow["jobs"]["verify"]
    build = workflow["jobs"]["build"]

    assert set(workflow["on"]) == {"workflow_dispatch"}
    assert workflow["permissions"] == {}
    assert workflow["on"]["workflow_dispatch"]["inputs"]["dry_run"]["default"] == "true"
    assert verify["outputs"] == {"version": "${{ steps.normalize.outputs.version }}"}

    release_check = next(
        step for step in verify["steps"] if "scripts/release_check.py" in step.get("run", "")
    )
    assert release_check["env"] == {"VERSION": "${{ steps.normalize.outputs.version }}"}
    assert "--notes-out release-notes.md" in release_check["run"]
    verify_commands = "\n".join(step["run"] for step in verify["steps"] if "run" in step)
    assert "refs/heads/main" in verify_commands
    assert build["needs"] == "verify"

    all_commands = "\n".join(
        step["run"] for job in workflow["jobs"].values() for step in job["steps"] if "run" in step
    )
    assert all_commands.count("uv build") == 1
    for job_name in ("tag", "publish", "github-release"):
        assert workflow["jobs"][job_name]["if"] == "${{ !inputs.dry_run }}"


def test_production_upload_is_oidc_only_and_uses_reviewed_action_pins() -> None:
    """Mutable publish actions or broader credentials in the PyPI job must fail."""
    workflow = _workflow()
    testpypi = _workflow(TESTPYPI_WORKFLOW_PATH)
    publish = workflow["jobs"]["publish"]

    assert publish["environment"] == {
        "name": "pypi",
        "url": "https://pypi.org/p/pkcs11-check",
    }
    assert publish["permissions"] == {"id-token": "write"}
    _assert_publish_action_pins_match_testpypi(workflow, testpypi)
    upload_step = _publish_action_step(workflow, PYPI_PUBLISH_ACTION)
    assert upload_step["with"] == {"skip-existing": "true"}
    assert all("run" not in step for step in publish["steps"])

    oidc_jobs = {
        name
        for name, job in workflow["jobs"].items()
        if job.get("permissions", {}).get("id-token") == "write"
    }
    assert oidc_jobs == {"publish"}
