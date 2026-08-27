"""Contract tests for the manual TestPyPI publishing workflow."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
WORKFLOW_PATH = REPO_ROOT / ".github/workflows/publish-testpypi.yml"
DOWNLOAD_ARTIFACT_ACTION = (
    "actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c"  # v8
)
PYPI_PUBLISH_ACTION = (
    "pypa/gh-action-pypi-publish@dc37677b2e1c63e2034f94d8a5b11f265b73ba33"  # release/v1
)


def _workflow() -> dict[str, Any]:
    loaded = yaml.load(WORKFLOW_PATH.read_text(encoding="utf-8"), Loader=yaml.BaseLoader)
    assert isinstance(loaded, dict)
    return loaded


def test_testpypi_workflow_is_manual_only_and_cannot_publish_a_release() -> None:
    """Adding a push trigger, tag command, or production endpoint must break this guard."""
    workflow = _workflow()

    assert set(workflow["on"]) == {"workflow_dispatch"}
    assert workflow["permissions"] == {}
    assert set(workflow["jobs"]) == {"verify", "build", "publish"}
    inputs = workflow["on"]["workflow_dispatch"]["inputs"]
    assert inputs["version"]["required"] == "true"
    assert inputs["version"]["type"] == "string"
    assert inputs["dry_run"]["type"] == "boolean"
    assert inputs["dry_run"]["default"] == "true"

    source = WORKFLOW_PATH.read_text(encoding="utf-8")
    assert "git tag" not in source
    assert "gh release" not in source
    assert "upload.pypi.org" not in source
    assert "contents: write" not in source


def test_testpypi_upload_is_an_oidc_only_job_gated_by_dry_run() -> None:
    """Uploading without the TestPyPI environment, OIDC, or dry-run gate must fail."""
    workflow = _workflow()
    publish = workflow["jobs"]["publish"]

    assert publish["needs"] == ["verify", "build"]
    assert publish["if"] == "${{ !inputs.dry_run }}"
    assert publish["environment"] == {
        "name": "testpypi",
        "url": "https://test.pypi.org/p/pkcs11-check",
    }
    assert publish["permissions"] == {"id-token": "write"}

    assert publish["steps"][0]["uses"] == DOWNLOAD_ARTIFACT_ACTION
    upload_steps = [step for step in publish["steps"] if step.get("uses") == PYPI_PUBLISH_ACTION]
    assert len(upload_steps) == 1
    assert upload_steps[0]["with"] == {
        "repository-url": "https://test.pypi.org/legacy/",
    }
    assert all("run" not in step for step in publish["steps"])

    oidc_jobs = {
        name
        for name, job in workflow["jobs"].items()
        if job.get("permissions", {}).get("id-token") == "write"
    }
    assert oidc_jobs == {"publish"}


def test_testpypi_workflow_builds_once_after_release_safety_checks() -> None:
    """Removing main/CI/version gates or rebuilding in the privileged job must fail."""
    workflow = _workflow()
    verify = workflow["jobs"]["verify"]
    build = workflow["jobs"]["build"]

    assert verify["permissions"] == {"contents": "read", "actions": "read"}
    verify_commands = "\n".join(step["run"] for step in verify["steps"] if "run" in step)
    assert "refs/heads/main" in verify_commands
    assert "scripts/release_check.py --version" in verify_commands
    assert "uv lock --check" in verify_commands
    assert "actions/runs?head_sha=$GITHUB_SHA" in verify_commands

    assert build["needs"] == "verify"
    all_commands = "\n".join(
        step["run"] for job in workflow["jobs"].values() for step in job["steps"] if "run" in step
    )
    assert all_commands.count("uv build") == 1
    assert all("run" not in step for step in workflow["jobs"]["publish"]["steps"])
