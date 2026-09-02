"""Contract tests for the manual TestPyPI publishing workflow."""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest
import yaml  # type: ignore[import-untyped]

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
    assert "X.Y.ZrcN" in inputs["version"]["description"]
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


def test_testpypi_verify_validates_the_candidate_and_its_stable_base() -> None:
    """Confusing the disposable candidate with committed stable state must fail."""
    workflow = _workflow()
    verify = workflow["jobs"]["verify"]

    assert verify["timeout-minutes"] == "35"
    assert verify["permissions"] == {"contents": "read", "actions": "read"}
    assert verify["outputs"] == {
        "version": "${{ steps.candidate.outputs.version }}",
        "base_version": "${{ steps.candidate.outputs.base_version }}",
    }

    candidate = next(step for step in verify["steps"] if step.get("id") == "candidate")
    assert candidate["env"] == {"CANDIDATE": "${{ inputs.version }}"}
    assert "rc[1-9][0-9]*" in candidate["run"]

    release_check = next(
        step for step in verify["steps"] if "scripts/release_check.py" in step.get("run", "")
    )
    assert release_check["env"] == {"VERSION": "${{ steps.candidate.outputs.base_version }}"}
    assert release_check["run"] == 'python3 scripts/release_check.py --version "$VERSION"'

    verify_commands = "\n".join(step["run"] for step in verify["steps"] if "run" in step)
    assert "refs/heads/main" in verify_commands
    assert "uv lock --check" in verify_commands


@pytest.mark.skipif(sys.platform != "linux", reason="the workflow runs on ubuntu-latest")
def test_testpypi_stages_the_candidate_before_its_only_build(tmp_path: Path) -> None:
    """The workflow's shell steps reject stable input and build candidate artifacts."""
    workflow = _workflow()
    candidate = next(
        step for step in workflow["jobs"]["verify"]["steps"] if step.get("id") == "candidate"
    )
    build = workflow["jobs"]["build"]

    assert build["needs"] == "verify"
    build_commands = [step for step in build["steps"] if "run" in step]
    stage_index = next(
        index
        for index, step in enumerate(build_commands)
        if step.get("name") == "Stage the TestPyPI candidate"
    )
    build_index = next(
        index for index, step in enumerate(build_commands) if step["run"] == "uv build"
    )
    assert stage_index < build_index
    stage = build_commands[stage_index]
    assert stage["env"] == {
        "VERSION": "${{ needs.verify.outputs.version }}",
        "BASE_VERSION": "${{ needs.verify.outputs.base_version }}",
    }
    artifact_check = next(
        step for step in build_commands if "dist/pkcs11_check-$VERSION.tar.gz" in step["run"]
    )
    assert artifact_check["env"] == {"VERSION": "${{ needs.verify.outputs.version }}"}

    all_commands = "\n".join(
        step["run"] for job in workflow["jobs"].values() for step in job["steps"] if "run" in step
    )
    assert all_commands.count("uv build") == 1
    assert all("run" not in step for step in workflow["jobs"]["publish"]["steps"])

    repository = tmp_path / "repository"
    shutil.copytree(
        REPO_ROOT,
        repository,
        ignore=shutil.ignore_patterns(".git", ".venv", "__pycache__", "build", "data", "dist"),
    )
    output = tmp_path / "github-output"
    environment = {**os.environ, "CANDIDATE": "0.1.9", "GITHUB_OUTPUT": str(output)}
    invalid = subprocess.run(
        ["bash", "-e", "-c", candidate["run"]], cwd=repository, env=environment, check=False
    )
    assert invalid.returncode != 0

    environment["CANDIDATE"] = "0.1.9rc1"
    subprocess.run(
        ["bash", "-e", "-c", candidate["run"]], cwd=repository, env=environment, check=True
    )
    assert output.read_text(encoding="utf-8") == "version=0.1.9rc1\nbase_version=0.1.9\n"

    subprocess.run(
        ["bash", "-e", "-c", stage["run"]],
        cwd=repository,
        env={**os.environ, "VERSION": "0.1.9rc1", "BASE_VERSION": "0.1.9"},
        check=True,
    )
    subprocess.run(["uv", "build"], cwd=repository, check=True, capture_output=True)
    assert (repository / "dist/pkcs11_check-0.1.9rc1-py3-none-any.whl").is_file()
    assert (repository / "dist/pkcs11_check-0.1.9rc1.tar.gz").is_file()
