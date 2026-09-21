"""Contract tests for the post-TestPyPI validation gate workflow."""

from __future__ import annotations

import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest
import yaml  # type: ignore[import-untyped]

REPO_ROOT = Path(__file__).resolve().parents[1]
WORKFLOW_PATH = REPO_ROOT / ".github/workflows/testpypi-gate.yml"

# Pinned action majors: checkout/upload-artifact track the sibling workflows;
# setup-python is gate-only (siblings provision Python via astral-sh/setup-uv).
_CHECKOUT_ACTION = "actions/checkout@v6"
_SETUP_PYTHON_ACTION = "actions/setup-python@v5"
_UPLOAD_ARTIFACT_ACTION = "actions/upload-artifact@v7"

# GitHub expressions are substituted before bash runs; stub them so `bash -n`
# sees only the shell the runner will execute.
_EXPRESSION = re.compile(r"\$\{\{.*?\}\}")


def _workflow() -> dict[str, Any]:
    loaded = yaml.load(WORKFLOW_PATH.read_text(encoding="utf-8"), Loader=yaml.BaseLoader)
    assert isinstance(loaded, dict)
    return loaded


def _steps(job: dict[str, Any]) -> list[dict[str, Any]]:
    steps = job["steps"]
    assert isinstance(steps, list) and steps
    return steps


def _step_index(steps: list[dict[str, Any]], needle: str) -> int:
    for index, step in enumerate(steps):
        if needle in str(step.get("name", "")) or needle in str(step.get("uses", "")):
            return index
    names = [str(step.get("name", step.get("uses", "<unnamed>"))) for step in steps]
    raise AssertionError(f"gate stage {needle!r} is missing; steps are: {names}")


def _run_of(steps: list[dict[str, Any]], needle: str) -> str:
    """The `run:` body of the step matching `needle`.

    Assertion strings must be scoped to their own step: a file-wide match
    would still pass if the assertion drifted into an `always()` step.
    """
    for step in steps:
        if needle in str(step.get("name", "")):
            assert "run" in step, f"gate stage {needle!r} has no run: block"
            return str(step["run"])
    raise AssertionError(f"gate stage {needle!r} is missing")


def test_gate_triggers_after_each_testpypi_publish_and_manually() -> None:
    """Losing the automatic leg or a manual leg must break this guard."""
    workflow = _workflow()

    assert set(workflow["on"]) == {"workflow_run", "workflow_dispatch", "workflow_call"}
    run = workflow["on"]["workflow_run"]
    assert run["workflows"] == ["TestPyPI"]
    assert run["types"] == ["completed"]
    # The trigger name must match the actual publish workflow: an upstream
    # rename would silently stop the gate from ever firing while staying green.
    publish = yaml.load(
        (REPO_ROOT / ".github/workflows/publish-testpypi.yml").read_text(encoding="utf-8"),
        Loader=yaml.BaseLoader,
    )
    assert publish["name"] == run["workflows"][0]
    for trigger in ("workflow_dispatch", "workflow_call"):
        version_input = workflow["on"][trigger]["inputs"]["version"]
        assert version_input["required"] == "false"
        assert version_input["type"] == "string"
        assert "latest on TestPyPI" in version_input["description"]


def test_gate_matrix_covers_every_os_and_artifact() -> None:
    """Dropping an OS or an artifact kind must break this guard."""
    workflow = _workflow()

    assert set(workflow["jobs"]) == {"validate"}
    job = workflow["jobs"]["validate"]
    assert job["runs-on"] == "${{ matrix.os }}"
    assert job["strategy"]["fail-fast"] == "false"
    assert job["strategy"]["matrix"]["os"] == ["ubuntu-latest", "windows-latest", "macos-latest"]
    assert job["strategy"]["matrix"]["artifact"] == ["wheel", "sdist"]
    # No silent leg-dropping: exclude/include could shrink the matrix unseen.
    assert "exclude" not in job["strategy"]["matrix"]
    assert "include" not in job["strategy"]["matrix"]


def test_gate_is_read_only_and_can_never_publish() -> None:
    """Any publish/tag/release capability in the gate must break this guard."""
    workflow = _workflow()

    assert workflow["permissions"] == {"contents": "read"}
    source = WORKFLOW_PATH.read_text(encoding="utf-8")
    assert "contents: write" not in source
    assert "id-token" not in source
    assert "git tag" not in source
    assert "gh release" not in source
    assert "pypi-publish" not in source
    assert "upload.pypi.org" not in source

    # The automatic leg only validates successful publish runs; manual legs run.
    # Pinned exactly: a substring check would pass inverted `!= success` logic.
    job = workflow["jobs"]["validate"]
    assert job["if"] == (
        "${{ github.event_name != 'workflow_run'"
        " || github.event.workflow_run.conclusion == 'success' }}"
    )

    uses = [step.get("uses", "") for step in _steps(job)]
    assert _CHECKOUT_ACTION in uses
    assert _SETUP_PYTHON_ACTION in uses
    assert _UPLOAD_ARTIFACT_ACTION in uses


def test_gate_runs_install_version_doctor_fetch_smoke_report_in_order() -> None:
    """Reordering or dropping a gate stage must break this guard."""
    job = _workflow()["jobs"]["validate"]
    steps = _steps(job)

    order = [
        _step_index(steps, needle)
        for needle in (
            "Resolve candidate version",
            "Install ${{ matrix.artifact }} from TestPyPI",
            "Version check",
            "Entry-point check",
            "Published-artifact meta-tests",
            "Install SoftHSM2",
            "doctor (pre-fetch)",
            "Fetch vectors",
            "doctor (post-fetch)",
            "Smoke (installed package)",
            "Vector slice (fetch-then-test proof)",
            "Report",
            "Summarize",
            _UPLOAD_ARTIFACT_ACTION,
        )
    ]
    assert order == sorted(order), [steps[i].get("name", steps[i].get("uses")) for i in order]

    commands = "\n".join(step["run"] for step in steps if "run" in step)
    # Wheel and sdist legs force their artifact kind off TestPyPI (deps from PyPI).
    assert "--only-binary=pkcs11-check" in commands
    assert "--no-binary=pkcs11-check" in commands
    assert "--index-url https://test.pypi.org/simple/" in commands
    assert "--extra-index-url https://pypi.org/simple/" in commands
    # Fresh 3.12 (the oldest supported interpreter) on every OS.
    setup = next(step for step in steps if step.get("uses") == _SETUP_PYTHON_ACTION)
    assert setup["with"] == {"python-version": "3.12"}
    # One SoftHSM provisioning per OS, each writing the same P11_* contract.
    providers = [step for step in steps if "Install SoftHSM2" in str(step.get("name", ""))]
    assert sorted(step["if"] for step in providers) == [
        "runner.os == 'Linux'",
        "runner.os == 'Windows'",
        "runner.os == 'macOS'",
    ]
    doctor_pre = _step_index(steps, "doctor (pre-fetch)")
    for step in providers:
        for var in ("P11_MODULE=", "P11_SLOT=", "P11_PIN=1234", "SOFTHSM2_CONF="):
            assert var in step["run"], f"{step.get('name')}: missing {var}"
        assert steps.index(step) < doctor_pre, f"{step.get('name')}: must precede doctor"
    # The TestPyPI version lookup is network I/O: it must be bounded so a hung
    # index cannot stall every leg up to the job timeout.
    resolve = next(step for step in steps if step.get("name") == "Resolve candidate version")
    assert "timeout=" in resolve["run"]
    # The smoke and vector summaries must prove execution, not empty green —
    # scoped to their own steps so drifting into an always() step still fails.
    for needle in ("Smoke (installed package)", "Vector slice (fetch-then-test proof)"):
        run_body = _run_of(steps, needle)
        assert 'summary["passed"] > 0' in run_body, needle
        assert 'summary["failed"] == 0' in run_body, needle


def _find_gnu_bash() -> str | None:
    """First `bash` that is really GNU bash, not the WSL launcher stub.

    On Windows `shutil.which("bash")` can resolve to the System32 WSL stub,
    which exits 1 with its complaint on stdout. Probe every candidate with
    `bash --version` and require the GNU banner, trying the Git for Windows
    paths when PATH resolution fails the probe.
    """
    candidates = [
        shutil.which("bash"),
        r"C:\Program Files\Git\bin\bash.exe",
        r"C:\Program Files\Git\usr\bin\bash.exe",
    ]
    for candidate in candidates:
        if candidate is None:
            continue
        try:
            probed = subprocess.run(
                [candidate, "--version"],
                capture_output=True,
                text=True,
                encoding="utf-8",
                timeout=30,
                check=False,
            )
        except OSError:
            continue
        if probed.returncode == 0 and "GNU bash" in probed.stdout:
            return candidate
    return None


@pytest.mark.skipif(shutil.which("bash") is None, reason="gate scripts are bash")
def test_gate_inline_bash_scripts_parse(tmp_path: Path) -> None:
    """Every bash `run:` block must be syntactically valid shell."""
    job = _workflow()["jobs"]["validate"]
    default_shell = job["defaults"]["run"]["shell"]
    assert default_shell == "bash"
    scripts = [
        (str(step.get("name", "<unnamed>")), step["run"])
        for step in _steps(job)
        if "run" in step and step.get("shell", default_shell) == "bash"
    ]
    assert len(scripts) >= 10
    # Every run: block must use a syntax-checked shell; a third shell would
    # otherwise slip through with zero validation.
    shells = {str(step.get("shell", default_shell)) for step in _steps(job) if "run" in step}
    assert shells <= {"bash", "pwsh"}, shells
    bash = _find_gnu_bash()
    if bash is None:
        pytest.skip("no GNU bash available")
    for name, script in scripts:
        stubbed = _EXPRESSION.sub("__GATE_EXPR__", script)
        probe = tmp_path / "probe.sh"
        probe.write_text(stubbed, encoding="utf-8", newline="\n")
        checked = subprocess.run(
            [bash, "-n", str(probe)],
            capture_output=True,
            text=True,
            encoding="utf-8",
            check=False,
        )
        assert checked.returncode == 0, f"{name}: {checked.stdout}{checked.stderr}"


@pytest.mark.skipif(shutil.which("pwsh") is None, reason="pwsh not installed")
def test_gate_inline_pwsh_scripts_parse(tmp_path: Path) -> None:
    """Every pwsh `run:` block must be syntactically valid PowerShell."""
    job = _workflow()["jobs"]["validate"]
    default_shell = job["defaults"]["run"]["shell"]
    scripts = [
        (str(step.get("name", "<unnamed>")), step["run"])
        for step in _steps(job)
        if "run" in step and step.get("shell", default_shell) == "pwsh"
    ]
    assert len(scripts) >= 1
    # The probe path travels as a `-File` argument: pwsh joins every token
    # after `-Command` into the command text, so `$args` would be empty there
    # and ParseFile would fail with "path is not valid" on every script.
    parser = tmp_path / "parser.ps1"
    parser.write_text(
        "$errs = $null; [void][System.Management.Automation.Language.Parser]::"
        "ParseFile($args[0], [ref]$null, [ref]$errs); "
        "if ($errs.Count -gt 0) { $errs | ForEach-Object { $_.Message }; exit 1 }\n",
        encoding="utf-8",
    )
    for name, script in scripts:
        stubbed = _EXPRESSION.sub("__GATE_EXPR__", script)
        probe = tmp_path / "probe.ps1"
        probe.write_text(stubbed, encoding="utf-8")
        checked = subprocess.run(
            [
                "pwsh",
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy",
                "Bypass",
                "-File",
                str(parser),
                str(probe),
            ],
            capture_output=True,
            text=True,
            encoding="utf-8",
            check=False,
        )
        assert checked.returncode == 0, f"{name}: {checked.stdout}{checked.stderr}"


def test_gate_windows_softhsm_pin_matches_ci() -> None:
    """The gate reuses CI's Windows SoftHSM2 pin; drift must break this guard."""
    ci_source = (REPO_ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    urls = [
        line.strip()
        for line in ci_source.splitlines()
        if line.strip().startswith("$url =") and "SoftHSM2-for-Windows" in line
    ]
    assert len(urls) == 1, f"expected one CI SoftHSM2 pin, found: {urls}"
    shas = [line.strip() for line in ci_source.splitlines() if line.strip().startswith("$sha =")]
    assert len(shas) == 1, f"expected one CI SoftHSM2 sha, found: {shas}"
    # Scoped to the Windows provisioning step, exactly once: a file-wide match
    # would pass with the pin kept in a comment while downloading another URL.
    job = _workflow()["jobs"]["validate"]
    windows_run = _run_of(_steps(job), "Install SoftHSM2 (Windows)")
    assert windows_run.count(urls[0]) == 1, f"gate SoftHSM2 URL drifted: {urls[0]}"
    assert windows_run.count(shas[0]) == 1, f"gate SoftHSM2 sha drifted: {shas[0]}"


def test_gate_runs_the_committed_published_artifact_tests() -> None:
    """The workflow and the meta-test file must reference each other."""
    job = _workflow()["jobs"]["validate"]
    steps = _steps(job)
    meta_run = _run_of(steps, "Published-artifact meta-tests")
    assert "tests/test_published_artifact.py" in meta_run
    assert (REPO_ROOT / "tests/test_published_artifact.py").is_file()
    # The installed package, never the checkout (asserted in Version check).
    assert "site-packages" in _run_of(steps, "Version check")
    # The meta-tests must actually gate the run: no swallowed failures, and the
    # out-of-checkout cd must precede the pytest invocation it justifies.
    assert "|| true" not in meta_run
    assert "continue-on-error" not in WORKFLOW_PATH.read_text(encoding="utf-8")
    assert meta_run.index('cd "$RUNNER_TEMP"') < meta_run.index("python -m pytest")


@pytest.mark.skipif(sys.platform == "win32", reason="simulates the WSL stub with a POSIX script")
def test_find_gnu_bash_rejects_non_gnu_stub(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A stub `bash` (WSL-launcher-shaped) on PATH must not be accepted."""
    stub = tmp_path / "bash"
    stub.write_text('#!/bin/sh\necho "no usable bash here"\nexit 1\n', encoding="utf-8")
    stub.chmod(0o755)
    monkeypatch.setenv("PATH", str(tmp_path))
    assert shutil.which("bash") == str(stub)  # the trap: naive lookup takes it
    assert _find_gnu_bash() is None
