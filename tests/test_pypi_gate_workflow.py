"""Contract tests for the post-publish (TestPyPI + PyPI) validation gate workflow."""

from __future__ import annotations

import contextlib
import io
import json
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
import yaml  # type: ignore[import-untyped]

REPO_ROOT = Path(__file__).resolve().parents[1]
WORKFLOW_PATH = REPO_ROOT / ".github/workflows/pypi-gate.yml"

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


def test_gate_triggers_after_each_publish_and_manually() -> None:
    """Losing an automatic leg or a manual leg must break this guard."""
    workflow = _workflow()

    assert set(workflow["on"]) == {"workflow_run", "workflow_dispatch", "workflow_call"}
    run = workflow["on"]["workflow_run"]
    assert run["workflows"] == ["TestPyPI", "Release"]
    assert run["types"] == ["completed"]
    # Each trigger name must match its actual publish workflow: an upstream
    # rename would silently stop that gate leg from ever firing while staying
    # green.
    for filename, trigger in (
        ("publish-testpypi.yml", "TestPyPI"),
        ("publish.yml", "Release"),
    ):
        publish = yaml.load(
            (REPO_ROOT / ".github/workflows" / filename).read_text(encoding="utf-8"),
            Loader=yaml.BaseLoader,
        )
        assert publish["name"] == trigger
    for trigger in ("workflow_dispatch", "workflow_call"):
        version_input = workflow["on"][trigger]["inputs"]["version"]
        assert version_input["required"] == "false"
        assert version_input["type"] == "string"
        assert "latest on that index" in version_input["description"]
    dispatch_index = workflow["on"]["workflow_dispatch"]["inputs"]["index"]
    assert dispatch_index["required"] == "false"
    assert dispatch_index["type"] == "choice"
    assert dispatch_index["options"] == ["test", "prod"]
    assert dispatch_index["default"] == "test"
    call_index = workflow["on"]["workflow_call"]["inputs"]["index"]
    assert call_index["required"] == "false"
    assert call_index["type"] == "string"


def test_gate_matrix_covers_every_os_and_artifact() -> None:
    """Dropping an OS or an artifact kind must break this guard."""
    workflow = _workflow()

    assert set(workflow["jobs"]) == {"prepare", "validate"}
    job = workflow["jobs"]["validate"]
    # Every leg validates the one version prepare pinned: resolving "latest"
    # per leg diverged within a single run (CDN-cached index reads).
    assert job["needs"] == ["prepare"]
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
            "Install ${{ matrix.artifact }} from the pinned index",
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
    # Each leg installs its exact file by URL resolved from the pinned
    # simple page (R2-3): pip consults every index without preferring
    # --index-url, so index-based installs could mix bytes across indexes.
    # The legs differ by file, never by pip flags; deps come from PyPI.
    assert "--only-binary" not in commands
    assert "--no-binary" not in commands
    assert "test.pypi.org" not in commands
    install_run = _run_of(steps, "Install ${{ matrix.artifact }} from the pinned index")
    assert 'f"pkcs11_check-{version}-py3-none-any.whl"' in install_run
    assert 'f"pkcs11_check-{version}.tar.gz"' in install_run
    assert "hrefs" in install_run and "len(hrefs) != 1" in install_run
    assert '"--index-url"' in install_run
    assert '"https://pypi.org/simple/"' in install_run
    assert "needs.prepare.outputs.simple_url" not in install_run
    install_step = next(s for s in steps if "from the pinned index" in str(s.get("name", "")))
    assert install_step["env"]["SIMPLE_URL"] == "${{ needs.prepare.outputs.simple_url }}"
    assert install_step["env"]["ARTIFACT"] == "${{ matrix.artifact }}"
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
    # The smoke and vector summaries must prove execution, not empty green —
    # scoped to their own steps so drifting into an always() step still fails.
    for needle in ("Smoke (installed package)", "Vector slice (fetch-then-test proof)"):
        run_body = _run_of(steps, needle)
        assert 'summary["passed"] > 0' in run_body, needle
        assert 'summary["failed"] == 0' in run_body, needle


def test_gate_pins_one_settled_version_for_every_leg() -> None:
    """The prepare job must settle "latest", await the release files, and pin
    one version for the whole matrix. Per-leg resolution diverged within one
    run (stale CDN reads), and installing straight after upload raced index
    propagation (metadata visible before files)."""
    workflow = _workflow()
    prepare = workflow["jobs"]["prepare"]

    assert prepare["runs-on"] == "ubuntu-latest"
    assert prepare["outputs"] == {
        "version": "${{ steps.candidate.outputs.version }}",
        "index": "${{ steps.candidate.outputs.index }}",
        "simple_url": "${{ steps.candidate.outputs.simple_url }}",
    }
    # Same leg gate as validate: a failed publish must skip prepare too.
    validate = workflow["jobs"]["validate"]
    assert prepare["if"] == validate["if"]

    steps = _steps(prepare)
    resolve = next(step for step in steps if "await candidate version" in str(step.get("name", "")))
    assert resolve["name"] == "Resolve and await candidate version"
    assert resolve["id"] == "candidate"
    assert resolve["env"] == {
        "REQUESTED": "${{ inputs.version }}",
        "REQUESTED_INDEX": "${{ inputs.index }}",
        "EVENT_NAME": "${{ github.event_name }}",
        "TRIGGERING_WORKFLOW": "${{ github.event.workflow_run.name }}",
        "HEAD_SHA": "${{ github.event.workflow_run.head_sha }}",
    }
    run_body = str(resolve["run"])
    # An explicitly requested version skips the settle; "latest" must prove
    # stability across consecutive identical reads, not one possibly stale read.
    assert 'os.environ.get("REQUESTED"' in run_body
    assert "SETTLE_READS" in run_body
    assert "len(set(" in run_body
    # The wait polls the same simple index pip will read, for BOTH release
    # files; pinning on metadata alone reintroduces the propagation race.
    # Both index hosts derive from the attested index in this one step.
    assert '"pypi.org" if index == "prod" else "test.pypi.org"' in run_body
    assert 'f"https://{host}/pypi/pkcs11-check/json"' in run_body
    assert 'f"https://{host}/simple/pkcs11-check/"' in run_body
    assert "INDEX_URL" not in run_body
    assert ".tar.gz" in run_body and "-{version}-" in run_body
    assert "WAIT_DEADLINE" in run_body
    # Bounded network I/O throughout: a hung index must fail loudly instead
    # of stalling up to the job timeout.
    assert "timeout=" in run_body
    assert "GITHUB_OUTPUT" in run_body

    # Every validate leg consumes the pinned version; no leg may resolve or
    # pin its own (that was the divergence).
    validate_source = "\n".join(
        f"{step.get('name', '')}\n{step.get('env', '')}\n{step.get('run', '')}"
        for step in _steps(validate)
    )
    assert "steps.candidate" not in validate_source
    assert "test.pypi.org/pypi/pkcs11-check/json" not in validate_source
    assert "pypi/pkcs11-check/json" not in validate_source
    for needle in (
        "Install ${{ matrix.artifact }} from the pinned index",
        "Version check",
        "Summarize",
    ):
        step = next(s for s in _steps(validate) if needle in str(s.get("name", "")))
        assert step["env"]["VERSION"] == "${{ needs.prepare.outputs.version }}", needle
    # The legs read the index only through prepare's outputs, never a
    # hardcoded host: the per-leg await and the install share one source.
    assert "needs.prepare.outputs.simple_url" in validate_source
    assert "test.pypi.org/simple" not in validate_source


def test_gate_waits_for_version_on_each_runner_before_install() -> None:
    """Each validate leg must await the pinned version on ITS OWN index view
    before installing. Prepare's single-vantage wait cannot cover other
    runners' CDN edges: run 44460105408 attempt 1 passed prepare, then the
    ubuntu wheel leg's pip saw an index without 0.3.0rc5 (other legs saw
    it) and failed with 'No matching distribution'."""
    job = _workflow()["jobs"]["validate"]
    steps = _steps(job)

    await_idx = _step_index(steps, "Await version on this runner's index")
    install_idx = _step_index(steps, "Install ${{ matrix.artifact }} from the pinned index")
    setup_idx = _step_index(steps, _SETUP_PYTHON_ACTION)
    assert setup_idx < await_idx < install_idx

    step = steps[await_idx]
    assert "if" not in step, "the wait must run on every leg, unconditionally"
    assert step["env"]["VERSION"] == "${{ needs.prepare.outputs.version }}"
    assert step["env"]["SIMPLE_URL"] == "${{ needs.prepare.outputs.simple_url }}"
    run_body = _run_of(steps, "Await version on this runner's index")
    # Same markers pip will need, on the same index pip will read; both
    # files required (either/or would pass on a half-published release).
    # The index arrives via prepare's output, never hardcoded per leg.
    assert 'SIMPLE_URL = os.environ["SIMPLE_URL"]' in run_body
    assert "test.pypi.org" not in run_body
    assert "pypi.org" not in run_body
    assert "-{version}-" in run_body and "-{version}.tar.gz" in run_body
    assert "wheel_marker in page and sdist_marker" in run_body
    # Bounded wait (~5 minutes), enforced (not just declared), loud
    # failure, polite polling, bounded network I/O.
    assert "WAIT_DEADLINE = 300" in run_body
    assert "+ WAIT_DEADLINE" in run_body
    assert "time.monotonic() >= deadline" in run_body
    assert "time.sleep(WAIT_INTERVAL)" in run_body
    assert "raise SystemExit" in run_body
    assert "timeout=" in run_body
    # Still the one pinned version: no per-leg resolution or JSON latest.
    assert "steps.candidate" not in run_body
    assert "test.pypi.org/pypi/pkcs11-check/json" not in run_body


def test_gate_index_is_attested_never_guessed() -> None:
    """Prepare must derive the index from an explicit input or the publisher.

    Garbage fails first on every event; an explicit input then wins
    everywhere (a reviewed caller passing one is attested by review, so a
    reusable call from a workflow_run-triggered caller keeps its explicit
    index instead of being overridden); only an omitted input falls through
    to trigger attestation (Release -> prod, TestPyPI -> test) or the test
    default. An unknown trigger fails loudly -- the gate never guesses.
    """
    prepare = _workflow()["jobs"]["prepare"]
    run_body = _run_of(_steps(prepare), "Resolve and await candidate version")
    assert 'os.environ.get("EVENT_NAME"' in run_body
    assert 'os.environ.get("TRIGGERING_WORKFLOW"' in run_body
    assert 'os.environ.get("REQUESTED_INDEX"' in run_body
    garbage_at = run_body.index('raise SystemExit(f"index must be')
    explicit_at = run_body.index('if requested_index in ("test", "prod")')
    attest_at = run_body.index('elif event == "workflow_run"')
    # Order is the contract: garbage rejects before anything is honored,
    # and an explicit input wins before attestation is consulted (R1-F8).
    assert garbage_at < explicit_at < attest_at
    assert 'if triggering == "Release"' in run_body
    assert 'elif triggering == "TestPyPI"' in run_body
    assert 'raise SystemExit(f"unexpected triggering workflow' in run_body
    # The resolved index reaches the legs as an output, and the evidence
    # artifact name carries it so prod/test runs never mix silently.
    validate_source = "\n".join(
        f"{step.get('name', '')}\n{step.get('env', '')}\n{step.get('run', '')}\n"
        f"{step.get('with', '')}"
        for step in _steps(_workflow()["jobs"]["validate"])
    )
    assert "needs.prepare.outputs.index" in validate_source


def test_gate_release_runs_bind_version_to_triggering_tag() -> None:
    """R1-F2: a Release trigger binds the version to its tag, not settle.

    Settle-agreement could freeze on a stale edge and green-light the
    previous release. The release tag at the triggering commit is exact.
    Only a clean lookup with no tag there (a dry-run success) falls back
    to settling latest; a failed lookup or missing trigger data stops the
    run (R2-1: a production publish whose version cannot be resolved must
    not validate a guess), ambiguity fails loudly, and non-release-shaped
    tags are ignored. Binding applies only when the selected index is the
    trigger's own (R2-2: a test-index call in a Release context settles on
    TestPyPI, never inherits the production tag).
    """
    prepare = _workflow()["jobs"]["prepare"]
    run_body = _run_of(_steps(prepare), "Resolve and await candidate version")
    assert "def release_tag_version()" in run_body
    assert 'git", "ls-remote", "--tags"' in run_body
    assert "HEAD_SHA" in run_body
    assert 'name.startswith("v") and len(name) > 1 and name[1].isdigit()' in run_body
    assert "ambiguous release tags" in run_body
    assert "cannot bind release version" in run_body
    assert "falling back to settle" not in run_body
    assert "bound to triggering release" in run_body
    assert "no release tag at the triggering commit" in run_body
    assert (
        'elif event == "workflow_run" and triggering == "Release" and index == "prod"' in run_body
    )


def _prepare_script() -> str:
    """The prepare step's embedded Python, without the heredoc wrapper."""
    prepare = _workflow()["jobs"]["prepare"]
    run_body = _run_of(_steps(prepare), "Resolve and await candidate version")
    prefix = "python - <<'PY'\n"
    assert run_body.startswith(prefix)
    script = run_body.removeprefix(prefix).rstrip()
    assert script.endswith("\nPY")
    return script[: -len("\nPY")]


class _PrepareResult(SimpleNamespace):
    """Outcome of one prepare execution: `raised`, `output`, `outputs`."""


def _exec_prepare(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    *,
    env: dict[str, str],
    ls_remote_stdout: str = "",
    ls_remote_rc: int = 0,
    latest: str = "9.9.9",
    page_version: str | None = "9.9.9",
) -> _PrepareResult:
    """Execute the SHIPPED prepare script with mocked git and index I/O.

    subprocess and urllib resolve to in-memory fakes (via sys.modules, so
    the script's own imports pick them up); sleeps are instant; the index
    serves one canned latest version plus a simple page carrying (or
    missing) one version's files. Hermetic: no network, no git.
    """
    output_path = tmp_path / "github_output.txt"
    output_path.write_text("", encoding="utf-8")

    def _fake_run(*args: object, **kwargs: object) -> SimpleNamespace:
        assert args[0][:3] == ["git", "ls-remote", "--tags"], args
        return SimpleNamespace(returncode=ls_remote_rc, stdout=ls_remote_stdout, stderr="")

    class _FakeResponse:
        def __init__(self, payload: bytes) -> None:
            self._payload = payload

        def read(self) -> bytes:
            return self._payload

        def __enter__(self) -> _FakeResponse:
            return self

        def __exit__(self, *args: object) -> None:
            return None

    def _fake_urlopen(url: str, timeout: object = None) -> _FakeResponse:
        del timeout
        if url.endswith("/json"):
            return _FakeResponse(json.dumps({"info": {"version": latest}}).encode())
        page = ""
        if page_version is not None:
            page = (
                f'<a href="../../packages/x/pkcs11_check-{page_version}-py3-none-any.whl">'
                f"pkcs11_check-{page_version}-py3-none-any.whl</a>\n"
                f'<a href="../../packages/x/pkcs11_check-{page_version}.tar.gz">'
                f"pkcs11_check-{page_version}.tar.gz</a>\n"
            )
        return _FakeResponse(page.encode())

    fake_urllib_request = SimpleNamespace(urlopen=_fake_urlopen)
    fake_urllib = SimpleNamespace(request=fake_urllib_request)
    monkeypatch.setitem(sys.modules, "subprocess", SimpleNamespace(run=_fake_run))
    monkeypatch.setitem(sys.modules, "urllib", fake_urllib)
    monkeypatch.setitem(sys.modules, "urllib.request", fake_urllib_request)
    monkeypatch.setattr(time, "sleep", lambda _seconds: None)
    monkeypatch.setenv("GITHUB_OUTPUT", str(output_path))
    for key in (
        "REQUESTED",
        "REQUESTED_INDEX",
        "EVENT_NAME",
        "TRIGGERING_WORKFLOW",
        "HEAD_SHA",
        "GITHUB_SERVER_URL",
        "GITHUB_REPOSITORY",
    ):
        monkeypatch.setenv(key, env.get(key, ""))
    # The script references subprocess.TimeoutExpired in an except clause.
    sys.modules["subprocess"].TimeoutExpired = subprocess.TimeoutExpired
    buffer = io.StringIO()
    raised: str | None = None
    try:
        with contextlib.redirect_stdout(buffer):
            exec(compile(_prepare_script(), "<gate-prepare>", "exec"), {})  # noqa: S102
    except SystemExit as exc:
        raised = str(exc.code)
    outputs = dict(
        line.split("=", 1)
        for line in output_path.read_text(encoding="utf-8").splitlines()
        if "=" in line
    )
    return _PrepareResult(raised=raised, output=buffer.getvalue(), outputs=outputs)


_RELEASE_BASE = {
    "EVENT_NAME": "workflow_run",
    "TRIGGERING_WORKFLOW": "Release",
    "GITHUB_SERVER_URL": "https://github.example",
    "GITHUB_REPOSITORY": "o/r",
}


def test_prepare_binds_peeled_release_tag(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """R2-5: an annotated tag binds through its peeled commit line."""
    head = "ab" * 20
    ls_remote = f"cd{'ef' * 19}\trefs/tags/v9.9.9\n{head}\trefs/tags/v9.9.9^{{}}\n"
    result = _exec_prepare(
        monkeypatch,
        tmp_path,
        env={**_RELEASE_BASE, "HEAD_SHA": head},
        ls_remote_stdout=ls_remote,
        latest="0.0.0",
    )
    assert result.raised is None, result.output
    assert result.outputs["version"] == "9.9.9"
    assert result.outputs["index"] == "prod"
    assert "bound to triggering release: 9.9.9" in result.output


def test_prepare_rejects_ambiguous_release_tags(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """R2-5: two v-tags at the head stop the run; non-release tags ignored."""
    head = "ab" * 20
    ls_remote = (
        f"{head}\trefs/tags/v9.9.9\n"
        f"{head}\trefs/tags/v8.8.8\n"
        f"{head}\trefs/tags/vetted\n"
        f"{head}\trefs/tags/v\n"
    )
    result = _exec_prepare(
        monkeypatch, tmp_path, env={**_RELEASE_BASE, "HEAD_SHA": head}, ls_remote_stdout=ls_remote
    )
    assert result.raised is not None and "ambiguous release tags" in result.raised
    assert result.outputs == {}


def test_prepare_ignores_non_release_tags(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """R2-5: `vetted` and bare `v` never bind (R2-1 tag-shape rule)."""
    head = "ab" * 20
    ls_remote = f"{head}\trefs/tags/vetted\n{head}\trefs/tags/v\n"
    result = _exec_prepare(
        monkeypatch,
        tmp_path,
        env={**_RELEASE_BASE, "HEAD_SHA": head},
        ls_remote_stdout=ls_remote,
        latest="9.9.9",
    )
    assert result.raised is None, result.output
    assert "no release tag at the triggering commit" in result.output
    assert result.outputs["version"] == "9.9.9"


def test_prepare_explicit_index_wins_in_release_context(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """R2-5 (R2-2): index=test in a Release context settles on TestPyPI."""
    result = _exec_prepare(
        monkeypatch,
        tmp_path,
        env={**_RELEASE_BASE, "REQUESTED_INDEX": "test", "HEAD_SHA": "ab" * 20},
        latest="8.8.8",
        page_version="8.8.8",
    )
    assert result.raised is None, result.output
    assert result.outputs["index"] == "test"
    assert result.outputs["version"] == "8.8.8"
    assert "bound to triggering release" not in result.output
    assert result.outputs["simple_url"] == "https://test.pypi.org/simple/pkcs11-check/"


def test_prepare_dry_run_shape_settles_loudly(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """R2-5: no tag at the head (dry run) settles latest with a notice."""
    result = _exec_prepare(
        monkeypatch,
        tmp_path,
        env={**_RELEASE_BASE, "HEAD_SHA": "ab" * 20},
        ls_remote_stdout=f"cd{'ef' * 19}\trefs/tags/v7.7.7\n",
        latest="9.9.9",
    )
    assert result.raised is None, result.output
    assert "no release tag at the triggering commit" in result.output
    assert result.outputs["version"] == "9.9.9"


def test_prepare_lookup_failure_stops_release_run(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """R2-5 (R2-1): an unresolvable production version stops, never settles."""
    result = _exec_prepare(
        monkeypatch, tmp_path, env={**_RELEASE_BASE, "HEAD_SHA": "ab" * 20}, ls_remote_rc=128
    )
    assert result.raised is not None and "cannot bind release version" in result.raised
    assert result.outputs == {}


def test_prepare_missing_head_sha_stops_release_run(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """R2-5 (R2-1): no head SHA means no binding, no guessing."""
    result = _exec_prepare(monkeypatch, tmp_path, env=_RELEASE_BASE)
    assert result.raised is not None and "cannot bind release version" in result.raised
    assert result.outputs == {}


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
    jobs = _workflow()["jobs"]
    job = jobs["validate"]
    default_shell = job["defaults"]["run"]["shell"]
    assert default_shell == "bash"
    scripts = [
        (str(step.get("name", "<unnamed>")), step["run"])
        for step in _steps(job)
        if "run" in step and step.get("shell", default_shell) == "bash"
    ]
    # The prepare job's scripts get the same syntax gate (ubuntu default
    # shell is bash; prepare pins no other shell).
    prepare = jobs["prepare"]
    prepare_scripts = [
        (f"prepare: {step.get('name', '<unnamed>')}", step["run"])
        for step in _steps(prepare)
        if "run" in step
    ]
    assert prepare_scripts, "prepare job lost its scripts"
    assert all("shell" not in step for step in _steps(prepare))
    scripts.extend(prepare_scripts)
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
