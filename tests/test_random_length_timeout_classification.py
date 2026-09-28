"""F14/P11C-0198-018: typed 180 s timeouts in the 4 GiB random tests are locally
probe_incomplete (completion/progress unknown) -- never a crash finding.

PKCS #11 specifies no 180-second completion limit for producing 4 GiB of
random data; a timeout can mean a provider is slowly honoring the request,
not that it crashed, hung, narrowed, or is unavailable.
"""

from __future__ import annotations

import ast
import inspect
from types import SimpleNamespace
from typing import Any

import pytest

from pkcs11_check import classification as C  # noqa: N812
from pkcs11_check.core.process_observation import (
    SUBPROCESS_ABRUPT_EXIT_MARKER,
    build_process_observation,
)
from pkcs11_check.raw.types_std import CKR_ARGUMENTS_BAD
from pkcs11_check.testcases._probes.runner import ProbeResult
from pkcs11_check.testcases._subprocess_preamble import (
    SUBPROCESS_TIMEOUT_MARKER,
    SUBPROCESS_TIMEOUT_RC,
)
from pkcs11_check.testcases.security import test_random_length_truncation as rlt


@pytest.fixture(autouse=True)
def _clear_classification_store() -> Any:
    C.clear()
    yield
    C.clear()


def _timed_out_stderr(timeout_s: int = 180) -> str:
    return f"partial child output\n{SUBPROCESS_TIMEOUT_MARKER}:{timeout_s}s\n"


def _observation(
    returncode: int,
    stderr: str,
    *,
    timed_out: bool = False,
    platform: str | None = None,
) -> dict[str, object]:
    """Build the runner-shaped observation for a returncode/stderr pair."""
    return build_process_observation(
        "random_length",
        "probe",
        0,
        returncode,
        platform=platform,
        timed_out=timed_out,
        stderr=stderr,
    )


def test_typed_timeout_is_probe_incomplete_not_crash() -> None:
    """A typed probe timeout raises FAIL/HIGH probe_incomplete with no
    fabricated CKR and no crash/hang language."""
    with pytest.raises(pytest.fail.Exception):
        rlt.fail_probe_incomplete_on_typed_timeout(
            context="C_GenerateRandom(ptr, len=0x100000008)",
            observation=_observation(SUBPROCESS_TIMEOUT_RC, _timed_out_stderr(), timed_out=True),
            timeout_s=180,
        )
    (rec,) = C.get_records()
    assert rec.reason == "probe_incomplete"
    assert rec.outcome == "fail"
    assert rec.severity == "HIGH"
    assert "crash" not in rec.summary.lower()
    assert "hang" not in rec.summary.lower()
    assert "unknown" in rec.summary.lower()
    assert rec.actual_ckr is None
    assert rec.expected_ckr is None
    assert rec.detail is not None
    termination = rec.detail.get("termination")
    assert isinstance(termination, dict) and termination.get("kind") == "timeout"


def test_clean_completion_returns_quietly() -> None:
    """Completed probes (the CKR_OK + UNDERFILL measurement path) pass through
    untouched so the truncation verdict stays reachable."""
    assert (
        rlt.fail_probe_incomplete_on_typed_timeout(
            context="C_GenerateRandom(ptr, len=0x100000008)",
            observation=_observation(0, ""),
            timeout_s=180,
        )
        is None
    )
    assert C.get_records() == []


def test_non_timeout_termination_keeps_generic_classifier() -> None:
    """Signal crashes and ordinary exits are not timeout evidence -- the helper
    stays quiet so assert_subprocess_no_crash still owns those verdicts."""
    assert (
        rlt.fail_probe_incomplete_on_typed_timeout(
            context="C_GenerateRandom(ptr, len=0x100000008)",
            observation=_observation(-11, ""),
            timeout_s=180,
        )
        is None
    )
    assert (
        rlt.fail_probe_incomplete_on_typed_timeout(
            context="C_SeedRandom(ptr, len=0x100000008)",
            observation=_observation(1, "Traceback (most recent call last)\n"),
            timeout_s=180,
        )
        is None
    )
    assert C.get_records() == []


def test_both_random_length_nodes_preserved() -> None:
    """F14/P11C-0198-018 loudness pin: both 4 GiB probe nodes still exist."""
    assert hasattr(
        rlt.TestGenerateRandomLengthTruncation,
        "test_generate_random_oversized_length_rejects_or_honors",
    )
    assert hasattr(
        rlt.TestSeedRandomLengthTruncation,
        "test_seed_random_oversized_length_return_code",
    )


def test_underfill_branch_still_reaches_accepted_invalid(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """F14/P11C-0198-018 loudness pin: the completed CKR_OK + UNDERFILL:1 path
    still fails accepted_invalid. Driven through the product node with a stubbed
    run_probe, so deleting the CKR_OK+UNDERFILL branch fails this test."""

    def _stub_probe(probe: str, params: dict[str, object], **_kwargs: object) -> ProbeResult:
        assert probe == "random_length"
        assert params.get("which") == "generate"
        return ProbeResult(returncode=0, stdout="GENRAND_RV:0\nUNDERFILL:1\n", stderr="")

    monkeypatch.setattr(rlt, "run_probe", _stub_probe)
    cfg = SimpleNamespace(module="/tmp/fake-pkcs11.so", slot=0)
    with pytest.raises(pytest.fail.Exception):
        rlt.TestGenerateRandomLengthTruncation().test_generate_random_oversized_length_rejects_or_honors(
            cfg
        )
    (rec,) = C.get_records()
    assert rec.reason == "accepted_invalid"
    assert rec.outcome == "fail"


def test_both_4gib_call_sites_share_the_probe_timeout_bound() -> None:
    """F14/P11C-0198-018 coupling pin: both 4 GiB call sites pass the same
    _PROBE_TIMEOUT_S bound to run_probe(timeout=...) and to the typed-timeout
    helper (timeout_s=...), so the failure message names the bound actually
    enforced on the probe."""
    tree = ast.parse(inspect.getsource(rlt))
    run_probe_timeouts: list[ast.AST] = []
    helper_timeouts: list[ast.AST] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Name):
            continue
        if node.func.id == "run_probe":
            run_probe_timeouts.extend(k.value for k in node.keywords if k.arg == "timeout")
        elif node.func.id == "fail_probe_incomplete_on_typed_timeout":
            helper_timeouts.extend(k.value for k in node.keywords if k.arg == "timeout_s")
    assert len(run_probe_timeouts) == 2  # generate + seed call sites
    assert len(helper_timeouts) == 2
    for value in (*run_probe_timeouts, *helper_timeouts):
        assert isinstance(value, ast.Name) and value.id == "_PROBE_TIMEOUT_S", ast.dump(value)


def test_fabricated_marker_on_clean_exit_returns_quietly() -> None:
    """A provider-copied timeout marker on rc=0 must not override the
    structured exit termination."""
    assert (
        rlt.fail_probe_incomplete_on_typed_timeout(
            context="C_GenerateRandom(ptr, len=0x100000008)",
            observation=_observation(0, _timed_out_stderr()),
            timeout_s=180,
        )
        is None
    )
    assert C.get_records() == []


def test_fabricated_marker_on_signal_crash_returns_quietly() -> None:
    """A provider-copied timeout marker on SIGSEGV must not conceal the
    crash from the generic classifier."""
    assert (
        rlt.fail_probe_incomplete_on_typed_timeout(
            context="C_GenerateRandom(ptr, len=0x100000008)",
            observation=_observation(-11, _timed_out_stderr()),
            timeout_s=180,
        )
        is None
    )
    assert C.get_records() == []


def test_fabricated_marker_on_abrupt_exit_returns_quietly() -> None:
    """A provider-copied timeout marker on an abrupt native exit must not
    reclassify it as a timeout."""
    stderr = f"{SUBPROCESS_ABRUPT_EXIT_MARKER}:0\n{_timed_out_stderr()}"
    assert (
        rlt.fail_probe_incomplete_on_typed_timeout(
            context="C_SeedRandom(ptr, len=0x100000008)",
            observation=_observation(0, stderr),
            timeout_s=180,
        )
        is None
    )
    assert C.get_records() == []


def test_fabricated_marker_on_windows_exception_returns_quietly() -> None:
    """A provider-copied timeout marker on a Windows exception must not
    reclassify it as a timeout."""
    assert (
        rlt.fail_probe_incomplete_on_typed_timeout(
            context="C_SeedRandom(ptr, len=0x100000008)",
            observation=_observation(0xC0000005, _timed_out_stderr(), platform="win32"),
            timeout_s=180,
        )
        is None
    )
    assert C.get_records() == []


def test_missing_observation_returns_quietly() -> None:
    """Without structured termination evidence the helper fails closed so
    the generic classifier owns the verdict."""
    assert (
        rlt.fail_probe_incomplete_on_typed_timeout(
            context="C_GenerateRandom(ptr, len=0x100000008)",
            observation=None,
            timeout_s=180,
        )
        is None
    )
    assert C.get_records() == []


def _stub_probe_with(result: ProbeResult) -> Any:
    def _stub_probe(probe: str, params: dict[str, object], **_kwargs: object) -> ProbeResult:
        assert probe == "random_length"
        return result

    return _stub_probe


def _termination_kind(rec: Any) -> object:
    assert rec.detail is not None
    termination = rec.detail.get("termination")
    assert isinstance(termination, dict)
    return termination.get("kind")


def test_product_node_completed_underfill_ignores_copied_marker(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A copied timeout marker on a completed underfill measurement must not
    displace the accepted_invalid verdict with a crash/hang verdict."""
    result = ProbeResult(
        returncode=0,
        stdout="GENRAND_RV:0\nUNDERFILL:1\n",
        stderr=_timed_out_stderr(),
        observation=_observation(0, _timed_out_stderr()),
    )
    monkeypatch.setattr(rlt, "run_probe", _stub_probe_with(result))
    cfg = SimpleNamespace(module="/tmp/fake-pkcs11.so", slot=0)
    with pytest.raises(pytest.fail.Exception):
        rlt.TestGenerateRandomLengthTruncation().test_generate_random_oversized_length_rejects_or_honors(
            cfg
        )
    (rec,) = C.get_records()
    assert rec.reason == "accepted_invalid"
    assert rec.outcome == "fail"


def test_product_node_clean_reject_ignores_copied_marker(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A copied timeout marker on a clean seed-path rejection must not
    turn the pass into a crash verdict."""
    result = ProbeResult(
        returncode=0,
        stdout=f"SEEDRAND_RV:{int(CKR_ARGUMENTS_BAD)}\n",
        stderr=_timed_out_stderr(),
        observation=_observation(0, _timed_out_stderr()),
    )
    monkeypatch.setattr(rlt, "run_probe", _stub_probe_with(result))
    cfg = SimpleNamespace(module="/tmp/fake-pkcs11.so", slot=0)
    try:
        rlt.TestSeedRandomLengthTruncation().test_seed_random_oversized_length_return_code(cfg)
    except pytest.fail.Exception:
        pytest.fail("copied timeout marker turned a clean reject into a crash verdict")
    assert [rec for rec in C.get_records() if rec.outcome == "fail"] == []


def test_product_node_signal_keeps_termination_despite_copied_marker(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A copied timeout marker on SIGSEGV must not rewrite the retained
    termination kind to timeout."""
    result = ProbeResult(
        returncode=-11,
        stdout="",
        stderr=_timed_out_stderr(),
        observation=_observation(-11, _timed_out_stderr(), platform="linux"),
    )
    monkeypatch.setattr(rlt, "run_probe", _stub_probe_with(result))
    cfg = SimpleNamespace(module="/tmp/fake-pkcs11.so", slot=0)
    with pytest.raises(pytest.fail.Exception):
        rlt.TestGenerateRandomLengthTruncation().test_generate_random_oversized_length_rejects_or_honors(
            cfg
        )
    (rec,) = C.get_records()
    assert rec.reason == "crash"
    assert _termination_kind(rec) == "signal"


def test_product_node_windows_exception_keeps_termination_despite_copied_marker(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A copied timeout marker on a Windows exception must not rewrite the
    retained termination kind to timeout."""
    result = ProbeResult(
        returncode=0xC0000005,
        stdout="",
        stderr=_timed_out_stderr(),
        observation=_observation(0xC0000005, _timed_out_stderr(), platform="win32"),
    )
    monkeypatch.setattr(rlt, "run_probe", _stub_probe_with(result))
    cfg = SimpleNamespace(module="/tmp/fake-pkcs11.so", slot=0)
    with pytest.raises(pytest.fail.Exception):
        rlt.TestSeedRandomLengthTruncation().test_seed_random_oversized_length_return_code(cfg)
    (rec,) = C.get_records()
    assert rec.reason == "crash"
    assert _termination_kind(rec) == "exception"


def test_product_node_abrupt_exit_keeps_termination_despite_copied_marker(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A copied timeout marker on an abrupt native exit must not rewrite the
    retained termination kind to timeout."""
    stderr = f"{SUBPROCESS_ABRUPT_EXIT_MARKER}:0\n{_timed_out_stderr()}"
    result = ProbeResult(
        returncode=0,
        stdout="",
        stderr=stderr,
        observation=_observation(0, stderr),
    )
    monkeypatch.setattr(rlt, "run_probe", _stub_probe_with(result))
    cfg = SimpleNamespace(module="/tmp/fake-pkcs11.so", slot=0)
    with pytest.raises(pytest.fail.Exception):
        rlt.TestGenerateRandomLengthTruncation().test_generate_random_oversized_length_rejects_or_honors(
            cfg
        )
    (rec,) = C.get_records()
    assert rec.reason == "crash"
    assert _termination_kind(rec) == "abrupt_exit"


def test_product_node_genuine_timeout_stays_probe_incomplete(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A genuine typed timeout through the product node still raises
    probe_incomplete (not a crash/hang verdict)."""
    result = ProbeResult(
        returncode=SUBPROCESS_TIMEOUT_RC,
        stdout="",
        stderr=_timed_out_stderr(),
        observation=_observation(SUBPROCESS_TIMEOUT_RC, _timed_out_stderr(), timed_out=True),
    )
    monkeypatch.setattr(rlt, "run_probe", _stub_probe_with(result))
    cfg = SimpleNamespace(module="/tmp/fake-pkcs11.so", slot=0)
    with pytest.raises(pytest.fail.Exception):
        rlt.TestSeedRandomLengthTruncation().test_seed_random_oversized_length_return_code(cfg)
    (rec,) = C.get_records()
    assert rec.reason == "probe_incomplete"
    assert _termination_kind(rec) == "timeout"
