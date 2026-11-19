"""Opt-in gate for foreign-binary interop tests (fw#73 follow-up).

`p11-kit`/`openssl` children spawned by the interop tests make provider
calls no framework channel can see (foreign binaries: no coverage, no
sidecar, no probe key). They run only with explicit operator opt-in so
default runs exclude their unattributable traffic.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

pytest_plugins = ["pytester"]

OPT_IN_ENV = "P11TEST_ENABLE_EXTERNAL_TOOL_INTEROP"


def test_external_tool_gate_disabled_by_default(monkeypatch: pytest.MonkeyPatch) -> None:
    from pkcs11_check.testcases.test_interop_openssl import _external_tool_interop_enabled

    monkeypatch.delenv(OPT_IN_ENV, raising=False)
    assert _external_tool_interop_enabled() is False


def test_external_tool_gate_rejects_garbage(monkeypatch: pytest.MonkeyPatch) -> None:
    from pkcs11_check.testcases.test_interop_openssl import _external_tool_interop_enabled

    monkeypatch.setenv(OPT_IN_ENV, "yes-please")
    assert _external_tool_interop_enabled() is False


def test_external_tool_gate_enabled(monkeypatch: pytest.MonkeyPatch) -> None:
    from pkcs11_check.testcases.test_interop_openssl import _external_tool_interop_enabled

    monkeypatch.setenv(OPT_IN_ENV, "1")
    assert _external_tool_interop_enabled() is True


def test_run_refuses_foreign_spawn_without_opt_in(monkeypatch: pytest.MonkeyPatch) -> None:
    from pkcs11_check.testcases.test_interop_openssl import _run
    from tests._skip_assert import assert_skips

    def _boom(*args: object, **kwargs: object) -> object:
        raise AssertionError("spawn attempted without opt-in")

    monkeypatch.delenv(OPT_IN_ENV, raising=False)
    monkeypatch.setattr(subprocess, "run", _boom)
    assert_skips(_run, [sys.executable, "-c", "pass"], match="external-tool interop")


def test_run_spawns_with_opt_in(monkeypatch: pytest.MonkeyPatch) -> None:
    from pkcs11_check.testcases.test_interop_openssl import _run

    monkeypatch.setenv(OPT_IN_ENV, "1")
    rc, out, _err = _run([sys.executable, "-c", "print('spawned')"])
    assert rc == 0
    assert "spawned" in out


def test_list_modules_skipped_without_opt_in(
    pytester: pytest.Pytester, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv(OPT_IN_ENV, raising=False)
    # Hermetic child: stub tool presence and trap the spawn inside the
    # inner pytest, so the test needs no host packages and cannot
    # launch anything on any platform if the gate regresses.
    pytester.makepyfile(
        stub_interop_env="""
import pytest


@pytest.fixture(autouse=True)
def _stub_external_tools(monkeypatch):
    import subprocess

    from pkcs11_check.testcases import test_interop_openssl as mod

    monkeypatch.setattr(mod, "_have_p11kit", lambda: True)

    def _boom(*args, **kwargs):
        raise AssertionError("spawn attempted without opt-in")

    monkeypatch.setattr(subprocess, "run", _boom)
"""
    )
    import pkcs11_check

    assert pkcs11_check.__file__ is not None
    node = (
        str(Path(pkcs11_check.__file__).parent / "testcases" / "test_interop_openssl.py")
        + "::TestP11KitProxy::test_p11kit_list_modules"
    )
    # Plugin disabled: the stock plugin skips every testcase item without
    # --p11-module, which would mask the gate's own skip.
    result = pytester.runpytest_subprocess(
        node,
        "-v",
        "-ra",
        "-p",
        "no:cacheprovider",
        "-p",
        "no:pkcs11-check",
        "-p",
        "stub_interop_env",
    )
    result.assert_outcomes(skipped=1)
    result.stdout.fnmatch_lines(["*external-tool interop*"])


def test_proxy_load_skipped_without_opt_in(
    pytester: pytest.Pytester, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv(OPT_IN_ENV, raising=False)
    # Hermetic child: stub proxy presence + p11_config and trap run_probe
    # inside the inner pytest, so the test needs no host packages and cannot
    # load anything on any platform if the gate regresses.
    pytester.makepyfile(
        stub_proxy_env="""
import pytest


def _boom(*args, **kwargs):
    raise AssertionError("run_probe attempted without opt-in")


@pytest.fixture
def p11_config():
    from types import SimpleNamespace

    return SimpleNamespace(interface="auto")


@pytest.fixture(autouse=True)
def _stub_proxy_env(monkeypatch):
    from pathlib import Path

    from pkcs11_check.testcases import test_interop_openssl as mod

    monkeypatch.setattr(mod, "_find_lib", lambda candidates: Path("/nonexistent-proxy.so"))
    monkeypatch.setattr(mod, "run_probe", _boom)
"""
    )
    import pkcs11_check

    assert pkcs11_check.__file__ is not None
    node = (
        str(Path(pkcs11_check.__file__).parent / "testcases" / "test_interop_openssl.py")
        + "::TestP11KitProxy::test_load_module_via_p11kit"
    )
    # Plugin disabled: the stock plugin skips every testcase item without
    # --p11-module, which would mask the gate's own skip.
    result = pytester.runpytest_subprocess(
        node,
        "-v",
        "-ra",
        "-p",
        "no:cacheprovider",
        "-p",
        "no:pkcs11-check",
        "-p",
        "stub_proxy_env",
    )
    result.assert_outcomes(skipped=1)
    result.stdout.fnmatch_lines(["*external-tool interop*"])


def test_proxy_load_runs_with_opt_in(
    pytester: pytest.Pytester, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv(OPT_IN_ENV, "1")
    # Hermetic child: the stubbed probe reports OK exactly once, proving the
    # opt-in path still reaches the probe (the no-crash signal is preserved).
    pytester.makepyfile(
        stub_proxy_env_opt_in="""
import pytest


def _stub_run_probe(*args, **kwargs):
    from types import SimpleNamespace

    _stub_run_probe.calls.append(1)
    if len(_stub_run_probe.calls) > 1:
        raise AssertionError("run_probe called twice")
    return SimpleNamespace(
        returncode=0, stdout="OK: p11-kit proxy loaded and initialized", stderr=""
    )


_stub_run_probe.calls = []


@pytest.fixture
def p11_config():
    from types import SimpleNamespace

    return SimpleNamespace(interface="auto")


@pytest.fixture(autouse=True)
def _stub_proxy_env(monkeypatch):
    from pathlib import Path

    from pkcs11_check.testcases import test_interop_openssl as mod

    monkeypatch.setattr(mod, "_find_lib", lambda candidates: Path("/nonexistent-proxy.so"))
    monkeypatch.setattr(mod, "run_probe", _stub_run_probe)
"""
    )
    import pkcs11_check

    assert pkcs11_check.__file__ is not None
    node = (
        str(Path(pkcs11_check.__file__).parent / "testcases" / "test_interop_openssl.py")
        + "::TestP11KitProxy::test_load_module_via_p11kit"
    )
    result = pytester.runpytest_subprocess(
        node,
        "-v",
        "-ra",
        "-p",
        "no:cacheprovider",
        "-p",
        "no:pkcs11-check",
        "-p",
        "stub_proxy_env_opt_in",
    )
    result.assert_outcomes(passed=1)
