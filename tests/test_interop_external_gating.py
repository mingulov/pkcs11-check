"""Opt-in gate for foreign-binary interop tests (fw#73 follow-up).

`p11-kit`/`openssl` children spawned by the interop tests make provider
calls no framework channel can see (foreign binaries: no coverage, no
sidecar, no probe key). They run only with explicit operator opt-in so
default runs stay exactly reconcilable against whole-tree observers.
"""

from __future__ import annotations

import shutil
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

    monkeypatch.delenv(OPT_IN_ENV, raising=False)
    with pytest.raises(pytest.skip.Exception, match="external-tool interop"):
        _run([sys.executable, "-c", "pass"])


def test_run_spawns_with_opt_in(monkeypatch: pytest.MonkeyPatch) -> None:
    from pkcs11_check.testcases.test_interop_openssl import _run

    monkeypatch.setenv(OPT_IN_ENV, "1")
    rc, out, _err = _run([sys.executable, "-c", "print('spawned')"])
    assert rc == 0
    assert "spawned" in out


def test_list_modules_skipped_without_opt_in(
    pytester: pytest.Pytester, monkeypatch: pytest.MonkeyPatch
) -> None:
    if shutil.which("p11-kit") is None:
        pytest.skip("p11-kit not installed")
    monkeypatch.delenv(OPT_IN_ENV, raising=False)
    import pkcs11_check

    assert pkcs11_check.__file__ is not None
    node = (
        str(
            Path(pkcs11_check.__file__).parent
            / "testcases"
            / "test_interop_openssl.py"
        )
        + "::TestP11KitProxy::test_p11kit_list_modules"
    )
    # Plugin disabled: the stock plugin skips every testcase item without
    # --p11-module, which would mask the gate's own skip.
    result = pytester.runpytest_subprocess(
        node, "-v", "-ra", "-p", "no:cacheprovider", "-p", "no:pkcs11-check"
    )
    result.assert_outcomes(skipped=1)
    result.stdout.fnmatch_lines(["*external-tool interop*"])
