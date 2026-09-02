"""Windows ctypes access violations must survive best-effort cleanup guards."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from pkcs11_check.raw.bootstrap import close_session_quietly, logout_quietly
from pkcs11_check.raw.recipes import _cancel_operation, destroy_quietly
from pkcs11_check.testcases._probes import initialize_args, mutex_callback_safety, v30_session
from pkcs11_check.testcases._probes import session as session_probe
from pkcs11_check.testcases.security import test_cve_regression, test_padding_oracle

_ACCESS_VIOLATION = "exception: access violation reading 0x0"


class _Callable:
    """ctypes-like callable that accepts restype/argtypes assignments in probe tests."""

    def __init__(self, fn: Any) -> None:
        self._fn = fn

    def __call__(self, *args: Any) -> Any:
        return self._fn(*args)


@pytest.mark.parametrize(
    ("helper", "method"),
    [
        (close_session_quietly, "C_CloseSession"),
        (logout_quietly, "C_Logout"),
        (destroy_quietly, "C_DestroyObject"),
    ],
)
def test_shared_cleanup_helpers_surface_ctypes_access_violation(helper: Any, method: str) -> None:
    class _Raw:
        def __getattr__(self, name: str) -> Any:
            if name == method:
                return lambda *_args: (_ for _ in ()).throw(OSError(_ACCESS_VIOLATION))
            raise AttributeError(name)

    with pytest.raises(OSError, match="access violation"):
        helper(_Raw(), 1, 2) if method == "C_DestroyObject" else helper(_Raw(), 1)


def test_session_cancel_cleanup_surfaces_ctypes_access_violation() -> None:
    class _Raw:
        def C_SessionCancel(self, *_args: Any) -> None:  # noqa: N802 - raw PKCS#11 API
            raise OSError(_ACCESS_VIOLATION)

    with pytest.raises(OSError, match="access violation"):
        _cancel_operation(_Raw(), 1, 0)


def test_probe_teardown_surfaces_ctypes_access_violation(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(session_probe, "_write_coverage", lambda _raw: None)
    monkeypatch.setattr(session_probe, "close_session_quietly", lambda *_args: None)

    class _Raw:
        def C_Finalize(self, _reserved: object) -> None:  # noqa: N802 - raw PKCS#11 API
            raise OSError(_ACCESS_VIOLATION)

    teardown = session_probe._ProbeTeardown(_Raw())  # type: ignore[arg-type]
    teardown.initialized = True

    with pytest.raises(OSError, match="access violation"):
        teardown()


def test_session_probe_runs_teardown_in_normal_control_flow(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An atexit exception cannot change rc; probe_main must invoke teardown explicitly."""
    monkeypatch.setattr(session_probe.atexit, "register", lambda *_args: None)
    monkeypatch.setattr(
        session_probe.ProbeParams,
        "load",
        classmethod(
            lambda _cls, _path: SimpleNamespace(
                module_path="module", slot_id=None, slot_label=None, interface=None, extra={}
            )
        ),
    )

    class _Raw:
        def C_Initialize(self, _args: object) -> int:  # noqa: N802 - raw PKCS#11 API
            return 0

        def C_Finalize(self, _reserved: object) -> None:  # noqa: N802 - raw PKCS#11 API
            raise OSError(_ACCESS_VIOLATION)

        call_log: dict[str, int] = {}
        mechanism_counts: dict[int, int] = {}
        call_log_ok: dict[str, int] = {}
        mechanism_rv_counts: dict[int, dict[int, int]] = {}
        rv_trace: list[dict[str, Any]] = []

    monkeypatch.setattr(session_probe.RawPKCS11, "from_lib", classmethod(lambda *_a: _Raw()))

    with pytest.raises(OSError, match="access violation"):
        session_probe.probe_main(lambda _ctx, _extra: None, level=session_probe.Level.INIT)


def test_v30_probe_teardown_surfaces_ctypes_access_violation() -> None:
    class _Raw:
        def C_CloseSession(self, _session: int) -> None:  # noqa: N802 - raw PKCS#11 API
            raise OSError(_ACCESS_VIOLATION)

        def C_Finalize(self, _reserved: object) -> None:  # noqa: N802 - raw PKCS#11 API
            raise AssertionError("finalize must not hide close access violation")

    with pytest.raises(OSError, match="access violation"):
        v30_session._teardown(_Raw(), 1)  # type: ignore[arg-type]


@pytest.mark.parametrize("module", [initialize_args, mutex_callback_safety])
def test_raw_initialize_probes_surface_finalize_ctypes_access_violation(module: Any) -> None:
    class _Lib:
        C_Initialize = _Callable(lambda _args: 0)
        C_Finalize = _Callable(lambda _args: (_ for _ in ()).throw(OSError(_ACCESS_VIOLATION)))

    fn = (
        initialize_args._call_initialize
        if module is initialize_args
        else (mutex_callback_safety._python_exception_in_create)
    )
    with pytest.raises(OSError, match="access violation"):
        fn(_Lib(), None) if module is initialize_args else fn(_Lib())


@pytest.mark.parametrize("module", [initialize_args, mutex_callback_safety])
def test_raw_initialize_probes_ignore_ordinary_finalize_oserror(module: Any) -> None:
    class _Lib:
        C_Initialize = _Callable(lambda _args: 0)
        C_Finalize = _Callable(
            lambda _args: (_ for _ in ()).throw(OSError("provider already finalized"))
        )

    if module is initialize_args:
        module._call_initialize(_Lib(), None)
    else:
        module._python_exception_in_create(_Lib())


def test_padding_oracle_abort_surfaces_ctypes_access_violation() -> None:
    class _Raw:
        def C_DecryptFinal(self, *_args: Any) -> None:  # noqa: N802 - raw PKCS#11 API
            raise OSError(_ACCESS_VIOLATION)

    with pytest.raises(OSError, match="access violation"):
        test_padding_oracle._abort_decrypt_operation(_Raw(), 1)


def test_cve_regression_abort_surfaces_ctypes_access_violation() -> None:
    class _Raw:
        def C_EncryptFinal(self, *_args: Any) -> None:  # noqa: N802 - raw PKCS#11 API
            raise OSError(_ACCESS_VIOLATION)

    with pytest.raises(OSError, match="access violation"):
        test_cve_regression._abort_encrypt_operation(_Raw(), 1)


def test_cleanup_helpers_still_ignore_ordinary_oserror() -> None:
    class _Raw:
        def C_CloseSession(self, _session: int) -> None:  # noqa: N802 - raw PKCS#11 API
            raise OSError("provider already finalized")

        def C_Logout(self, _session: int) -> None:  # noqa: N802 - raw PKCS#11 API
            raise OSError("provider already finalized")

        def C_DestroyObject(self, _session: int, _handle: int) -> None:  # noqa: N802
            raise OSError("provider already finalized")

        def C_SessionCancel(self, *_args: Any) -> None:  # noqa: N802 - raw PKCS#11 API
            raise OSError("provider already finalized")

    raw = _Raw()
    close_session_quietly(raw, 1)
    logout_quietly(raw, 1)
    destroy_quietly(raw, 1, 2)
    _cancel_operation(raw, 1, 0)


def test_shared_session_health_surfaces_ctypes_access_violation() -> None:
    from pkcs11_check.fixtures import _ModuleSessionHolder

    class _Raw:
        def C_GetSessionInfo(self, *_args: Any) -> int:  # noqa: N802
            raise OSError(_ACCESS_VIOLATION)

    holder = _ModuleSessionHolder(SimpleNamespace(raw=_Raw()), object())  # type: ignore[arg-type]
    holder._sh = 1

    with pytest.raises(OSError, match="access violation"):
        holder._is_healthy()
