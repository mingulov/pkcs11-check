from __future__ import annotations

import ctypes
from unittest.mock import Mock, patch


def test_generated_standard_c_methods() -> None:
    from pkcs11_check.raw import metadata_std

    names = set(metadata_std.FUNCTION_SIGNATURES)
    assert "C_GetFunctionList" in names
    assert "C_CancelFunction" in names
    assert "C_DigestEncryptUpdate" in names
    assert len(names) >= 104


def test_rawpkcs11_available_function_names_are_explicit() -> None:
    from pkcs11_check.raw.api import RawPKCS11

    raw = object.__new__(RawPKCS11)
    raw._funcs = {"C_GetFunctionList": object(), "C_CancelFunction": object()}

    assert raw.available_function_names() == {"C_GetFunctionList", "C_CancelFunction"}


def test_raw_api_never_auto_raises() -> None:
    from pkcs11_check.raw.rv import ckr_name

    assert ckr_name(0x00000007) == "CKR_ARGUMENTS_BAD"


def test_from_lib_generic_240_interface_does_not_load_v30_or_v32_tails() -> None:
    from pkcs11_check.raw.api import RawPKCS11
    from pkcs11_check.raw.types_std import (
        CK_INTERFACE,
        CK_INTERFACE_PTR,
        CK_VERSION,
        CK_VERSION_PTR,
        CKR_FUNCTION_FAILED,
        CKR_OK,
    )

    class FakeFunctionList(ctypes.Structure):
        _fields_ = [("version", CK_VERSION), ("reserved", ctypes.c_void_p)]

    class FakeGetInterface:
        def __init__(self) -> None:
            self.function_list = FakeFunctionList()
            self.function_list.version.major = 2
            self.function_list.version.minor = 40
            self.interface = CK_INTERFACE()
            self.interface.pInterfaceName = None
            self.interface.pFunctionList = ctypes.cast(
                ctypes.pointer(self.function_list), ctypes.c_void_p
            ).value
            self.interface.flags = 0
            self.interface_ptr = ctypes.pointer(self.interface)
            self.calls: list[tuple[int | None, int | None]] = []

        def __call__(
            self, _name: object, version: object, interface_out: object, _flags: object
        ) -> int:
            if version is not None:
                requested = ctypes.cast(version, CK_VERSION_PTR).contents
                self.calls.append((int(requested.major), int(requested.minor)))
                return CKR_FUNCTION_FAILED

            self.calls.append((None, None))
            ctypes.cast(interface_out, ctypes.POINTER(CK_INTERFACE_PTR))[0] = self.interface_ptr
            return CKR_OK

    fake_get_interface = FakeGetInterface()
    fake_lib = type("FakeLib", (), {"C_GetInterface": fake_get_interface})()
    raw = object.__new__(RawPKCS11)
    raw._funcs = {}
    raw._lib = None
    raw._load_from_ptr = Mock()
    raw._load_v30_from_ptr = Mock()
    raw._load_v32_from_ptr = Mock()

    with patch("pkcs11_check.raw.api.ctypes.CDLL", return_value=fake_lib):
        RawPKCS11._load_from_lib(raw, "/tmp/libpkcs11.so")

    assert fake_get_interface.calls == [(3, 2), (None, None)]
    function_list_ptr = ctypes.cast(
        ctypes.pointer(fake_get_interface.function_list), ctypes.c_void_p
    ).value
    raw._load_from_ptr.assert_called_once_with(function_list_ptr)
    raw._load_v30_from_ptr.assert_not_called()
    raw._load_v32_from_ptr.assert_not_called()


def test_from_lib_generic_30_interface_loads_v30_but_not_v32_tails() -> None:
    from pkcs11_check.raw.api import RawPKCS11
    from pkcs11_check.raw.types_std import (
        CK_INTERFACE,
        CK_INTERFACE_PTR,
        CK_VERSION,
        CK_VERSION_PTR,
        CKR_FUNCTION_FAILED,
        CKR_OK,
    )

    class FakeFunctionList(ctypes.Structure):
        _fields_ = [("version", CK_VERSION), ("reserved", ctypes.c_void_p)]

    class FakeGetInterface:
        def __init__(self) -> None:
            self.function_list = FakeFunctionList()
            self.function_list.version.major = 3
            self.function_list.version.minor = 0
            self.interface = CK_INTERFACE()
            self.interface.pInterfaceName = None
            self.interface.pFunctionList = ctypes.cast(
                ctypes.pointer(self.function_list), ctypes.c_void_p
            ).value
            self.interface.flags = 0
            self.interface_ptr = ctypes.pointer(self.interface)
            self.calls: list[tuple[int | None, int | None]] = []

        def __call__(
            self, _name: object, version: object, interface_out: object, _flags: object
        ) -> int:
            if version is not None:
                requested = ctypes.cast(version, CK_VERSION_PTR).contents
                self.calls.append((int(requested.major), int(requested.minor)))
                return CKR_FUNCTION_FAILED

            self.calls.append((None, None))
            ctypes.cast(interface_out, ctypes.POINTER(CK_INTERFACE_PTR))[0] = self.interface_ptr
            return CKR_OK

    fake_get_interface = FakeGetInterface()
    fake_lib = type("FakeLib", (), {"C_GetInterface": fake_get_interface})()
    raw = object.__new__(RawPKCS11)
    raw._funcs = {}
    raw._lib = None
    raw._load_from_ptr = Mock()
    raw._load_v30_from_ptr = Mock()
    raw._load_v32_from_ptr = Mock()

    with patch("pkcs11_check.raw.api.ctypes.CDLL", return_value=fake_lib):
        RawPKCS11._load_from_lib(raw, "/tmp/libpkcs11.so")

    assert fake_get_interface.calls == [(3, 2), (None, None)]
    function_list_ptr = ctypes.cast(
        ctypes.pointer(fake_get_interface.function_list), ctypes.c_void_p
    ).value
    raw._load_from_ptr.assert_called_once_with(function_list_ptr)
    raw._load_v30_from_ptr.assert_called_once_with(function_list_ptr)
    raw._load_v32_from_ptr.assert_not_called()


def test_call_log_starts_empty_after_reset() -> None:
    from pkcs11_check.raw.api import RawPKCS11

    raw = object.__new__(RawPKCS11)
    raw._funcs = {"C_Initialize": Mock(return_value=0)}
    from collections import defaultdict

    raw._call_log = defaultdict(int)

    assert raw.call_log == {}
    assert raw.call_count == 0


def test_call_log_increments_on_call() -> None:
    from pkcs11_check.raw.api import RawPKCS11

    raw = object.__new__(RawPKCS11)
    raw._funcs = {"C_Initialize": Mock(return_value=0)}
    from collections import defaultdict

    raw._call_log = defaultdict(int)

    raw.C_Initialize()

    assert raw.call_log == {"C_Initialize": 1}
    assert raw.call_count == 1

    raw.C_Initialize()
    raw.C_Initialize()

    assert raw.call_log == {"C_Initialize": 3}
    assert raw.call_count == 3


def test_call_log_reset_clears_counts() -> None:
    from pkcs11_check.raw.api import RawPKCS11

    raw = object.__new__(RawPKCS11)
    raw._funcs = {"C_Initialize": Mock(return_value=0)}
    from collections import defaultdict

    raw._call_log = defaultdict(int)

    raw.C_Initialize()
    assert raw.call_count == 1

    raw.reset_call_log()
    assert raw.call_log == {}
    assert raw.call_count == 0


def test_available_function_names_returns_set_of_loaded_functions() -> None:
    from pkcs11_check.raw.api import RawPKCS11

    raw = object.__new__(RawPKCS11)
    raw._funcs = {"C_Initialize": object(), "C_Finalize": object(), "C_GetSlotList": object()}

    names = raw.available_function_names()
    assert isinstance(names, set)
    assert names == {"C_Initialize", "C_Finalize", "C_GetSlotList"}


def test_call_log_returns_copy() -> None:
    from pkcs11_check.raw.api import RawPKCS11

    raw = object.__new__(RawPKCS11)
    raw._funcs = {"C_Initialize": Mock(return_value=0)}
    from collections import defaultdict

    raw._call_log = defaultdict(int)

    raw.C_Initialize()
    log_copy = raw.call_log
    log_copy["FAKE"] = 999

    assert "FAKE" not in raw.call_log
    from pkcs11_check.raw.api import RawPKCS11
    from pkcs11_check.raw.types_std import (
        CK_INTERFACE,
        CK_INTERFACE_PTR,
        CK_VERSION,
        CK_VERSION_PTR,
        CKR_OK,
    )

    class FakeFunctionList(ctypes.Structure):
        _fields_ = [("version", CK_VERSION), ("reserved", ctypes.c_void_p)]

    class FakeGetInterface:
        def __init__(self) -> None:
            self.function_list = FakeFunctionList()
            self.function_list.version.major = 3
            self.function_list.version.minor = 2
            self.interface = CK_INTERFACE()
            self.interface.pInterfaceName = None
            self.interface.pFunctionList = ctypes.cast(
                ctypes.pointer(self.function_list), ctypes.c_void_p
            ).value
            self.interface.flags = 0
            self.interface_ptr = ctypes.pointer(self.interface)
            self.calls: list[tuple[int | None, int | None]] = []

        def __call__(
            self, _name: object, version: object, interface_out: object, _flags: object
        ) -> int:
            requested = ctypes.cast(version, CK_VERSION_PTR).contents
            self.calls.append((int(requested.major), int(requested.minor)))
            ctypes.cast(interface_out, ctypes.POINTER(CK_INTERFACE_PTR))[0] = self.interface_ptr
            return CKR_OK

    fake_get_interface = FakeGetInterface()
    fake_lib = type("FakeLib", (), {"C_GetInterface": fake_get_interface})()
    raw = object.__new__(RawPKCS11)
    raw._funcs = {}
    raw._lib = None
    raw._load_from_ptr = Mock()
    raw._load_v30_from_ptr = Mock()
    raw._load_v32_from_ptr = Mock()

    with patch("pkcs11_check.raw.api.ctypes.CDLL", return_value=fake_lib):
        RawPKCS11._load_from_lib(raw, "/tmp/libpkcs11.so")

    assert fake_get_interface.calls == [(3, 2)]
    function_list_ptr = ctypes.cast(
        ctypes.pointer(fake_get_interface.function_list), ctypes.c_void_p
    ).value
    raw._load_from_ptr.assert_called_once_with(function_list_ptr)
    raw._load_v30_from_ptr.assert_called_once_with(function_list_ptr)
    raw._load_v32_from_ptr.assert_called_once_with(function_list_ptr)
