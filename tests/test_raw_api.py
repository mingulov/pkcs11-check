from __future__ import annotations

import ctypes
from collections import Counter, defaultdict
from types import SimpleNamespace
from unittest.mock import Mock, patch

import pytest


def test_generated_standard_c_methods() -> None:
    from pkcs11_check.raw import metadata_std

    names = set(metadata_std.FUNCTION_SIGNATURES)
    assert "C_GetFunctionList" in names
    assert "C_CancelFunction" in names
    assert "C_DigestEncryptUpdate" in names
    for name in (
        "C_DigestXofInit",
        "C_DigestXof",
        "C_DigestXofUpdate",
        "C_DigestXofExtract",
        "C_DigestXofFinal",
        "C_DigestXofKeyValue",
    ):
        assert name in names
    assert len(names) >= 110


def test_rawpkcs11_loads_optional_exported_xof_functions() -> None:
    from pkcs11_check.raw.api import RawPKCS11
    from pkcs11_check.raw.types_std import CK_BYTE_PTR, CK_RV, CK_SESSION_HANDLE, CK_ULONG

    exported = Mock(return_value=0)
    fake_lib = SimpleNamespace(C_DigestXof=exported)
    raw = object.__new__(RawPKCS11)
    raw._funcs = {}
    raw._lib = fake_lib

    RawPKCS11._load_optional_exported_functions(raw)

    assert raw.available_function_names() == {"C_DigestXof"}
    assert exported.restype is CK_RV
    assert exported.argtypes == [
        CK_SESSION_HANDLE,
        CK_BYTE_PTR,
        CK_ULONG,
        CK_BYTE_PTR,
        CK_ULONG,
    ]


def test_xof_trace_records_input_and_requested_output_lengths() -> None:
    from pkcs11_check.raw.api import RawPKCS11
    from pkcs11_check.raw.types_std import CK_BYTE, CKR_OK

    raw = object.__new__(RawPKCS11)
    raw._funcs = {"C_DigestXof": Mock(return_value=CKR_OK)}
    raw._call_log = defaultdict(int)
    raw._call_log_ok = defaultdict(int)
    raw._used_mechanisms = set()
    raw._mechanism_counts = Counter()
    raw._mechanism_rv_counts = defaultdict(Counter)
    raw._journal = None
    raw.enable_rv_trace()

    in_buf = (CK_BYTE * 4).from_buffer_copy(b"data")
    out_buf = (CK_BYTE * 16)()

    raw.C_DigestXof(1, in_buf, 4, out_buf, 16)

    assert raw.rv_trace == [
        {
            "i": 0,
            "fn": "C_DigestXof",
            "mech": None,
            "rv": int(CKR_OK),
            "rv_name": "CKR_OK",
            "in_len": 4,
            "out_len": 16,
        }
    ]


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


def test_from_lib_explicit_v31_requests_exact_table_and_retains_provenance() -> None:
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
            self.function_list.version.minor = 1
            self.interface = CK_INTERFACE()
            self.interface.pFunctionList = ctypes.cast(
                ctypes.pointer(self.function_list), ctypes.c_void_p
            ).value
            self.interface_ptr = ctypes.pointer(self.interface)
            self.calls: list[tuple[int, int]] = []

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
    raw._dll_dir_handles = []
    raw._load_from_ptr = Mock()
    raw._load_v30_from_ptr = Mock()
    raw._load_v32_from_ptr = Mock()

    with patch("pkcs11_check.raw.api.ctypes.CDLL", return_value=fake_lib):
        RawPKCS11._load_from_lib(raw, "/tmp/libpkcs11.so", interface="3.1")

    assert fake_get_interface.calls == [(3, 1)]
    assert raw.interface_version == "3.1"


def test_from_lib_explicit_v31_does_not_fallback_to_legacy_function_list() -> None:
    from pkcs11_check.raw.api import RawPKCS11
    from pkcs11_check.raw.types_std import CKR_FUNCTION_FAILED

    class FakeGetInterface:
        def __call__(self, *_args: object) -> int:
            return CKR_FUNCTION_FAILED

    class FakeGetFunctionList:
        def __call__(self, *_args: object) -> int:
            raise AssertionError("explicit v3.1 must not call C_GetFunctionList")

    fake_lib = type(
        "FakeLib",
        (),
        {"C_GetInterface": FakeGetInterface(), "C_GetFunctionList": FakeGetFunctionList()},
    )()
    raw = object.__new__(RawPKCS11)
    raw._funcs = {}
    raw._lib = None
    raw._dll_dir_handles = []

    with (
        patch("pkcs11_check.raw.api.ctypes.CDLL", return_value=fake_lib),
        pytest.raises(RuntimeError, match="3.1"),
    ):
        RawPKCS11._load_from_lib(raw, "/tmp/libpkcs11.so", interface="3.1")


def test_from_lib_explicit_v240_rejects_non_240_function_table() -> None:
    from pkcs11_check.raw.api import RawPKCS11
    from pkcs11_check.raw.types_std import CK_FUNCTION_LIST_PTR, CK_VERSION, CKR_OK

    class FakeFunctionList(ctypes.Structure):
        _fields_ = [("version", CK_VERSION), ("reserved", ctypes.c_void_p)]

    function_list = FakeFunctionList()
    function_list.version.major = 3
    function_list.version.minor = 1
    function_list_ptr = ctypes.pointer(function_list)

    class FakeGetFunctionList:
        def __call__(self, output: object) -> int:
            ctypes.cast(output, ctypes.POINTER(CK_FUNCTION_LIST_PTR))[0] = ctypes.cast(
                function_list_ptr, CK_FUNCTION_LIST_PTR
            )
            return CKR_OK

    fake_lib = type("FakeLib", (), {"C_GetFunctionList": FakeGetFunctionList()})()
    raw = object.__new__(RawPKCS11)
    raw._funcs = {}
    raw._lib = None
    raw._dll_dir_handles = []

    with (
        patch("pkcs11_check.raw.api.ctypes.CDLL", return_value=fake_lib),
        pytest.raises(RuntimeError, match="2.40"),
    ):
        RawPKCS11._load_from_lib(raw, "/tmp/libpkcs11.so", interface="2.40")


@pytest.mark.parametrize(
    ("rv", "label"),
    [(0x00000006, "CKR_FUNCTION_FAILED"), (0x12345678, "0x12345678")],
)
def test_explicit_v3_lookup_preserves_non_ok_rv(rv: int, label: str) -> None:
    from pkcs11_check.raw.api import InterfaceLookupError, RawPKCS11

    class FakeGetInterface:
        def __call__(self, *_args: object) -> int:
            return rv

    fake_lib = type("FakeLib", (), {"C_GetInterface": FakeGetInterface()})()
    raw = object.__new__(RawPKCS11)
    raw._funcs = {}
    raw._lib = None
    raw._dll_dir_handles = []

    with (
        patch("pkcs11_check.raw.api.ctypes.CDLL", return_value=fake_lib),
        pytest.raises(InterfaceLookupError) as exc_info,
    ):
        RawPKCS11._load_from_lib(raw, "/tmp/libpkcs11.so", interface="3.1")

    assert exc_info.value.requested_interface == "3.1"
    assert exc_info.value.reason == "rv"
    assert exc_info.value.rv == rv
    assert label in str(exc_info.value)


def test_explicit_v3_lookup_distinguishes_null_interface_pointer() -> None:
    from pkcs11_check.raw.api import InterfaceLookupError, RawPKCS11
    from pkcs11_check.raw.types_std import CKR_OK

    class FakeGetInterface:
        def __call__(self, _name: object, _version: object, _out: object, _flags: object) -> int:
            return CKR_OK

    fake_lib = type("FakeLib", (), {"C_GetInterface": FakeGetInterface()})()
    raw = object.__new__(RawPKCS11)
    raw._funcs = {}
    raw._lib = None
    raw._dll_dir_handles = []

    with (
        patch("pkcs11_check.raw.api.ctypes.CDLL", return_value=fake_lib),
        pytest.raises(InterfaceLookupError) as exc_info,
    ):
        RawPKCS11._load_from_lib(raw, "/tmp/libpkcs11.so", interface="3.1")

    assert exc_info.value.requested_interface == "3.1"
    assert exc_info.value.reason == "null_interface"
    assert exc_info.value.rv == int(CKR_OK)
    assert "NULL interface pointer" in str(exc_info.value)


def test_explicit_v3_lookup_distinguishes_null_function_list_pointer() -> None:
    from pkcs11_check.raw.api import InterfaceLookupError, RawPKCS11
    from pkcs11_check.raw.types_std import CK_INTERFACE, CK_INTERFACE_PTR, CKR_OK

    interface = CK_INTERFACE()
    interface.pFunctionList = None
    interface_ptr = ctypes.pointer(interface)

    class FakeGetInterface:
        def __call__(self, _name: object, _version: object, out: object, _flags: object) -> int:
            ctypes.cast(out, ctypes.POINTER(CK_INTERFACE_PTR))[0] = interface_ptr
            return CKR_OK

    fake_lib = type("FakeLib", (), {"C_GetInterface": FakeGetInterface()})()
    raw = object.__new__(RawPKCS11)
    raw._funcs = {}
    raw._lib = None
    raw._dll_dir_handles = []

    with (
        patch("pkcs11_check.raw.api.ctypes.CDLL", return_value=fake_lib),
        pytest.raises(InterfaceLookupError) as exc_info,
    ):
        RawPKCS11._load_from_lib(raw, "/tmp/libpkcs11.so", interface="3.1")

    assert exc_info.value.requested_interface == "3.1"
    assert exc_info.value.reason == "null_function_list"
    assert exc_info.value.rv == int(CKR_OK)
    assert "NULL pFunctionList" in str(exc_info.value)


def test_explicit_v3_lookup_rejects_mismatched_table_version() -> None:
    from pkcs11_check.raw.api import RawPKCS11
    from pkcs11_check.raw.types_std import CK_INTERFACE, CK_INTERFACE_PTR, CK_VERSION, CKR_OK

    class FakeFunctionList(ctypes.Structure):
        _fields_ = [("version", CK_VERSION), ("reserved", ctypes.c_void_p)]

    function_list = FakeFunctionList()
    function_list.version.major = 3
    function_list.version.minor = 0
    interface = CK_INTERFACE()
    interface.pFunctionList = ctypes.cast(
        ctypes.pointer(function_list), ctypes.c_void_p
    ).value
    interface_ptr = ctypes.pointer(interface)

    class FakeGetInterface:
        def __call__(self, _name: object, _version: object, out: object, _flags: object) -> int:
            ctypes.cast(out, ctypes.POINTER(CK_INTERFACE_PTR))[0] = interface_ptr
            return CKR_OK

    fake_lib = type("FakeLib", (), {"C_GetInterface": FakeGetInterface()})()
    raw = object.__new__(RawPKCS11)
    raw._funcs = {}
    raw._lib = None
    raw._dll_dir_handles = []

    with (
        patch("pkcs11_check.raw.api.ctypes.CDLL", return_value=fake_lib),
        pytest.raises(RuntimeError, match="Requested PKCS#11 interface 3.1, got table 3.0"),
    ):
        RawPKCS11._load_from_lib(raw, "/tmp/libpkcs11.so", interface="3.1")


def test_unknown_interface_rejected_before_cdll_load() -> None:
    from pkcs11_check.raw.api import RawPKCS11

    with (
        patch("pkcs11_check.raw.api.ctypes.CDLL") as cdll,
        pytest.raises(ValueError, match="Unknown interface '3.3'"),
    ):
        RawPKCS11.from_lib("/tmp/libpkcs11.so", interface="3.3")

    cdll.assert_not_called()


def test_direct_pointer_table_header_retains_exact_31_provenance() -> None:
    from pkcs11_check.raw.api import RawPKCS11
    from pkcs11_check.raw.types_std import CK_VERSION

    class FakeFunctionList(ctypes.Structure):
        _fields_ = [("version", CK_VERSION), ("reserved", ctypes.c_void_p)]

    function_list = FakeFunctionList()
    function_list.version.major = 3
    function_list.version.minor = 1
    raw = object.__new__(RawPKCS11)
    raw._funcs = {}
    raw._load_functions_from_ptr = Mock()

    ptr = ctypes.cast(ctypes.pointer(function_list), ctypes.c_void_p).value
    assert ptr is not None
    RawPKCS11._load_from_ptr(raw, ptr)

    assert raw.interface_version == "3.1"


def test_from_lib_surfaces_get_interface_access_violation() -> None:
    from pkcs11_check.raw.api import RawPKCS11

    class FakeGetInterface:
        restype: object = None
        argtypes: object = None

        def __call__(self, *_args: object) -> int:
            raise OSError("exception: access violation reading 0x0")

    fake_lib = SimpleNamespace(C_GetInterface=FakeGetInterface())
    raw = object.__new__(RawPKCS11)
    raw._funcs = {}
    raw._lib = None
    raw._dll_dir_handles = []

    with (
        patch("pkcs11_check.raw.api.ctypes.CDLL", return_value=fake_lib),
        pytest.raises(OSError, match="access violation"),
    ):
        RawPKCS11._load_from_lib(raw, "/tmp/libpkcs11.so")


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
    raw._call_log_ok = defaultdict(int)

    assert raw.call_log == {}
    assert raw.call_count == 0


def test_call_log_increments_on_call() -> None:
    from pkcs11_check.raw.api import RawPKCS11

    raw = object.__new__(RawPKCS11)
    raw._funcs = {"C_Initialize": Mock(return_value=0)}

    raw._call_log = defaultdict(int)
    raw._call_log_ok = defaultdict(int)
    raw._rv_trace = None

    raw.C_Initialize()

    assert raw.call_log == {"C_Initialize": 1}
    assert raw.call_count == 1

    raw.C_Initialize()
    raw.C_Initialize()

    assert raw.call_log == {"C_Initialize": 3}
    assert raw.call_count == 3


def test_mechanism_rv_counts_track_accept_and_clean_reject() -> None:
    from pkcs11_check.raw.api import RawPKCS11
    from pkcs11_check.raw.types_std import (
        CK_MECHANISM,
        CKM_AES_CBC,
        CKR_MECHANISM_INVALID,
        CKR_OK,
    )

    raw = object.__new__(RawPKCS11)
    raw._funcs = {"C_EncryptInit": Mock(side_effect=[CKR_OK, CKR_MECHANISM_INVALID])}
    raw._call_log = defaultdict(int)
    raw._call_log_ok = defaultdict(int)
    raw._used_mechanisms = set()
    raw._mechanism_counts = Counter()
    raw._mechanism_rv_counts = defaultdict(Counter)
    raw._rv_trace = None
    raw._journal = None
    mech = CK_MECHANISM(CKM_AES_CBC, None, 0)

    raw.C_EncryptInit(1, ctypes.byref(mech), 2)
    raw.C_EncryptInit(1, ctypes.byref(mech), 2)

    assert raw.mechanism_counts == {int(CKM_AES_CBC): 2}
    assert raw.mechanism_rv_counts == {
        int(CKM_AES_CBC): {
            int(CKR_OK): 1,
            int(CKR_MECHANISM_INVALID): 1,
        }
    }


def test_call_log_reset_clears_counts() -> None:
    from pkcs11_check.raw.api import RawPKCS11

    raw = object.__new__(RawPKCS11)
    raw._funcs = {"C_Initialize": Mock(return_value=0)}

    raw._call_log = defaultdict(int)
    raw._call_log_ok = defaultdict(int)
    raw._rv_trace = None

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


def _synthetic_function_table(
    major: int,
    minor: int,
    *,
    non_null: tuple[str, ...] = (),
) -> tuple[int, object, tuple[object, ...]]:
    from pkcs11_check.raw import api, metadata_std
    from pkcs11_check.raw.types_std import CK_VERSION, CKR_FUNCTION_NOT_SUPPORTED

    size = api._VERSION_SIZE + (max(metadata_std.FUNCTION_INDICES.values()) + 1) * api._PTR_SIZE
    table = (ctypes.c_ubyte * size)()
    version = ctypes.cast(ctypes.addressof(table), ctypes.POINTER(CK_VERSION)).contents
    version.major = major
    version.minor = minor
    slots = ctypes.cast(
        ctypes.addressof(table) + api._VERSION_SIZE,
        ctypes.POINTER(ctypes.c_void_p),
    )
    callbacks: list[object] = []
    for name in non_null:
        callback_type = api._FUNCTION_TYPES[name]
        callback = callback_type(lambda *_args: int(CKR_FUNCTION_NOT_SUPPORTED))
        callbacks.append(callback)
        slots[metadata_std.FUNCTION_INDICES[name]] = ctypes.cast(callback, ctypes.c_void_p).value
    return ctypes.addressof(table), table, tuple(callbacks)


@pytest.mark.parametrize(
    ("version", "unselected"),
    [
        ((2, 40), "v30_v32"),
        ((3, 0), "v32"),
        ((3, 2), "none"),
    ],
)
def test_missing_function_list_names_tracks_only_selected_layout(
    version: tuple[int, int], unselected: str
) -> None:
    from pkcs11_check.raw import api

    ptr, table, callbacks = _synthetic_function_table(*version)
    raw = api.RawPKCS11(funclist_ptr=ptr)
    if version >= (3, 0):
        raw._load_versioned_function_list(ptr)

    selected_names = {
        name
        for name, index in api.metadata_std.FUNCTION_INDICES.items()
        if index < api._V30_START
        or (version >= (3, 0) and index < api._V32_START)
        or (version >= (3, 2) and index >= api._V32_START)
    }
    missing = raw.missing_function_list_names()
    assert missing == selected_names
    missing.clear()
    assert raw.missing_function_list_names() == selected_names
    assert raw.available_function_names() == set()
    if unselected == "v30_v32":
        assert missing.isdisjoint(api._V30_FUNCTION_NAMES + api._V32_FUNCTION_NAMES)
    elif unselected == "v32":
        assert missing.isdisjoint(api._V32_FUNCTION_NAMES)


def test_non_null_function_list_stub_is_available_and_not_missing() -> None:
    from pkcs11_check.raw import api
    from pkcs11_check.raw.types_std import CKR_FUNCTION_NOT_SUPPORTED

    ptr, table, callbacks = _synthetic_function_table(2, 40, non_null=("C_GetOperationState",))
    raw = api.RawPKCS11(funclist_ptr=ptr)
    state_len = ctypes.c_ulong(0)

    assert "C_GetOperationState" in raw.available_function_names()
    assert "C_GetOperationState" not in raw.missing_function_list_names()
    assert raw.C_GetOperationState(1, None, ctypes.byref(state_len)) == CKR_FUNCTION_NOT_SUPPORTED
    del table, callbacks


def test_non_null_selected_pointer_discards_prior_missing_entry() -> None:
    from pkcs11_check.raw import api

    null_ptr, null_table, null_callbacks = _synthetic_function_table(2, 40)
    raw = api.RawPKCS11(funclist_ptr=null_ptr)
    assert "C_Initialize" in raw.missing_function_list_names()

    selected_ptr, selected_table, selected_callbacks = _synthetic_function_table(
        2, 40, non_null=("C_Initialize",)
    )
    raw._load_functions_from_ptr(selected_ptr, ("C_Initialize",))

    assert "C_Initialize" not in raw.missing_function_list_names()
    del null_table, null_callbacks, selected_table, selected_callbacks


def test_null_reload_removes_stale_callable_and_records_missing_entry() -> None:
    """A later selected table with a NULL slot must revoke the old callable."""
    from pkcs11_check.raw import api

    selected_ptr, selected_table, selected_callbacks = _synthetic_function_table(
        2, 40, non_null=("C_Initialize",)
    )
    raw = api.RawPKCS11(funclist_ptr=selected_ptr)
    assert "C_Initialize" in raw.available_function_names()

    null_ptr, null_table, null_callbacks = _synthetic_function_table(2, 40)
    raw._load_functions_from_ptr(null_ptr, ("C_Initialize",))

    assert "C_Initialize" not in raw.available_function_names()
    assert "C_Initialize" not in raw._funcs
    assert "C_Initialize" in raw.missing_function_list_names()
    del selected_table, selected_callbacks, null_table, null_callbacks


def test_call_log_returns_copy() -> None:
    from pkcs11_check.raw.api import RawPKCS11

    raw = object.__new__(RawPKCS11)
    raw._funcs = {"C_Initialize": Mock(return_value=0)}
    from collections import defaultdict

    raw._call_log = defaultdict(int)
    raw._call_log_ok = defaultdict(int)
    raw._rv_trace = None

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
