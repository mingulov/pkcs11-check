"""Generated metadata-driven raw PKCS#11 API."""

from __future__ import annotations

import ctypes
from ctypes import byref, c_void_p, cast
from typing import Any

from . import metadata_std
from .types_std import *  # noqa: F401,F403

_PTR_SIZE = ctypes.sizeof(c_void_p)
_VERSION_SIZE = _PTR_SIZE
_V30_START = metadata_std.FUNCTION_INDICES["C_GetInterfaceList"]
_V32_START = metadata_std.FUNCTION_INDICES["C_EncapsulateKey"]


def _resolve_ctype(name: str) -> Any:
    return globals()[name]


def _build_function_type(name: str) -> Any:
    argtypes = [_resolve_ctype(arg_name) for arg_name in metadata_std.FUNCTION_SIGNATURES[name]]
    return ctypes.CFUNCTYPE(CK_RV, *argtypes)


_FUNCTION_TYPES = {name: _build_function_type(name) for name in metadata_std.FUNCTION_SIGNATURES}
_STANDARD_FUNCTION_NAMES = tuple(
    name
    for name, index in sorted(metadata_std.FUNCTION_INDICES.items(), key=lambda item: item[1])
    if index < _V30_START
)
_V30_FUNCTION_NAMES = tuple(
    name
    for name, index in sorted(metadata_std.FUNCTION_INDICES.items(), key=lambda item: item[1])
    if _V30_START <= index < _V32_START
)
_V32_FUNCTION_NAMES = tuple(
    name
    for name, index in sorted(metadata_std.FUNCTION_INDICES.items(), key=lambda item: item[1])
    if index >= _V32_START
)


class RawPKCS11:
    """Raw ctypes access to PKCS#11 C_* functions."""

    def __init__(
        self,
        funclist_ptr: int = 0,
        lib_path: str | None = None,
        funclist3_ptr: int = 0,
        funclist32_ptr: int = 0,
    ) -> None:
        self._funcs: dict[str, Any] = {}
        self._lib: ctypes.CDLL | None = None

        if funclist_ptr:
            self._load_from_ptr(funclist_ptr)
        elif lib_path:
            self._load_from_lib(lib_path)
        else:
            raise ValueError("Provide funclist_ptr or lib_path")

        if funclist3_ptr:
            self._load_v30_from_ptr(funclist3_ptr)
        if funclist32_ptr:
            self._load_v32_from_ptr(funclist32_ptr)

    def available_function_names(self) -> set[str]:
        return set(self._funcs)

    @property
    def interface_version(self) -> str:
        """Detect negotiated PKCS#11 interface version."""
        names = self.available_function_names()
        if "C_EncapsulateKey" in names:
            return "3.2"
        if "C_GetInterface" in names:
            return "3.0"  # 3.0 and 3.1 share the same function set
        return "2.40"

    def _load_functions_from_ptr(self, ptr: int, names: tuple[str, ...]) -> None:
        for name in names:
            offset = _VERSION_SIZE + (metadata_std.FUNCTION_INDICES[name] * _PTR_SIZE)
            addr_ptr = cast(ptr + offset, ctypes.POINTER(c_void_p))
            addr = addr_ptr.contents.value
            if addr:
                self._funcs[name] = _FUNCTION_TYPES[name](addr)

    def _load_from_ptr(self, ptr: int) -> None:
        self._load_functions_from_ptr(ptr, _STANDARD_FUNCTION_NAMES)

    def _load_v30_from_ptr(self, ptr: int) -> None:
        self._load_functions_from_ptr(ptr, _V30_FUNCTION_NAMES)

    def _load_v32_from_ptr(self, ptr: int) -> None:
        self._load_functions_from_ptr(ptr, _V32_FUNCTION_NAMES)

    def _function_list_version(self, ptr: int) -> tuple[int, int]:
        version = cast(ptr, ctypes.POINTER(CK_VERSION)).contents
        return version.major, version.minor

    def _load_versioned_function_list(self, ptr: int) -> None:
        self._load_from_ptr(ptr)
        major, minor = self._function_list_version(ptr)
        if (major, minor) >= (3, 0):
            self._load_v30_from_ptr(ptr)
        if (major, minor) >= (3, 2):
            self._load_v32_from_ptr(ptr)

    def _get_interface_function_list_ptr(
        self, get_interface: Any, version: tuple[int, int] | None
    ) -> int | None:
        interface_ptr = CK_INTERFACE_PTR()
        version_ptr = None
        requested_version: CK_VERSION | None = None
        if version is not None:
            requested_version = CK_VERSION()
            requested_version.major = version[0]
            requested_version.minor = version[1]
            version_ptr = byref(requested_version)

        rv = get_interface(None, version_ptr, byref(interface_ptr), 0)
        if rv != CKR_OK or not bool(interface_ptr):
            return None
        function_list_ptr = interface_ptr.contents.pFunctionList
        if not function_list_ptr:
            return None
        return int(function_list_ptr)

    def _load_from_lib(self, lib_path: str) -> None:
        self._lib = ctypes.CDLL(lib_path)

        try:
            get_interface = self._lib.C_GetInterface
            get_interface.restype = CK_RV
            get_interface.argtypes = [
                CK_UTF8CHAR_PTR,
                CK_VERSION_PTR,
                CK_INTERFACE_PTR_PTR,
                CK_FLAGS,
            ]
            function_list_ptr = self._get_interface_function_list_ptr(get_interface, (3, 2))
            if function_list_ptr is not None:
                self._load_versioned_function_list(function_list_ptr)
                return

            function_list_ptr = self._get_interface_function_list_ptr(get_interface, None)
            if function_list_ptr is not None:
                self._load_versioned_function_list(function_list_ptr)
                return
        except (AttributeError, OSError, TypeError, ValueError):
            pass

        get_function_list = self._lib.C_GetFunctionList
        get_function_list.restype = CK_RV
        get_function_list.argtypes = [CK_FUNCTION_LIST_PTR_PTR]
        function_list_ptr = CK_FUNCTION_LIST_PTR()
        rv = get_function_list(byref(function_list_ptr))
        if rv != CKR_OK:
            raise RuntimeError(f"C_GetFunctionList failed: 0x{rv:08x}")
        if not bool(function_list_ptr):
            raise RuntimeError("C_GetFunctionList returned NULL pointer")
        base_ptr = cast(function_list_ptr, c_void_p).value
        if base_ptr is None:
            raise RuntimeError("C_GetFunctionList returned NULL pointer")
        self._load_from_ptr(base_ptr)

    @classmethod
    def from_lib(cls, lib_path: str) -> RawPKCS11:
        return cls(lib_path=lib_path)

    def _call(self, name: str, *args: Any) -> int:
        func = self._funcs.get(name)
        if func is None:
            raise AttributeError(f"{name} not available in this module")
        return int(func(*args))


def _make_method(name: str) -> Any:
    def method(self: RawPKCS11, *args: Any) -> int:
        return self._call(name, *args)

    method.__name__ = name
    method.__qualname__ = f"RawPKCS11.{name}"
    return method


for _name in metadata_std.FUNCTION_SIGNATURES:
    setattr(RawPKCS11, _name, _make_method(_name))


__all__ = ["RawPKCS11"]
