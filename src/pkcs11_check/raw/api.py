"""Generated metadata-driven raw PKCS#11 API."""

from __future__ import annotations

import ctypes
from collections import Counter, defaultdict, deque
from ctypes import byref, c_void_p, cast
from typing import Any

from . import metadata_std
from .types_std import *  # noqa: F401,F403,F405

_PTR_SIZE = ctypes.sizeof(c_void_p)

# Reverse lookups: int -> named constant
_CKR_BY_VALUE: dict[int, CKR] = {}
_CKM_BY_VALUE: dict[int, CKM] = {}
_CK_PREFIX_LOOKUPS: dict[str, dict[int, Any]] = {}  # prefix -> {value -> constant}


def _build_constant_lookups() -> None:
    """Populate reverse lookup tables from all named constants in types_std."""
    import importlib

    mod = importlib.import_module("pkcs11_check.raw.types_std")
    for attr_name in dir(mod):
        obj = getattr(mod, attr_name)
        if not isinstance(obj, int) or not hasattr(obj, "_name"):
            continue
        val = int(obj)
        if attr_name.startswith("CKR_"):
            _CKR_BY_VALUE[val] = obj  # type: ignore[assignment]
        elif attr_name.startswith("CKM_"):
            _CKM_BY_VALUE[val] = obj  # type: ignore[assignment]
        if hasattr(obj, "_name") and obj._name:
            prefix = attr_name.split("_", 1)[0] + "_"
            lookup = _CK_PREFIX_LOOKUPS.setdefault(prefix, {})
            lookup[val] = obj


_build_constant_lookups()


def _to_ckr(rv: int) -> CKR:
    """Convert a raw return value to a named CKR constant."""
    known = _CKR_BY_VALUE.get(rv)
    if known is not None:
        return known
    return CKR(rv)


def ckm_name(mechanism_id: int) -> str:
    """Return the CKM_* name for a mechanism ID, or hex if unknown."""
    obj = _CKM_BY_VALUE.get(mechanism_id)
    if obj is not None:
        return str(obj)
    return f"0x{mechanism_id:08x}"


def constant_name(value: int, prefix: str = "") -> str:
    """Return the name of a CK_CONSTANT by value, optionally filtering by prefix."""
    if prefix:
        lookup = _CK_PREFIX_LOOKUPS.get(prefix, {})
        obj = lookup.get(value)
        if obj is not None:
            return str(obj)
    obj = _CKM_BY_VALUE.get(value)
    if obj is not None:
        return str(obj)
    return f"0x{value:08x}"


_SUB_PARAM_PREFIXES: dict[str, str] = {"mgf": "CKG_", "kdf": "CKD_"}


def sub_param_name(param_name: str, value: int) -> str:
    """Return the named constant for a sub-mechanism parameter value."""
    prefix = _SUB_PARAM_PREFIXES.get(param_name)
    if prefix:
        return constant_name(value, prefix)
    return ckm_name(value)


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


_MECHANISM_ARG_FUNCS = frozenset(
    {
        "C_EncryptInit",
        "C_DecryptInit",
        "C_DigestInit",
        "C_SignInit",
        "C_VerifyInit",
        "C_SignRecoverInit",
        "C_VerifyRecoverInit",
        "C_GenerateKey",
        "C_GenerateKeyPair",
        "C_WrapKey",
        "C_UnwrapKey",
        "C_DeriveKey",
        "C_MessageEncryptInit",
        "C_MessageDecryptInit",
        "C_MessageSignInit",
        "C_MessageVerifyInit",
        # v3.2 functions that take CK_MECHANISM_PTR
        "C_EncapsulateKey",
        "C_DecapsulateKey",
        "C_WrapKeyAuthenticated",
        "C_UnwrapKeyAuthenticated",
    }
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
        self._call_log: dict[str, int] = defaultdict(int)
        self._used_mechanisms: set[int] = set()
        self._mechanism_counts: Counter[int] = Counter()
        # Optional per-test CK_RV trace (off unless enable_rv_trace() is called).
        # When None, _call records nothing and output is byte-identical.
        self._rv_trace: deque[dict[str, Any]] | None = None
        self._rv_trace_total: int = 0

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
        except (AttributeError, OSError):
            pass  # Module does not export C_GetInterface or library load failed

        get_function_list = self._lib.C_GetFunctionList
        get_function_list.restype = CK_RV
        get_function_list.argtypes = [CK_FUNCTION_LIST_PTR_PTR]
        # The earlier `function_list_ptr` (int | None from interface lookup) is
        # rebound here to a CK_FUNCTION_LIST_PTR ctypes object — different type
        # but same logical role. Use a fresh local to keep mypy happy.
        fn_list_ptr = CK_FUNCTION_LIST_PTR()
        rv = get_function_list(byref(fn_list_ptr))
        if rv != CKR_OK:
            raise RuntimeError(f"C_GetFunctionList failed: 0x{rv:08x}")
        if not bool(fn_list_ptr):
            raise RuntimeError("C_GetFunctionList returned NULL pointer")
        base_ptr = cast(fn_list_ptr, c_void_p).value
        if base_ptr is None:
            raise RuntimeError("C_GetFunctionList returned NULL pointer")
        self._load_from_ptr(base_ptr)

    @property
    def call_log(self) -> dict[str, int]:
        return dict(self._call_log)

    @property
    def call_count(self) -> int:
        return sum(self._call_log.values())

    def reset_call_log(self) -> None:
        self._call_log.clear()

    @property
    def used_mechanisms(self) -> set[int]:
        return set(self._used_mechanisms)

    @property
    def mechanism_counts(self) -> dict[int, int]:
        """Per-mechanism invocation counts (CKM int -> call count)."""
        return dict(self._mechanism_counts)

    def reset_used_mechanisms(self) -> None:
        self._used_mechanisms.clear()
        self._mechanism_counts.clear()

    def enable_rv_trace(self, *, maxlen: int | None = None) -> None:
        """Start (or restart) per-test CK_RV tracing.

        ``maxlen=None`` keeps the full trace; an int keeps only the last N
        entries (a ring buffer) while still counting every call, so
        ``rv_trace_dropped`` reports how many leading entries were elided.
        Doubles as the per-test reset (fresh buffer, zeroed counter).
        """
        self._rv_trace = deque(maxlen=maxlen)
        self._rv_trace_total = 0

    def reset_rv_trace(self) -> None:
        """Clear the trace for the next test, preserving the configured maxlen.

        No-op when tracing was never enabled.
        """
        if self._rv_trace is not None:
            self._rv_trace.clear()
        self._rv_trace_total = 0

    @property
    def rv_trace_enabled(self) -> bool:
        """True once enable_rv_trace() has been called (distinguishes off vs empty)."""
        return self._rv_trace is not None

    @property
    def rv_trace(self) -> list[dict[str, Any]]:
        """A copy of the current trace entries (empty when tracing is off)."""
        if self._rv_trace is None:
            return []
        return list(self._rv_trace)

    @property
    def rv_trace_dropped(self) -> int:
        """Count of leading trace entries elided by the ring buffer (0 in full mode)."""
        if self._rv_trace is None:
            return 0
        return max(0, self._rv_trace_total - len(self._rv_trace))

    @classmethod
    def from_lib(cls, lib_path: str) -> RawPKCS11:
        return cls(lib_path=lib_path)

    def _call(self, name: str, *args: Any) -> CKR:
        self._call_log[name] += 1
        mech_id: int | None = None
        if name in _MECHANISM_ARG_FUNCS and len(args) >= 2:
            try:
                m = args[1]._obj.mechanism
                self._used_mechanisms.add(m)
                self._mechanism_counts[m] += 1
                mech_id = m
            except (AttributeError, TypeError):
                pass
        func = self._funcs.get(name)
        if func is None:
            raise AttributeError(f"{name} not available in this module")
        result = int(func(*args))
        ckr = _to_ckr(result)
        if self._rv_trace is not None:
            self._rv_trace.append(
                {
                    "i": self._rv_trace_total,
                    "fn": name,
                    "mech": mech_id,
                    "rv": result,
                    "rv_name": str(ckr),
                }
            )
            self._rv_trace_total += 1
        return ckr

    # C_* methods (C_Initialize, C_GenerateKey, C_OpenSession, ...) are attached
    # to the class at module load via the `setattr(RawPKCS11, name, ...)` loop
    # below. Static type-checkers do not see those, so this fallback keeps
    # `obj.C_X(...)` type-checking without per-call-site `# type: ignore`.
    # Runtime is unchanged: this fires only when normal attribute lookup
    # fails, so the AttributeError for actually-missing names matches the
    # default Python behavior.
    def __getattr__(self, name: str) -> Any:
        raise AttributeError(f"{type(self).__name__!r} object has no attribute {name!r}")


def _make_method(name: str) -> Any:
    def method(self: RawPKCS11, *args: Any) -> CKR:
        return self._call(name, *args)

    method.__name__ = name
    method.__qualname__ = f"RawPKCS11.{name}"
    return method


for _name in metadata_std.FUNCTION_SIGNATURES:
    setattr(RawPKCS11, _name, _make_method(_name))


__all__ = ["RawPKCS11"]
