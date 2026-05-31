"""Generated metadata-driven raw PKCS#11 API."""

from __future__ import annotations

import ctypes
import json
import os
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

# Output-producing C_* functions: those routed through recipes._two_call_output,
# where the output byte-length is the *last* positional arg as byref(CK_ULONG).
# Gating by name is essential — C_DeriveKey/C_UnwrapKey/C_GenerateKeyPair also
# have a byref last arg, but it is a key HANDLE, not a length.  Kept honest by
# the drift-guard meta-test (every _two_call_output caller must be listed).
_OUTPUT_LEN_FUNCS = frozenset(
    {
        "C_Encrypt",
        "C_Decrypt",
        "C_Sign",
        "C_Digest",
        "C_SignRecover",
        "C_SignFinal",
        "C_DigestFinal",
        "C_EncryptFinal",  # via recipes._multipart_output(final_fn=...)
        "C_DecryptFinal",  # via recipes._multipart_output(final_fn=...)
        "C_WrapKey",
        "C_WrapKeyAuthenticated",
        "C_GetOperationState",
    }
)

# Single-shot input-data functions: the input byte-length is a by-value CK_ULONG
# at this positional index (ulDataLen).  Length only, never the bytes.
_INPUT_LEN_ARG = {
    "C_Encrypt": 2,
    "C_Decrypt": 2,
    "C_Sign": 2,
    "C_Digest": 2,
    "C_SignRecover": 2,
}

# out_len is meaningful only when the module actually set the length pointer.
_OUT_LEN_OK_RVS = (int(CKR_OK), int(CKR_BUFFER_TOO_SMALL))


def _coerce_len(value: Any) -> int | None:
    """Best-effort read of a length: a plain int, or a ctypes scalar's .value."""
    try:
        if isinstance(value, int):
            return value
        return int(value.value)
    except (AttributeError, TypeError, ValueError):
        return None


def _read_out_len(name: str, args: tuple[Any, ...], rv: int) -> int | None:
    """Output byte-length from the trailing byref(CK_ULONG), best-effort."""
    if name not in _OUTPUT_LEN_FUNCS or rv not in _OUT_LEN_OK_RVS or not args:
        return None
    try:
        return _coerce_len(args[-1]._obj)
    except (AttributeError, TypeError, IndexError):
        return None


def _read_in_len(name: str, args: tuple[Any, ...]) -> int | None:
    """Input byte-length from the by-value ulDataLen arg, best-effort."""
    idx = _INPUT_LEN_ARG.get(name)
    if idx is None or idx >= len(args):
        return None
    return _coerce_len(args[idx])


# Crash-survivable write-ahead journal: when PKCS11_CHECK_RV_TRACE_JOURNAL names a
# path, every C_* call writes a 'call' record *before* invoking the module and a
# 'ret' record *after*.  A process death (segfault/abort) between the two leaves
# an unmatched 'call' on disk = the exact crashing call.  Robust because it never
# tries to handle the signal (unsafe in a corrupted interpreter) — the data is
# already flushed to the kernel.  See docs/rv-trace-design.md (Phase 4).
_RV_TRACE_JOURNAL_PATH = os.environ.get("PKCS11_CHECK_RV_TRACE_JOURNAL")


def _journal_path(template: str) -> str:
    """Expand a ``{pid}`` placeholder so concurrent subprocesses don't collide."""
    return template.replace("{pid}", str(os.getpid()))


class _RvTraceJournal:
    """Append-only WAL of C_* calls (one 'call' + one 'ret' line each, flushed)."""

    def __init__(self, path: str) -> None:
        self._fh = open(path, "a", encoding="utf-8")  # noqa: SIM115 — lifetime = process
        self._n = 0

    def before(
        self, fn: str, mech: int | None, mech_params: dict[str, int] | None, in_len: int | None
    ) -> int:
        i = self._n
        self._n += 1
        rec: dict[str, Any] = {"ev": "call", "i": i, "fn": fn, "mech": mech}
        if mech_params:
            rec["mech_params"] = mech_params
        if in_len is not None:
            rec["in_len"] = in_len
        self._write(rec)
        return i

    def after(self, i: int, rv: int, rv_name: str, out_len: int | None) -> None:
        rec: dict[str, Any] = {"ev": "ret", "i": i, "rv": rv, "rv_name": rv_name}
        if out_len is not None:
            rec["out_len"] = out_len
        self._write(rec)

    def _write(self, rec: dict[str, Any]) -> None:
        self._fh.write(json.dumps(rec) + "\n")
        self._fh.flush()  # push to the kernel so a later segfault can't lose it


def read_crash_journal(
    path: str | os.PathLike[str],
) -> tuple[list[dict[str, Any]], dict[str, Any] | None]:
    """Parse a WAL journal into (completed_calls, last_incomplete_or_None).

    The last incomplete call (a 'call' with no matching 'ret') is the call the
    process died inside — the crash forensics payload. A torn final line (the
    crash interrupted a write) is skipped, not raised on.
    """
    completed: dict[int, dict[str, Any]] = {}
    pending: dict[int, dict[str, Any]] = {}
    order: list[int] = []
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue  # torn final line from a crash mid-write
            i = rec.get("i")
            if not isinstance(i, int):
                continue  # malformed/corrupt record -- keep the parser total
            if rec.get("ev") == "call":
                pending[i] = rec
                order.append(i)
            elif rec.get("ev") == "ret":
                call = pending.pop(i, {})
                completed[i] = {k: v for k, v in {**call, **rec}.items() if k != "ev"}
    done = [completed[i] for i in order if i in completed]
    last_incomplete: dict[str, Any] | None = None
    if pending:
        last_i = max(pending)
        last_incomplete = {k: v for k, v in pending[last_i].items() if k != "ev"}
    return done, last_incomplete


class RawPKCS11:
    """Raw ctypes access to PKCS#11 C_* functions."""

    # Class-default so partial test doubles (object.__new__) inherit None without
    # having to set it; real instances may override in __init__ when the journal
    # env var is set.
    _journal: _RvTraceJournal | None = None

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
        # Crash-survivable journal (off unless PKCS11_CHECK_RV_TRACE_JOURNAL set).
        if _RV_TRACE_JOURNAL_PATH:
            self._journal = _RvTraceJournal(_journal_path(_RV_TRACE_JOURNAL_PATH))

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
        tracing = self._rv_trace is not None or self._journal is not None
        mech_id: int | None = None
        mech_params: dict[str, int] | None = None
        if name in _MECHANISM_ARG_FUNCS and len(args) >= 2:
            try:
                obj = args[1]._obj
                m = obj.mechanism
                self._used_mechanisms.add(m)
                self._mechanism_counts[m] += 1
                mech_id = m
                if tracing:
                    sub = getattr(obj, "_rv_trace_sub", None)
                    if sub:
                        mech_params = {k: int(v) for k, v in sub.items()}
            except (AttributeError, TypeError):
                pass
        func = self._funcs.get(name)
        if func is None:
            raise AttributeError(f"{name} not available in this module")
        in_len = _read_in_len(name, args) if tracing else None
        journal_i = (
            self._journal.before(name, mech_id, mech_params, in_len)
            if self._journal is not None
            else None
        )
        result = int(func(*args))
        ckr = _to_ckr(result)
        out_len = _read_out_len(name, args, result) if tracing else None
        if journal_i is not None and self._journal is not None:
            self._journal.after(journal_i, result, str(ckr), out_len)
        if self._rv_trace is not None:
            entry: dict[str, Any] = {
                "i": self._rv_trace_total,
                "fn": name,
                "mech": mech_id,
                "rv": result,
                "rv_name": str(ckr),
            }
            if mech_params is not None:
                entry["mech_params"] = mech_params
            if in_len is not None:
                entry["in_len"] = in_len
            if out_len is not None:
                entry["out_len"] = out_len
            self._rv_trace.append(entry)
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
