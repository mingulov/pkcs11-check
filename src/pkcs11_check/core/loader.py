"""PKCS#11 module loading and interface negotiation.

Uses RawPKCS11.from_lib() directly -- no python-pkcs11 fork dependency.
"""

from __future__ import annotations

import ctypes
from ctypes import byref
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from pkcs11_check.raw.api import RawPKCS11
from pkcs11_check.raw.bootstrap import get_slot_ids
from pkcs11_check.raw.types_std import (
    CK_MECHANISM_INFO,
    CK_MECHANISM_TYPE,
    CK_TOKEN_INFO,
    CK_ULONG,
    CKR_CRYPTOKI_ALREADY_INITIALIZED,
    CKR_OK,
)

SUPPORTED_INTERFACES = ("auto", "2.40", "3.0", "3.1", "3.2")


# ---------------------------------------------------------------------------
# Thin wrappers -- provide the same duck-typed interface as python-pkcs11 Slot
# and Token objects, implemented over RawPKCS11 calls.
# ---------------------------------------------------------------------------


class MechInfo:
    """Minimal mechanism info wrapper (replaces python-pkcs11 MechanismInfo)."""

    __slots__ = ("min_key_length", "max_key_length", "flags")

    def __init__(self, min_key: int, max_key: int, flags: int) -> None:
        self.min_key_length = min_key
        self.max_key_length = max_key
        self.flags = flags


class MechValue(int):
    """Integer mechanism value with a .name attribute for compatibility."""

    _mech_names: dict[int, str] | None = None

    @classmethod
    def _get_names(cls) -> dict[int, str]:
        if cls._mech_names is None:
            from pkcs11_check.raw.metadata_std import MECHANISM_NAMES

            cls._mech_names = MECHANISM_NAMES
        return cls._mech_names

    @property
    def name(self) -> str:
        """Return canonical CKM_ name, or hex fallback."""
        names = self._get_names()
        full = names.get(self, "")
        # Strip leading CKM_ to match python-pkcs11 Mechanism.name convention
        if full.startswith("CKM_"):
            return full[4:]
        return full or f"0x{self:08x}"

    def __repr__(self) -> str:
        return f"<MechValue {self.name}>"


class RawToken:
    """Minimal token info wrapper (replaces python-pkcs11 Token)."""

    def __init__(self, slot_id: int, raw: RawPKCS11) -> None:
        self._slot_id = slot_id
        self._raw = raw
        self._info: CK_TOKEN_INFO | None = None

    def _get_info(self) -> CK_TOKEN_INFO:
        if self._info is None:
            info = CK_TOKEN_INFO()
            rv = self._raw.C_GetTokenInfo(self._slot_id, byref(info))
            if rv != CKR_OK:
                raise RuntimeError(f"C_GetTokenInfo failed: 0x{rv:08x}")
            self._info = info
        return self._info

    @property
    def label(self) -> str:
        return bytes(self._get_info().label).decode("utf-8").strip()

    @property
    def manufacturer_id(self) -> str:
        return bytes(self._get_info().manufacturerID).decode("utf-8").strip()

    @property
    def model(self) -> str:
        return bytes(self._get_info().model).decode("utf-8").strip()

    def open(self, rw: bool = False) -> Any:
        """Not implemented in the raw loader -- use fixtures.py raw bootstrap."""
        raise NotImplementedError(
            "RawToken.open() not supported -- use p11_raw_session fixture or "
            "raw bootstrap helpers directly (Task 2 will replace this path)."
        )


class RawSlot:
    """Minimal slot wrapper (replaces python-pkcs11 Slot).

    Provides get_mechanisms(), get_mechanism_info(), and get_token() so that
    callers that duck-typed against python-pkcs11 Slot continue to work.
    """

    def __init__(self, slot_id: int, raw: RawPKCS11) -> None:
        self._slot_id = slot_id
        self._raw = raw

    @property
    def slot_id(self) -> int:
        return self._slot_id

    def get_mechanisms(self) -> list[MechValue]:
        """Return mechanism list for this slot."""
        count = CK_ULONG(0)
        rv = self._raw.C_GetMechanismList(self._slot_id, None, byref(count))
        if rv != CKR_OK:
            raise RuntimeError(f"C_GetMechanismList (count) failed: 0x{rv:08x}")
        if count.value == 0:
            return []
        mechs = (CK_MECHANISM_TYPE * count.value)()
        rv = self._raw.C_GetMechanismList(self._slot_id, mechs, byref(count))
        if rv != CKR_OK:
            raise RuntimeError(f"C_GetMechanismList failed: 0x{rv:08x}")
        return [MechValue(mechs[i]) for i in range(count.value)]

    def get_mechanism_info(self, mech: Any) -> MechInfo | None:
        """Return mechanism info for a single mechanism."""
        info = CK_MECHANISM_INFO()
        rv = self._raw.C_GetMechanismInfo(self._slot_id, mech, byref(info))
        if rv != CKR_OK:
            return None
        return MechInfo(
            min_key=info.ulMinKeySize,
            max_key=info.ulMaxKeySize,
            flags=info.flags,
        )

    def get_token(self) -> RawToken:
        """Return token info for this slot."""
        return RawToken(self._slot_id, self._raw)


# ---------------------------------------------------------------------------
# P11Module
# ---------------------------------------------------------------------------


@dataclass
class P11Module:
    """A loaded PKCS#11 module with negotiated interface."""

    path: Path
    _raw: RawPKCS11
    # lib is intentionally None -- python-pkcs11 fork no longer used.
    # Tests that access p11_module.lib will get None and should be updated
    # to use p11_module.raw or the raw bootstrap helpers instead.
    lib: Any = None
    # Count of mid-run re-initializations (a proxied provider crashed and the
    # proxy restarted, so the client lost its C_Initialize state). ~one per
    # provider restart; surfaced so the recovery is never silent.
    reinit_count: int = 0

    @property
    def raw(self) -> RawPKCS11:
        """Return the underlying RawPKCS11 instance."""
        return self._raw

    def reinitialize(self) -> None:
        """Re-establish C_Initialize state after the library lost it.

        When a proxied provider crashes and the proxy restarts, the loaded
        client module survives but returns ``CKR_CRYPTOKI_NOT_INITIALIZED``
        until re-initialized. ``C_Finalize`` is best-effort (it drops any stale
        "initialized" belief so ``C_Initialize`` reconnects); ``C_Initialize``
        must then succeed (``CKR_OK`` or ``CKR_CRYPTOKI_ALREADY_INITIALIZED``).
        """
        try:
            self._raw.C_Finalize(None)
        except (AttributeError, OSError):
            pass
        rv = int(self._raw.C_Initialize(None))
        if rv not in (CKR_OK, CKR_CRYPTOKI_ALREADY_INITIALIZED):
            raise RuntimeError(f"re-C_Initialize failed: 0x{rv:08x}")
        self.reinit_count += 1

    @property
    def interface_version(self) -> str:
        """Negotiated PKCS#11 interface version string."""
        return self._raw.interface_version

    def get_slots(self, token_present: bool = False) -> list[RawSlot]:
        """Return available slots as RawSlot wrappers."""
        slot_ids = get_slot_ids(self._raw, token_present=token_present)
        return [RawSlot(sid, self._raw) for sid in slot_ids]

    def get_slot_ids(self, token_present: bool = False) -> list[int]:
        """Return raw slot ID integers."""
        return get_slot_ids(self._raw, token_present=token_present)

    def get_token(self, slot_index: int = 0) -> RawToken:
        """Return the token at the given slot index."""
        slots = self.get_slots(token_present=True)
        if slot_index >= len(slots):
            msg = f"Slot {slot_index} not found (available: {len(slots)})"
            raise IndexError(msg)
        return slots[slot_index].get_token()

    def get_interface_list(self) -> list[tuple[str, int, int]]:
        """Return supported interfaces when the module exposes C_GetInterfaceList.

        Returns list of (name, major, minor) tuples.
        Returns [] for v2.40 modules that lack C_GetInterfaceList.
        """
        if "C_GetInterfaceList" not in self._raw.available_function_names():
            return []
        from pkcs11_check.raw.types_std import (
            CK_INTERFACE,
        )

        # First call: get count
        count = CK_ULONG(0)
        rv = self._raw.C_GetInterfaceList(None, byref(count))
        if rv != CKR_OK or count.value == 0:
            return []

        # Second call: get list
        iface_array = (CK_INTERFACE * count.value)()
        rv = self._raw.C_GetInterfaceList(iface_array, byref(count))
        if rv != CKR_OK:
            return []

        result = []
        for i in range(count.value):
            iface = iface_array[i]
            name_ptr = iface.pInterfaceName
            if name_ptr:
                try:
                    name = ctypes.cast(name_ptr, ctypes.c_char_p).value
                    name_str = name.decode("utf-8") if name else ""
                except Exception:
                    name_str = ""
            else:
                name_str = ""
            ver_ptr = iface.pFunctionList
            # The version is the first field of the function list
            if ver_ptr:
                try:
                    from pkcs11_check.raw.types_std import CK_VERSION

                    ver = ctypes.cast(ver_ptr, ctypes.POINTER(CK_VERSION)).contents
                    major = ver.major
                    minor = ver.minor
                except Exception:
                    major, minor = 0, 0
            else:
                major, minor = 0, 0
            result.append((name_str, major, minor))
        return result


# ---------------------------------------------------------------------------
# Factory
# ---------------------------------------------------------------------------


def load_module(
    path: Path,
    interface: str = "auto",
) -> P11Module:
    """Load a PKCS#11 module and negotiate the interface version.

    Supports v2.40 (C_GetFunctionList) and v3.0/v3.1/v3.2 (C_GetInterface).
    When ``interface="auto"`` (default), RawPKCS11.from_lib() probes for the
    highest available interface automatically.

    :param path: Path to the PKCS#11 shared library.
    :param interface: Requested interface version: ``"auto"``, ``"2.40"``,
        ``"3.0"``, ``"3.1"``, or ``"3.2"``.
    :raises FileNotFoundError: If the module file does not exist.
    :raises ValueError: If ``interface`` is not a recognised value.
    :raises RuntimeError: If the module cannot be loaded.
    """
    if not path.exists():
        msg = f"Module not found: {path}"
        raise FileNotFoundError(msg)

    if interface not in SUPPORTED_INTERFACES:
        msg = f"Unknown interface {interface!r}; must be one of {SUPPORTED_INTERFACES}"
        raise ValueError(msg)

    raw = RawPKCS11.from_lib(str(path))

    # Initialize the cryptoki library. C_Initialize may return
    # CKR_CRYPTOKI_ALREADY_INITIALIZED (0x00000191) if another part of the
    # process already initialized it -- that is acceptable.
    rv = raw.C_Initialize(None)
    _ckr_already_initialized = 0x00000191
    if rv not in (CKR_OK, _ckr_already_initialized):
        raise RuntimeError(f"C_Initialize failed: 0x{rv:08x}")

    return P11Module(path=path, _raw=raw)
