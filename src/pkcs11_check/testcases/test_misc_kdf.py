"""Miscellaneous simple key derivation mechanism tests.

Covers CKM_CONCATENATE_BASE_AND_KEY, CKM_CONCATENATE_BASE_AND_DATA,
CKM_CONCATENATE_DATA_AND_BASE, CKM_XOR_BASE_AND_DATA, and
CKM_EXTRACT_KEY_FROM_KEY.

These mechanisms derive a new secret key by simple byte-level operations on
the base key value.  The parameter types are:

  - CONCATENATE_BASE_AND_KEY   - CK_OBJECT_HANDLE (second key handle, CK_ULONG)
  - CONCATENATE_BASE_AND_DATA  - CK_KEY_DERIVATION_STRING_DATA (ptr + len)
  - CONCATENATE_DATA_AND_BASE  - CK_KEY_DERIVATION_STRING_DATA (ptr + len)
  - XOR_BASE_AND_DATA          - CK_KEY_DERIVATION_STRING_DATA (ptr + len)
  - EXTRACT_KEY_FROM_KEY       - CK_EXTRACT_PARAMS (bit offset, CK_ULONG)

The python-pkcs11 wrapper does not have native struct support for these
mechanisms, so we construct parameters manually using ctypes and pass them
as raw bytes - the same pattern used in test_x942_dh.py.

OASIS spec: generic_secret_key.md, key_management_functions.md
"""

from __future__ import annotations

import ctypes
from typing import Any

import pytest
from pkcs11 import Attribute, KeyType, Mechanism, ObjectClass
from pkcs11.exceptions import (
    ArgumentsBad,
    FunctionFailed,
    GeneralError,
    KeySizeRange,
    MechanismInvalid,
    MechanismParamInvalid,
    TemplateIncomplete,
    TemplateInconsistent,
)

from pkcs11_check.testcases.conftest import has_mechanism

pytestmark = pytest.mark.keymgmt

# ---------------------------------------------------------------------------
# Acceptable error tuple for derive operations on non-conforming modules
# ---------------------------------------------------------------------------

_DERIVE_ERRORS = (
    MechanismInvalid,
    MechanismParamInvalid,
    FunctionFailed,
    GeneralError,
    KeySizeRange,
    TemplateIncomplete,
    TemplateInconsistent,
    ArgumentsBad,
)

# ---------------------------------------------------------------------------
# ctypes struct helpers
# ---------------------------------------------------------------------------

_CK_ULONG = ctypes.c_ulong
_CK_BYTE_PTR = ctypes.POINTER(ctypes.c_ubyte)


class _KeyDerivationStringData(ctypes.Structure):
    """CK_KEY_DERIVATION_STRING_DATA - parameter for CONCATENATE and XOR mechs."""

    _fields_ = [
        ("pData", _CK_BYTE_PTR),
        ("ulLen", _CK_ULONG),
    ]


def _make_string_data_param(
    data: bytes,
) -> tuple[_KeyDerivationStringData, ctypes.Array[ctypes.c_ubyte]]:
    """Build a CK_KEY_DERIVATION_STRING_DATA struct for ``data``.

    Returns (struct, data_array) - caller must keep both alive until
    C_DeriveKey returns.
    """
    arr = (ctypes.c_ubyte * len(data))(*data)
    params = _KeyDerivationStringData()
    params.pData = ctypes.cast(arr, _CK_BYTE_PTR)
    params.ulLen = len(data)
    return params, arr


def _struct_to_bytes(s: ctypes.Structure) -> bytes:
    """Serialize a ctypes Structure to raw bytes."""
    return bytes(ctypes.string_at(ctypes.addressof(s), ctypes.sizeof(s)))


def _ulong_to_bytes(value: int) -> bytes:
    """Serialize a CK_ULONG to raw bytes (native byte order)."""
    return bytes(ctypes.string_at(ctypes.addressof(_CK_ULONG(value)), ctypes.sizeof(_CK_ULONG)))


# ---------------------------------------------------------------------------
# Helper: import a GENERIC_SECRET key for derivation
# ---------------------------------------------------------------------------

_DERIVE_TEMPLATE: dict[Attribute, Any] = {
    Attribute.SENSITIVE: False,
    Attribute.EXTRACTABLE: True,
    Attribute.TOKEN: False,
}


def _import_generic_secret(session: Any, value: bytes) -> Any:
    """Import ``value`` as a GENERIC_SECRET key with DERIVE=True."""
    return session.create_object(
        {
            Attribute.CLASS: ObjectClass.SECRET_KEY,
            Attribute.KEY_TYPE: KeyType.GENERIC_SECRET,
            Attribute.VALUE: value,
            Attribute.TOKEN: False,
            Attribute.SENSITIVE: False,
            Attribute.EXTRACTABLE: True,
            Attribute.DERIVE: True,
        }
    )


# ---------------------------------------------------------------------------
# TestConcatenateBaseAndKey
# ---------------------------------------------------------------------------


class TestConcatenateBaseAndKey:
    """CKM_CONCATENATE_BASE_AND_KEY - derive by concatenating two key values."""

    def test_concat_two_keys_value(self, p11_session: Any, p11_module: Any) -> None:
        """Derived value equals base_key_bytes || second_key_bytes."""
        if not has_mechanism(p11_module, "CONCATENATE_BASE_AND_KEY"):
            pytest.skip("CKM_CONCATENATE_BASE_AND_KEY not supported")

        base_bytes = b"\x01" * 16
        second_bytes = b"\x02" * 16
        expected = base_bytes + second_bytes

        base = _import_generic_secret(p11_session, base_bytes)
        second = _import_generic_secret(p11_session, second_bytes)
        derived = None
        try:
            # CK_OBJECT_HANDLE is a single CK_ULONG - pass as raw bytes
            handle = second.handle
            assert handle is not None
            param_bytes = _ulong_to_bytes(handle)
            derived = base.derive_key(
                KeyType.GENERIC_SECRET,
                len(expected) * 8,
                mechanism=Mechanism.CONCATENATE_BASE_AND_KEY,
                mechanism_param=param_bytes,
                template=_DERIVE_TEMPLATE,
            )
            derived_value = derived[Attribute.VALUE]
            assert derived_value == expected, (
                f"Expected {expected.hex()}, got {derived_value.hex()}"
            )
        except _DERIVE_ERRORS as exc:
            pytest.xfail(f"CKM_CONCATENATE_BASE_AND_KEY derive failed: {exc}")
        finally:
            if derived is not None:
                try:
                    derived.destroy()
                except Exception:
                    pass
            try:
                base.destroy()
            except Exception:
                pass
            try:
                second.destroy()
            except Exception:
                pass

    def test_concat_produces_combined_length(self, p11_session: Any, p11_module: Any) -> None:
        """Derived key length equals sum of base and second key lengths."""
        if not has_mechanism(p11_module, "CONCATENATE_BASE_AND_KEY"):
            pytest.skip("CKM_CONCATENATE_BASE_AND_KEY not supported")

        base_bytes = b"\xaa" * 16
        second_bytes = b"\xbb" * 16

        base = _import_generic_secret(p11_session, base_bytes)
        second = _import_generic_secret(p11_session, second_bytes)
        derived = None
        try:
            handle = second.handle
            assert handle is not None
            param_bytes = _ulong_to_bytes(handle)
            derived = base.derive_key(
                KeyType.GENERIC_SECRET,
                32 * 8,
                mechanism=Mechanism.CONCATENATE_BASE_AND_KEY,
                mechanism_param=param_bytes,
                template=_DERIVE_TEMPLATE,
            )
            assert len(derived[Attribute.VALUE]) == 32
        except _DERIVE_ERRORS as exc:
            pytest.xfail(f"CKM_CONCATENATE_BASE_AND_KEY derive failed: {exc}")
        finally:
            if derived is not None:
                try:
                    derived.destroy()
                except Exception:
                    pass
            try:
                base.destroy()
            except Exception:
                pass
            try:
                second.destroy()
            except Exception:
                pass


# ---------------------------------------------------------------------------
# TestConcatenateBaseAndData
# ---------------------------------------------------------------------------


class TestConcatenateBaseAndData:
    """CKM_CONCATENATE_BASE_AND_DATA - derive by appending data to base key value."""

    def test_concat_value_cross_verify(self, p11_session: Any, p11_module: Any) -> None:
        """Derived value equals base_key_bytes || data_bytes."""
        if not has_mechanism(p11_module, "CONCATENATE_BASE_AND_DATA"):
            pytest.skip("CKM_CONCATENATE_BASE_AND_DATA not supported")

        base_bytes = b"AAAA" * 4  # 16 bytes
        data_bytes = b"BBBB" * 4  # 16 bytes
        expected = base_bytes + data_bytes

        base = _import_generic_secret(p11_session, base_bytes)
        derived = None
        try:
            params, arr = _make_string_data_param(data_bytes)
            param_bytes = _struct_to_bytes(params)
            derived = base.derive_key(
                KeyType.GENERIC_SECRET,
                len(expected) * 8,
                mechanism=Mechanism.CONCATENATE_BASE_AND_DATA,
                mechanism_param=param_bytes,
                template=_DERIVE_TEMPLATE,
            )
            derived_value = derived[Attribute.VALUE]
            assert derived_value == expected, (
                f"Expected {expected.hex()}, got {derived_value.hex()}"
            )
        except _DERIVE_ERRORS as exc:
            pytest.xfail(f"CKM_CONCATENATE_BASE_AND_DATA derive failed: {exc}")
        finally:
            if derived is not None:
                try:
                    derived.destroy()
                except Exception:
                    pass
            try:
                base.destroy()
            except Exception:
                pass

    def test_different_data_produces_different_derived_key(
        self, p11_session: Any, p11_module: Any
    ) -> None:
        """Different data bytes yield different derived keys from the same base."""
        if not has_mechanism(p11_module, "CONCATENATE_BASE_AND_DATA"):
            pytest.skip("CKM_CONCATENATE_BASE_AND_DATA not supported")

        base_bytes = b"\x55" * 16
        data_a = b"\x11" * 16
        data_b = b"\x22" * 16

        base = _import_generic_secret(p11_session, base_bytes)
        derived_a = None
        derived_b = None
        try:
            params_a, arr_a = _make_string_data_param(data_a)
            derived_a = base.derive_key(
                KeyType.GENERIC_SECRET,
                32 * 8,
                mechanism=Mechanism.CONCATENATE_BASE_AND_DATA,
                mechanism_param=_struct_to_bytes(params_a),
                template=_DERIVE_TEMPLATE,
            )
            params_b, arr_b = _make_string_data_param(data_b)
            derived_b = base.derive_key(
                KeyType.GENERIC_SECRET,
                32 * 8,
                mechanism=Mechanism.CONCATENATE_BASE_AND_DATA,
                mechanism_param=_struct_to_bytes(params_b),
                template=_DERIVE_TEMPLATE,
            )
            assert derived_a[Attribute.VALUE] != derived_b[Attribute.VALUE]
        except _DERIVE_ERRORS as exc:
            pytest.xfail(f"CKM_CONCATENATE_BASE_AND_DATA derive failed: {exc}")
        finally:
            for obj in (derived_a, derived_b, base):
                if obj is not None:
                    try:
                        obj.destroy()
                    except Exception:
                        pass


# ---------------------------------------------------------------------------
# TestConcatenateDataAndBase
# ---------------------------------------------------------------------------


class TestConcatenateDataAndBase:
    """CKM_CONCATENATE_DATA_AND_BASE - derive by prepending data to base key value."""

    def test_concat_value_cross_verify(self, p11_session: Any, p11_module: Any) -> None:
        """Derived value equals data_bytes || base_key_bytes."""
        if not has_mechanism(p11_module, "CONCATENATE_DATA_AND_BASE"):
            pytest.skip("CKM_CONCATENATE_DATA_AND_BASE not supported")

        base_bytes = b"BBBB" * 4  # 16 bytes
        data_bytes = b"AAAA" * 4  # 16 bytes
        expected = data_bytes + base_bytes

        base = _import_generic_secret(p11_session, base_bytes)
        derived = None
        try:
            params, arr = _make_string_data_param(data_bytes)
            param_bytes = _struct_to_bytes(params)
            derived = base.derive_key(
                KeyType.GENERIC_SECRET,
                len(expected) * 8,
                mechanism=Mechanism.CONCATENATE_DATA_AND_BASE,
                mechanism_param=param_bytes,
                template=_DERIVE_TEMPLATE,
            )
            derived_value = derived[Attribute.VALUE]
            assert derived_value == expected, (
                f"Expected {expected.hex()}, got {derived_value.hex()}"
            )
        except _DERIVE_ERRORS as exc:
            pytest.xfail(f"CKM_CONCATENATE_DATA_AND_BASE derive failed: {exc}")
        finally:
            if derived is not None:
                try:
                    derived.destroy()
                except Exception:
                    pass
            try:
                base.destroy()
            except Exception:
                pass

    def test_base_and_data_ordering_differ(self, p11_session: Any, p11_module: Any) -> None:
        """CONCATENATE_BASE_AND_DATA and CONCATENATE_DATA_AND_BASE yield different results."""
        if not has_mechanism(p11_module, "CONCATENATE_BASE_AND_DATA"):
            pytest.skip("CKM_CONCATENATE_BASE_AND_DATA not supported")
        if not has_mechanism(p11_module, "CONCATENATE_DATA_AND_BASE"):
            pytest.skip("CKM_CONCATENATE_DATA_AND_BASE not supported")

        base_bytes = b"\x11" * 16
        data_bytes = b"\x22" * 16

        # base != data so concatenation order matters
        base = _import_generic_secret(p11_session, base_bytes)
        derived_bd = None
        derived_db = None
        try:
            params, arr = _make_string_data_param(data_bytes)
            param_raw = _struct_to_bytes(params)
            derived_bd = base.derive_key(
                KeyType.GENERIC_SECRET,
                32 * 8,
                mechanism=Mechanism.CONCATENATE_BASE_AND_DATA,
                mechanism_param=param_raw,
                template=_DERIVE_TEMPLATE,
            )
            derived_db = base.derive_key(
                KeyType.GENERIC_SECRET,
                32 * 8,
                mechanism=Mechanism.CONCATENATE_DATA_AND_BASE,
                mechanism_param=param_raw,
                template=_DERIVE_TEMPLATE,
            )
            assert derived_bd[Attribute.VALUE] != derived_db[Attribute.VALUE]
        except _DERIVE_ERRORS as exc:
            pytest.xfail(f"CONCATENATE ordering test failed: {exc}")
        finally:
            for obj in (derived_bd, derived_db, base):
                if obj is not None:
                    try:
                        obj.destroy()
                    except Exception:
                        pass


# ---------------------------------------------------------------------------
# TestXorBaseAndData
# ---------------------------------------------------------------------------


class TestXorBaseAndData:
    """CKM_XOR_BASE_AND_DATA - derive by XOR-ing base key value with data bytes."""

    def test_xor_cross_verify(self, p11_session: Any, p11_module: Any) -> None:
        """Derived value equals base_key_bytes XOR data_bytes."""
        if not has_mechanism(p11_module, "XOR_BASE_AND_DATA"):
            pytest.skip("CKM_XOR_BASE_AND_DATA not supported")

        base_bytes = b"\xff" * 16
        data_bytes = b"\x0f" * 16
        expected = bytes(a ^ b for a, b in zip(base_bytes, data_bytes))

        base = _import_generic_secret(p11_session, base_bytes)
        derived = None
        try:
            params, arr = _make_string_data_param(data_bytes)
            param_bytes = _struct_to_bytes(params)
            derived = base.derive_key(
                KeyType.GENERIC_SECRET,
                len(base_bytes) * 8,
                mechanism=Mechanism.XOR_BASE_AND_DATA,
                mechanism_param=param_bytes,
                template=_DERIVE_TEMPLATE,
            )
            derived_value = derived[Attribute.VALUE]
            assert derived_value == expected, (
                f"Expected {expected.hex()}, got {derived_value.hex()}"
            )
        except _DERIVE_ERRORS as exc:
            pytest.xfail(f"CKM_XOR_BASE_AND_DATA derive failed: {exc}")
        finally:
            if derived is not None:
                try:
                    derived.destroy()
                except Exception:
                    pass
            try:
                base.destroy()
            except Exception:
                pass

    def test_xor_with_zero_data_is_identity(self, p11_session: Any, p11_module: Any) -> None:
        """XOR with all-zero data bytes leaves the key value unchanged."""
        if not has_mechanism(p11_module, "XOR_BASE_AND_DATA"):
            pytest.skip("CKM_XOR_BASE_AND_DATA not supported")

        base_bytes = b"\xab\xcd\xef\x01" * 4  # 16 bytes
        data_bytes = b"\x00" * 16

        base = _import_generic_secret(p11_session, base_bytes)
        derived = None
        try:
            params, arr = _make_string_data_param(data_bytes)
            derived = base.derive_key(
                KeyType.GENERIC_SECRET,
                len(base_bytes) * 8,
                mechanism=Mechanism.XOR_BASE_AND_DATA,
                mechanism_param=_struct_to_bytes(params),
                template=_DERIVE_TEMPLATE,
            )
            assert derived[Attribute.VALUE] == base_bytes
        except _DERIVE_ERRORS as exc:
            pytest.xfail(f"CKM_XOR_BASE_AND_DATA derive failed: {exc}")
        finally:
            if derived is not None:
                try:
                    derived.destroy()
                except Exception:
                    pass
            try:
                base.destroy()
            except Exception:
                pass

    def test_xor_with_all_ones_is_bitflip(self, p11_session: Any, p11_module: Any) -> None:
        """XOR with all-0xFF bytes inverts every bit of the base key."""
        if not has_mechanism(p11_module, "XOR_BASE_AND_DATA"):
            pytest.skip("CKM_XOR_BASE_AND_DATA not supported")

        base_bytes = b"\x55" * 16
        data_bytes = b"\xff" * 16
        expected = bytes(b ^ 0xFF for b in base_bytes)

        base = _import_generic_secret(p11_session, base_bytes)
        derived = None
        try:
            params, arr = _make_string_data_param(data_bytes)
            derived = base.derive_key(
                KeyType.GENERIC_SECRET,
                len(base_bytes) * 8,
                mechanism=Mechanism.XOR_BASE_AND_DATA,
                mechanism_param=_struct_to_bytes(params),
                template=_DERIVE_TEMPLATE,
            )
            assert derived[Attribute.VALUE] == expected
        except _DERIVE_ERRORS as exc:
            pytest.xfail(f"CKM_XOR_BASE_AND_DATA derive failed: {exc}")
        finally:
            if derived is not None:
                try:
                    derived.destroy()
                except Exception:
                    pass
            try:
                base.destroy()
            except Exception:
                pass


# ---------------------------------------------------------------------------
# TestExtractKeyFromKey
# ---------------------------------------------------------------------------


class TestExtractKeyFromKey:
    """CKM_EXTRACT_KEY_FROM_KEY - extract a sub-key from a base key at a bit offset."""

    def test_extract_from_offset_zero(self, p11_session: Any, p11_module: Any) -> None:
        """Extract at bit offset 0 yields the leading bytes of the base key."""
        if not has_mechanism(p11_module, "EXTRACT_KEY_FROM_KEY"):
            pytest.skip("CKM_EXTRACT_KEY_FROM_KEY not supported")

        # 32-byte base key; extract first 16 bytes (bit offset 0, 128-bit derived)
        base_bytes = bytes(range(32))
        expected = base_bytes[:16]

        base = _import_generic_secret(p11_session, base_bytes)
        derived = None
        try:
            # CK_EXTRACT_PARAMS is typedef CK_ULONG - bit offset
            bit_offset = 0
            param_bytes = _ulong_to_bytes(bit_offset)
            derived = base.derive_key(
                KeyType.GENERIC_SECRET,
                128,
                mechanism=Mechanism.EXTRACT_KEY_FROM_KEY,
                mechanism_param=param_bytes,
                template=_DERIVE_TEMPLATE,
            )
            derived_value = derived[Attribute.VALUE]
            assert derived_value == expected, (
                f"Expected {expected.hex()}, got {derived_value.hex()}"
            )
        except _DERIVE_ERRORS as exc:
            pytest.xfail(f"CKM_EXTRACT_KEY_FROM_KEY derive failed: {exc}")
        finally:
            if derived is not None:
                try:
                    derived.destroy()
                except Exception:
                    pass
            try:
                base.destroy()
            except Exception:
                pass

    def test_extract_at_byte_boundary_offset(self, p11_session: Any, p11_module: Any) -> None:
        """Extract at bit offset 128 (byte 16) yields the second half of a 32-byte key."""
        if not has_mechanism(p11_module, "EXTRACT_KEY_FROM_KEY"):
            pytest.skip("CKM_EXTRACT_KEY_FROM_KEY not supported")

        base_bytes = bytes(range(32))
        expected = base_bytes[16:]  # bytes 16-31

        base = _import_generic_secret(p11_session, base_bytes)
        derived = None
        try:
            bit_offset = 128  # skip first 16 bytes
            param_bytes = _ulong_to_bytes(bit_offset)
            derived = base.derive_key(
                KeyType.GENERIC_SECRET,
                128,
                mechanism=Mechanism.EXTRACT_KEY_FROM_KEY,
                mechanism_param=param_bytes,
                template=_DERIVE_TEMPLATE,
            )
            derived_value = derived[Attribute.VALUE]
            assert derived_value == expected, (
                f"Expected {expected.hex()}, got {derived_value.hex()}"
            )
        except _DERIVE_ERRORS as exc:
            pytest.xfail(f"CKM_EXTRACT_KEY_FROM_KEY derive failed: {exc}")
        finally:
            if derived is not None:
                try:
                    derived.destroy()
                except Exception:
                    pass
            try:
                base.destroy()
            except Exception:
                pass

    def test_extract_different_offsets_yield_different_keys(
        self, p11_session: Any, p11_module: Any
    ) -> None:
        """Different bit offsets yield different extracted key values."""
        if not has_mechanism(p11_module, "EXTRACT_KEY_FROM_KEY"):
            pytest.skip("CKM_EXTRACT_KEY_FROM_KEY not supported")

        # Use a key where bytes differ across its length
        base_bytes = bytes(range(32))

        base = _import_generic_secret(p11_session, base_bytes)
        derived_a = None
        derived_b = None
        try:
            derived_a = base.derive_key(
                KeyType.GENERIC_SECRET,
                128,
                mechanism=Mechanism.EXTRACT_KEY_FROM_KEY,
                mechanism_param=_ulong_to_bytes(0),
                template=_DERIVE_TEMPLATE,
            )
            derived_b = base.derive_key(
                KeyType.GENERIC_SECRET,
                128,
                mechanism=Mechanism.EXTRACT_KEY_FROM_KEY,
                mechanism_param=_ulong_to_bytes(128),
                template=_DERIVE_TEMPLATE,
            )
            assert derived_a[Attribute.VALUE] != derived_b[Attribute.VALUE]
        except _DERIVE_ERRORS as exc:
            pytest.xfail(f"CKM_EXTRACT_KEY_FROM_KEY derive failed: {exc}")
        finally:
            for obj in (derived_a, derived_b, base):
                if obj is not None:
                    try:
                        obj.destroy()
                    except Exception:
                        pass
