"""ABI-general packing of scalar CK_ULONG mechanism parameters.

Mechanisms whose ``CK_MECHANISM.pParameter`` is a single ``CK_ULONG`` (the ``*_MAC_GENERAL``
family, ``CK_EXTRACT_PARAMS``, the XEdDSA hash type, ...) must derive the parameter width and
byte order from the ``CK_ULONG`` ctypes type -- never a literal ``to_bytes(8, "little")``, which
is 8 bytes on LP64 but must be 4 on Win64 LLP64 where ``CK_ULONG`` is 32-bit.
"""

from __future__ import annotations

import ctypes

from pkcs11_check.raw.pack import ck_ulong_bytes, mech_scalar, mech_ulong
from pkcs11_check.raw.types_std import CK_ULONG, CKM_AES_MAC_GENERAL


def test_ck_ulong_bytes_width_and_roundtrip() -> None:
    encoded = ck_ulong_bytes(16)
    # width comes from the ctypes type, not a literal
    assert len(encoded) == ctypes.sizeof(CK_ULONG)
    assert encoded == bytes(CK_ULONG(16))
    # decodes back to the original value on this ABI
    assert CK_ULONG.from_buffer_copy(encoded).value == 16


def test_mech_ulong_param_len_tracks_ck_ulong_size() -> None:
    mech = mech_ulong(CKM_AES_MAC_GENERAL, 8)
    assert mech.ck.mechanism == CKM_AES_MAC_GENERAL
    # ulParameterLen must equal sizeof(CK_ULONG), NOT a hardcoded 8
    assert len(mech.storage) == ctypes.sizeof(CK_ULONG)
    assert mech.pointer_arg.native_length == ctypes.sizeof(CK_ULONG)
    assert bytes(mech.storage) == ck_ulong_bytes(8)
    assert CK_ULONG.from_buffer_copy(bytes(mech.storage)).value == 8


def test_mech_scalar_is_generic_over_ctype() -> None:
    # mech_ulong is the CK_ULONG specialization of the general scalar packer
    via_scalar = mech_scalar(CKM_AES_MAC_GENERAL, CK_ULONG, 8)
    via_ulong = mech_ulong(CKM_AES_MAC_GENERAL, 8)
    assert bytes(via_scalar.storage) == bytes(via_ulong.storage)
    assert len(via_scalar.storage) == ctypes.sizeof(CK_ULONG)
