"""Undersized-buffer read probe for C_GetAttributeValue.

A conformant module asked to fill an attribute into a buffer whose declared
``ulValueLen`` is smaller than the required data must:
  - return ``CKR_BUFFER_TOO_SMALL``,
  - set ``ulValueLen`` to the required size,
  - NOT write any bytes into the caller's buffer.

This probe is sound: the caller honestly declares a small ``ulValueLen``
against a generous physical buffer (64 bytes) filled with a sentinel value
(0xAA).  Any write past the declared length (the guard region) is detected
by inspecting the sentinel bytes after the call.  A conformant module leaves
the guard intact and returns ``CKR_BUFFER_TOO_SMALL``.

Attributes under test:
  - ``CKA_VALUE_LEN`` (``CK_ULONG``, 8 bytes on 64-bit) with ``ulValueLen=1``
  - ``CKA_SENSITIVE`` (``CK_BBOOL``, 1 byte) with ``ulValueLen=0``

Reference: PKCS#11 spec §C_GetAttributeValue; CWE-787 (out-of-bounds write),
CWE-125 (out-of-bounds read).
"""

from __future__ import annotations

import ctypes
from typing import Any

import pytest

from pkcs11_check.classification import fail_as
from pkcs11_check.raw.types_std import (
    CK_ATTRIBUTE,
    CKA_SENSITIVE,
    CKA_VALUE_LEN,
    CKR_ATTRIBUTE_TYPE_INVALID,
    CKR_BUFFER_TOO_SMALL,
    CKR_OK,
)
from pkcs11_check.testcases.conftest import (
    classify_negative_rv,
    destroy_returned_handles,
    gen_aes_key_or_xfail,
)

pytestmark = pytest.mark.security

# Physical guard buffer size.  64 bytes is amply larger than any scalar
# attribute value we will probe; the guard region begins immediately after the
# declared ``ulValueLen``.
_GUARD_BUF_SIZE = 64
_SENTINEL = 0xAA


def _probe_undersized_getattr(
    rs: Any,
    key: int,
    attr_type: int,
    declared_len: int,
    attr_label: str,
) -> None:
    """Run one undersized-buffer C_GetAttributeValue probe.

    Allocates a 64-byte physical buffer filled with 0xAA, declares only
    ``declared_len`` bytes to the module, then checks for guard-region
    corruption before classifying the return value.

    Args:
        rs: raw session fixture (has ``.raw`` and ``.sh``).
        key: AES key object handle to query.
        attr_type: CKA_ constant to request.
        declared_len: the ``ulValueLen`` value to declare (< true attribute size).
        attr_label: human-readable label for classification messages.
    """
    buf = (ctypes.c_ubyte * _GUARD_BUF_SIZE)(*([_SENTINEL] * _GUARD_BUF_SIZE))

    tmpl = (CK_ATTRIBUTE * 1)()
    tmpl[0].type = attr_type
    tmpl[0].pValue = ctypes.cast(buf, ctypes.c_void_p)
    tmpl[0].ulValueLen = declared_len

    rv = rs.raw.C_GetAttributeValue(rs.sh, key, tmpl, 1)

    # Check guard region first — an OOB write is the most severe outcome.
    guard_start = declared_len  # bytes [declared_len..63] are the guard region
    guard_corrupted = any(buf[i] != _SENTINEL for i in range(guard_start, _GUARD_BUF_SIZE))
    if guard_corrupted:
        fail_as(
            "self_contradiction",
            kind="metadata",
            label=(
                f"C_GetAttributeValue wrote past the declared ulValueLen "
                f"(buffer over-write) for {attr_label}"
            ),
            operation="C_GetAttributeValue",
        )

    if rv == CKR_OK:
        fail_as(
            "accepted_invalid",
            kind="metadata",
            label=(
                f"C_GetAttributeValue returned CKR_OK for an undersized buffer for {attr_label}"
            ),
            operation="C_GetAttributeValue",
        )

    classify_negative_rv(
        rv,
        (CKR_BUFFER_TOO_SMALL, CKR_ATTRIBUTE_TYPE_INVALID),
        label=f"C_GetAttributeValue rejects an undersized buffer for {attr_label}",
        kind="metadata",
    )


class TestGetAttrUndersizedBuffer:
    """C_GetAttributeValue must not overrun a caller-declared undersized buffer."""

    def _make_key(self, rs: Any) -> int:
        """Generate an AES-256 key that carries CKA_VALUE_LEN and CKA_SENSITIVE."""
        if not rs.has_mechanism("AES_KEY_GEN"):
            pytest.skip("AES_KEY_GEN not supported by module")
        return gen_aes_key_or_xfail(rs, 256, purpose="getattr-buffer-probe setup")

    def test_ulong_attr_undersized_buffer(self, p11_raw_session: Any) -> None:
        """CKA_VALUE_LEN (8-byte CK_ULONG) into a 1-byte declared buffer.

        ``ulValueLen=1`` is genuinely undersized; a conformant module must
        return ``CKR_BUFFER_TOO_SMALL`` without writing to the caller's buffer.
        Writing any byte past offset 0 corrupts the guard region and is
        classified as a self-contradiction (CWE-787).
        """
        rs = p11_raw_session
        key = self._make_key(rs)
        try:
            _probe_undersized_getattr(rs, key, CKA_VALUE_LEN, 1, "CKA_VALUE_LEN")
        finally:
            destroy_returned_handles(rs, key)

    def test_bool_attr_undersized_buffer(self, p11_raw_session: Any) -> None:
        """CKA_SENSITIVE (1-byte CK_BBOOL) into a zero-byte declared buffer.

        ``ulValueLen=0`` is genuinely undersized for a 1-byte boolean; a
        conformant module must return ``CKR_BUFFER_TOO_SMALL`` without writing
        any byte to the caller's buffer.  Any write to buf[0] or beyond
        corrupts the guard region and is classified as a self-contradiction
        (CWE-787).
        """
        rs = p11_raw_session
        key = self._make_key(rs)
        try:
            _probe_undersized_getattr(rs, key, CKA_SENSITIVE, 0, "CKA_SENSITIVE")
        finally:
            destroy_returned_handles(rs, key)
