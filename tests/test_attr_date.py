"""Direct packing guard for the ``attr_date`` helper (fw#49).

``CK_DATE`` fields are ``CK_CHAR`` (``c_ubyte``) arrays, which reject the
``bytes`` objects ``attr_date`` used to pass -- the same pre-call ctypes
rejection family as the ``C_AsyncGetID`` selector.
"""

from __future__ import annotations

from pkcs11_check.raw.pack import attr_date
from pkcs11_check.raw.types_std import CKA_START_DATE


def test_attr_date_packs_ascii_fields() -> None:
    """attr_date must pack YYYYMMDD ASCII into the CK_DATE struct (fw#49)."""
    packed = attr_date(CKA_START_DATE, "2026", "10", "07")
    assert bytes(packed.storage) == b"20261007"
    assert packed.attribute.ulValueLen == 8
