"""Classification meta-tests for x509/test_search by-attribute (Phase 5 P1a).

If the module extracted a derived cert attribute (CKA_SUBJECT/ISSUER/SERIAL) but
search-by-that-attribute does not return the object, that is search-by-derived-
attribute provider-incompleteness -> ``xfail``, not a bare ``assert`` ``fail``.
A successful search still passes.
"""

from __future__ import annotations

import pytest
from _pytest.outcomes import XFailed

from pkcs11_check.testcases.x509 import test_search as ts


def test_search_miss_xfails() -> None:
    with pytest.raises(XFailed):
        ts._xfail_if_search_miss([2, 3], 7, by="CKA_SUBJECT")


def test_search_hit_passes() -> None:
    ts._xfail_if_search_miss([2, 7, 3], 7, by="CKA_SUBJECT")
