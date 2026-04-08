"""AES-CTS variant detection validation.

If a module advertises CKM_AES_CTS but the runtime probe cannot determine
which CBC-CS variant (CS1/CS2/CS3) it implements, this test FAILS -- the
module claims CTS support but cannot actually perform CTS encryption.
"""

from __future__ import annotations

from typing import Any

import pytest

from pkcs11_check.testcases.acvp.aes.base_cts import get_detected_variant

pytestmark = [pytest.mark.kat, pytest.mark.acvp]
REQUIRED_MECHANISMS = ["AES_CTS"]


def test_cts_variant_detected(p11_raw_session: Any) -> None:
    """Module advertises AES_CTS -- verify that a CS variant can be detected.

    If this fails, the module lists CKM_AES_CTS in its mechanism list but
    errors out when actually attempting CTS encryption.  This is a module bug:
    either fix CTS or stop advertising the mechanism.
    """
    rs = p11_raw_session
    variant = get_detected_variant(rs)
    assert variant is not None, (
        "Module advertises CKM_AES_CTS but CTS variant detection failed. "
        "The module errors on CTS encrypt probes -- CTS is non-functional."
    )
    assert variant in ("1", "2", "3"), (
        f"CTS variant detection returned unexpected value: {variant!r}"
    )
