from __future__ import annotations

import json
from pathlib import Path

import pytest

from pkcs11_check.raw.der import decode_ec_point
from pkcs11_check.testcases.acvp.test_acvp_ecdh import _extract_ec_point
from pkcs11_check.testcases.data import WYCHEPROOF_DIR


def _first_valid_public_key(filename: str) -> bytes:
    data = json.loads((Path(WYCHEPROOF_DIR) / filename).read_text())
    for group in data["testGroups"]:
        for test in group["tests"]:
            if test.get("result") == "valid":
                return bytes.fromhex(test["public"])
    raise AssertionError(f"{filename} has no valid ECDH vectors")


@pytest.mark.parametrize(
    ("filename", "coord_len"),
    [
        ("ecdh_secp384r1_test.json", 48),
        ("ecdh_secp521r1_test.json", 66),
    ],
)
def test_extract_ec_point_uses_spki_bit_string_not_curve_oid(filename: str, coord_len: int) -> None:
    public_key = _first_valid_public_key(filename)

    extracted = _extract_ec_point(public_key, coord_len)

    assert extracted is not None
    assert decode_ec_point(extracted) == public_key[-(1 + 2 * coord_len) :]
