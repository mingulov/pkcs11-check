import pytest
from cryptography.hazmat.primitives.asymmetric import ec

from pkcs11_check.testcases._ec_export import (
    MalformedSignature,
    coord_len_for_curve,
    split_raw_ecdsa,
)


def test_split_p256_fixed_width():
    r = (1).to_bytes(32, "big")
    s = (2).to_bytes(32, "big")
    assert split_raw_ecdsa(r + s, 32) == (1, 2)


def test_split_p521_fixed_width():
    r = (3).to_bytes(66, "big")
    s = (4).to_bytes(66, "big")
    assert split_raw_ecdsa(r + s, 66) == (3, 4)


def test_split_odd_width_raises_malformed():
    with pytest.raises(MalformedSignature):
        split_raw_ecdsa(b"\x00" * 67, 32)


def test_coord_len_for_curve():
    assert coord_len_for_curve(ec.SECP256R1()) == 32
    assert coord_len_for_curve(ec.SECP384R1()) == 48
    assert coord_len_for_curve(ec.SECP521R1()) == 66
