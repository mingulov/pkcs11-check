from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa, utils

from pkcs11_check.testcases._local_verify import ecdsa_local, rsa_pkcs15_local, rsa_pss_local


def test_rsa_pkcs15_local_roundtrip() -> None:
    k = rsa.generate_private_key(65537, 2048)
    msg = b"m"
    sig = k.sign(msg, padding.PKCS1v15(), hashes.SHA256())
    assert rsa_pkcs15_local(k.public_key(), msg, sig, hashes.SHA256()) is True
    assert rsa_pkcs15_local(k.public_key(), b"x", sig, hashes.SHA256()) is False


def test_rsa_pss_local_salt0() -> None:
    k = rsa.generate_private_key(65537, 2048)
    msg = b"m"
    sig = k.sign(
        msg, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=0), hashes.SHA256()
    )
    assert rsa_pss_local(k.public_key(), msg, sig, hashes.SHA256(), hashes.SHA256(), 0) is True


def test_rsa_pss_local_salt32() -> None:
    k = rsa.generate_private_key(65537, 2048)
    msg = b"m"
    sig = k.sign(
        msg, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32), hashes.SHA256()
    )
    assert rsa_pss_local(k.public_key(), msg, sig, hashes.SHA256(), hashes.SHA256(), 32) is True
    assert rsa_pss_local(k.public_key(), b"x", sig, hashes.SHA256(), hashes.SHA256(), 32) is False


def test_ecdsa_local_p256_raw_sig() -> None:
    k = ec.generate_private_key(ec.SECP256R1())
    msg = b"m"
    der = k.sign(msg, ec.ECDSA(hashes.SHA256()))
    r, s = utils.decode_dss_signature(der)
    raw = r.to_bytes(32, "big") + s.to_bytes(32, "big")
    assert ecdsa_local(k.public_key(), msg, raw, hashes.SHA256(), 32) is True
    bad = (r ^ 1).to_bytes(32, "big") + s.to_bytes(32, "big")
    assert ecdsa_local(k.public_key(), msg, bad, hashes.SHA256(), 32) is False


def test_ecdsa_local_p521_raw_sig() -> None:
    k = ec.generate_private_key(ec.SECP521R1())
    msg = b"m"
    der = k.sign(msg, ec.ECDSA(hashes.SHA256()))
    r, s = utils.decode_dss_signature(der)
    raw = r.to_bytes(66, "big") + s.to_bytes(66, "big")
    assert ecdsa_local(k.public_key(), msg, raw, hashes.SHA256(), 66) is True
