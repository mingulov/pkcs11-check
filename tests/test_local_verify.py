from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa, utils

from pkcs11_check.testcases._local_verify import (
    ecdsa_local,
    rsa_pkcs15_local,
    rsa_pss_local,
    rsa_pss_local_any_salt,
    rsa_pss_local_recover_mgf,
)


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


def test_rsa_pss_local_any_salt_accepts_unrequested_salt() -> None:
    # A module that signs PSS with a salt different from the requested one still
    # produces a cryptographically valid signature; any-salt verify must accept it
    # (exact-salt verify would false-reject), while a tampered sig is rejected.
    k = rsa.generate_private_key(65537, 2048)
    msg = b"m"
    for signed_salt in (0, 32, 62):
        sig = k.sign(
            msg,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=signed_salt),
            hashes.SHA256(),
        )
        # exact verify with the WRONG requested salt (32) fails for 0/62...
        if signed_salt != 32:
            assert (
                rsa_pss_local(k.public_key(), msg, sig, hashes.SHA256(), hashes.SHA256(), 32)
                is False
            )
        # ...but any-salt verify accepts the valid signature regardless of salt.
        assert (
            rsa_pss_local_any_salt(k.public_key(), msg, sig, hashes.SHA256(), hashes.SHA256())
            is True
        )
    bad = k.sign(
        b"other", padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32), hashes.SHA256()
    )
    assert (
        rsa_pss_local_any_salt(k.public_key(), msg, bad, hashes.SHA256(), hashes.SHA256()) is False
    )


def test_rsa_pss_local_recover_mgf_detects_substituted_mgf() -> None:
    # A module that produces a VALID PSS signature whose MGF1 hash differs from
    # the requested one (here MGF1-SHA1 while the message digest is SHA-256) must
    # NOT be accused of a crypto break. any-salt verify with the requested MGF
    # (SHA-256) fails, but recover finds the actual MGF1 hash -> honest_deviation.
    k = rsa.generate_private_key(65537, 2048)
    msg = b"m"
    sig = k.sign(
        msg,
        padding.PSS(mgf=padding.MGF1(hashes.SHA1()), salt_length=32),  # nosec B303
        hashes.SHA256(),
    )
    assert (
        rsa_pss_local_any_salt(k.public_key(), msg, sig, hashes.SHA256(), hashes.SHA256()) is False
    )
    recovered = rsa_pss_local_recover_mgf(k.public_key(), msg, sig, hashes.SHA256())
    assert recovered is not None
    assert recovered.name == "sha1"


def test_rsa_pss_local_recover_mgf_returns_requested_when_honored() -> None:
    k = rsa.generate_private_key(65537, 2048)
    msg = b"m"
    sig = k.sign(
        msg, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32), hashes.SHA256()
    )
    recovered = rsa_pss_local_recover_mgf(k.public_key(), msg, sig, hashes.SHA256())
    assert recovered is not None
    assert recovered.name == "sha256"


def test_rsa_pss_local_recover_mgf_covers_sha3_family() -> None:
    # The MGF1 hash family in PKCS#11 (CKG_MGF1_*) includes the SHA3 hashes. A
    # module that legitimately signs PSS with MGF1-SHA3-256 produces a VALID
    # signature; recover must find it (not return None) so the caller never
    # false-accuses a crypto break for an out-of-(SHA2)-family but valid MGF.
    k = rsa.generate_private_key(65537, 2048)
    msg = b"m"
    sig = k.sign(
        msg, padding.PSS(mgf=padding.MGF1(hashes.SHA3_256()), salt_length=32), hashes.SHA256()
    )
    assert (
        rsa_pss_local_any_salt(k.public_key(), msg, sig, hashes.SHA256(), hashes.SHA256()) is False
    )
    recovered = rsa_pss_local_recover_mgf(k.public_key(), msg, sig, hashes.SHA256())
    assert recovered is not None
    assert recovered.name == "sha3-256"


def test_rsa_pss_local_recover_mgf_none_for_invalid_signature() -> None:
    # A genuinely invalid signature verifies under NO standard MGF -> None, so the
    # caller still reports wrong_result (a real crypto break is never masked).
    k = rsa.generate_private_key(65537, 2048)
    msg = b"m"
    bad = k.sign(
        b"other", padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32), hashes.SHA256()
    )
    assert rsa_pss_local_recover_mgf(k.public_key(), msg, bad, hashes.SHA256()) is None


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
