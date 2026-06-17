"""Meta-tests for the parameter-fidelity core + recover helpers.

Pure software: no PKCS#11 module is touched. ``fail_as``/``xfail_as`` route through
``classification.classify``, which raises ``pytest.fail`` (-> ``Failed``) /
``pytest.xfail`` (-> ``XFailed``) -- both subclass ``BaseException``, NOT ``Exception``
-- and record into ``classification.get_records()``. Assert outcomes via the records,
following ``tests/test_verify_roundtrip.py`` / ``tests/test_classification_emit.py``.
"""

import pytest
from _pytest.outcomes import Failed, XFailed
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from pkcs11_check.classification import clear, get_records
from pkcs11_check.testcases._param_fidelity import (
    FidelityResult,
    build_gcm_fidelity,
    classify_fidelity,
    recover_oaep_params,
    recover_pss_salt_len,
)


def test_classify_pass_when_valid_and_conforms() -> None:
    clear()
    r = FidelityResult(
        valid=True,
        conforms=True,
        interpretable=True,
        requested={"salt": 8},
        actual={"salt": 8},
        detail="",
    )
    assert classify_fidelity(r, label="L", operation="C_Sign", mechanism="CKM_TEST") is None
    assert get_records() == []


def test_classify_honest_deviation_when_valid_not_conforms() -> None:
    clear()
    r = FidelityResult(
        valid=True,
        conforms=False,
        interpretable=True,
        requested={"salt": 8},
        actual={"salt": 32},
        detail="salt not honored",
    )
    with pytest.raises(XFailed):
        classify_fidelity(r, label="L", operation="C_Sign", mechanism="CKM_TEST")
    rec = get_records()[-1]
    assert rec.reason == "honest_deviation"
    assert rec.kind == "metadata"
    assert rec.outcome == "xfail"


def test_classify_wrong_result_when_invalid_but_interpretable() -> None:
    clear()
    r = FidelityResult(
        valid=False,
        conforms=False,
        interpretable=True,
        requested={"salt": 8},
        actual={"salt": None},
        detail="invalid under all params",
    )
    with pytest.raises(Failed):
        classify_fidelity(r, label="L", operation="C_Sign", mechanism="CKM_TEST")
    rec = get_records()[-1]
    assert rec.reason == "wrong_result"
    assert rec.kind == "crypto"
    assert rec.outcome == "fail"


def test_classify_not_operational_when_not_interpretable() -> None:
    clear()
    r = FidelityResult(
        valid=False,
        conforms=False,
        interpretable=False,
        requested={"tag_bits": 96},
        actual={"tag_len_bytes": 31},
        detail="non-append layout",
    )
    with pytest.raises(XFailed):
        classify_fidelity(r, label="L", operation="C_Sign", mechanism="CKM_TEST")
    rec = get_records()[-1]
    assert rec.reason == "not_operational"
    assert rec.outcome == "xfail"


def test_recover_pss_salt_len_finds_exact_salt() -> None:
    k = rsa.generate_private_key(65537, 2048)
    msg = b"m"
    for signed_salt in (0, 8, 32, 222):  # 222 = emLen-hLen-2 for 2048/SHA256
        sig = k.sign(
            msg,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=signed_salt),
            hashes.SHA256(),
        )
        got = recover_pss_salt_len(k.public_key(), msg, sig, hashes.SHA256(), hashes.SHA256())
        assert got == signed_salt


def test_recover_pss_salt_len_none_for_invalid() -> None:
    k = rsa.generate_private_key(65537, 2048)
    sig = k.sign(
        b"other", padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32), hashes.SHA256()
    )
    assert recover_pss_salt_len(k.public_key(), b"m", sig, hashes.SHA256(), hashes.SHA256()) is None


def _gcm_module_output(
    key: bytes, nonce: bytes, aad: bytes, plaintext: bytes, tag_len: int
) -> bytes:
    enc = Cipher(algorithms.AES(key), modes.GCM(nonce)).encryptor()
    if aad:
        enc.authenticate_additional_data(aad)
    ct = enc.update(plaintext) + enc.finalize()
    return ct + enc.tag[:tag_len]


def test_build_gcm_fidelity_conforms() -> None:
    key = bytes(range(32))
    nonce = bytes(range(12))
    aad = b"a"
    pt = b"gcm body!!"
    out = _gcm_module_output(key, nonce, aad, pt, 12)  # 96-bit tag, as requested
    r = build_gcm_fidelity(key, nonce, aad, pt, out, requested_tag_bits=96)
    assert r.valid and r.conforms and r.interpretable


def test_build_gcm_fidelity_tag_length_deviation() -> None:
    key = bytes(range(32))
    nonce = bytes(range(12))
    aad = b"a"
    pt = b"gcm body!!"
    out = _gcm_module_output(key, nonce, aad, pt, 16)  # module produced 128-bit tag
    r = build_gcm_fidelity(key, nonce, aad, pt, out, requested_tag_bits=96)
    assert r.valid and not r.conforms and r.interpretable
    assert r.actual["tag_bits"] == 128


def test_build_gcm_fidelity_uninterpretable_layout() -> None:
    key = bytes(range(32))
    nonce = bytes(range(12))
    aad = b"a"
    pt = b"gcm body!!"
    out = b"\x00" * (len(pt) + 31)  # implausible 31-byte trailer -> non-append layout
    r = build_gcm_fidelity(key, nonce, aad, pt, out, requested_tag_bits=96)
    assert not r.interpretable and not r.valid


_OAEP_HASHES = (hashes.SHA1(), hashes.SHA256(), hashes.SHA384(), hashes.SHA512())  # nosec B303


def test_recover_oaep_params_matched_hash_and_label() -> None:
    k = rsa.generate_private_key(65537, 2048)
    pt = b"oaep fidelity"
    ct = k.public_key().encrypt(
        pt, padding.OAEP(mgf=padding.MGF1(hashes.SHA384()), algorithm=hashes.SHA384(), label=b"L")
    )
    got = recover_oaep_params(k, ct, pt, _OAEP_HASHES, _OAEP_HASHES, (b"L", None))
    assert got is not None
    alg, mgf, label = got
    assert alg.name == "sha384" and mgf.name == "sha384" and label == b"L"


def test_recover_oaep_params_distinct_mgf() -> None:
    k = rsa.generate_private_key(65537, 2048)
    pt = b"oaep fidelity"
    ct = k.public_key().encrypt(
        pt,
        padding.OAEP(
            mgf=padding.MGF1(hashes.SHA1()),  # nosec B303
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    got = recover_oaep_params(k, ct, pt, _OAEP_HASHES, _OAEP_HASHES, (None,))
    assert got is not None
    alg, mgf, _ = got
    assert alg.name == "sha256" and mgf.name == "sha1"


def test_recover_oaep_params_none_when_unrecoverable() -> None:
    k = rsa.generate_private_key(65537, 2048)
    pt = b"oaep fidelity"
    ct = k.public_key().encrypt(
        pt, padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=b"X")
    )
    # Candidate labels exclude b"X" -> cannot recover.
    assert recover_oaep_params(k, ct, pt, _OAEP_HASHES, _OAEP_HASHES, (None, b"Y")) is None
