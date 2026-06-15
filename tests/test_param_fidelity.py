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

from pkcs11_check.classification import clear, get_records
from pkcs11_check.testcases._param_fidelity import (
    FidelityResult,
    classify_fidelity,
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
