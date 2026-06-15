"""Meta-tests for the parameter-fidelity core + recover helpers.

Pure software: no PKCS#11 module is touched. ``fail_as``/``xfail_as`` route through
``classification.classify``, which raises ``pytest.fail`` (-> ``Failed``) /
``pytest.xfail`` (-> ``XFailed``) -- both subclass ``BaseException``, NOT ``Exception``
-- and record into ``classification.get_records()``. Assert outcomes via the records,
following ``tests/test_verify_roundtrip.py`` / ``tests/test_classification_emit.py``.
"""

import pytest
from _pytest.outcomes import Failed, XFailed

from pkcs11_check.classification import clear, get_records
from pkcs11_check.testcases._param_fidelity import FidelityResult, classify_fidelity


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
