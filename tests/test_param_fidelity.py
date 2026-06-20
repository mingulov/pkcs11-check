"""Meta-tests for the parameter-fidelity core + recover helpers.

Pure software: no PKCS#11 module is touched. ``fail_as``/``xfail_as`` route through
``classification.classify``, which raises ``pytest.fail`` (-> ``Failed``) /
``pytest.xfail`` (-> ``XFailed``) -- both subclass ``BaseException``, NOT ``Exception``
-- and record into ``classification.get_records()``. Assert outcomes via the records,
following ``tests/test_verify_roundtrip.py`` / ``tests/test_classification_emit.py``.

Also contains structural tests for the PSS/OAEP mismatch probe classes
(TestPssParamMismatch, TestOaepParamMismatch) verifying three-state classification
without touching a real PKCS#11 module.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest
from _pytest.outcomes import Failed, XFailed
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from pkcs11_check.classification import clear, get_records
from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import CKR_MECHANISM_PARAM_INVALID
from pkcs11_check.testcases import test_oaep_parameter_fidelity as oaep_mod
from pkcs11_check.testcases import test_pss_parameter_fidelity as pss_mod
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


# ---------------------------------------------------------------------------
# Mismatch/contradiction probe meta-tests (WS4-P2):
#   TestPssParamMismatch / TestOaepParamMismatch
# ---------------------------------------------------------------------------
# Pure structural tests: monkeypatch the PKCS#11 call sites so no real module
# is needed. We verify the three-state classification: reject->xfail, accept->
# honest_deviation (via fidelity oracle), crash->propagate.
# ---------------------------------------------------------------------------


def _rs(has_mech: bool = True) -> Any:
    ns = SimpleNamespace(raw=object(), sh=1)
    ns.has_mechanism = lambda _name: has_mech  # type: ignore[attr-defined]
    return ns


def _ckr_refuse(*_a: Any, **_kw: Any) -> Any:
    raise CkrAssertionError(
        "Unexpected CK_RV CKR_MECHANISM_PARAM_INVALID; expected one of: CKR_OK",
        int(CKR_MECHANISM_PARAM_INVALID),
    )


# ---- PSS mismatch ----


def _wire_pss(
    monkeypatch: pytest.MonkeyPatch,
    *,
    keygen: Any = lambda *a, **k: (7, 8),
    sign: Any = None,
    read_pub: Any = None,
) -> None:
    monkeypatch.setattr(pss_mod, "gen_rsa_keypair", keygen)
    monkeypatch.setattr(pss_mod, "destroy_quietly", lambda *a, **k: None)
    monkeypatch.setattr(pss_mod, "mech_pss", lambda *a, **k: object())
    if sign is not None:
        monkeypatch.setattr(pss_mod, "sign_single", sign)
    if read_pub is not None:
        monkeypatch.setattr(pss_mod, "read_rsa_public_key_or_xfail", read_pub)


def test_pss_mismatch_clean_reject_is_xfail(monkeypatch: pytest.MonkeyPatch) -> None:
    """A module that rejects the mismatched PSS params -> xfail(not_operational)."""
    clear()
    _wire_pss(monkeypatch, sign=_ckr_refuse)
    with pytest.raises(XFailed):
        pss_mod.TestPssParamMismatch().test_pss_hash_mismatch(_rs())
    assert get_records()[-1].reason == "not_operational"


def test_pss_mismatch_accept_then_invalid_sig_is_fail(monkeypatch: pytest.MonkeyPatch) -> None:
    """A module that accepts the mismatch but produces an invalid sig -> wrong_result."""
    # Sign returns a garbage byte-string that cannot verify under any standard MGF.
    _wire_pss(
        monkeypatch,
        sign=lambda *a, **k: b"\x00" * 256,
        read_pub=lambda rs, pub, *, label: rsa.generate_private_key(65537, 2048).public_key(),
    )
    with pytest.raises(Failed):
        pss_mod.TestPssParamMismatch().test_pss_hash_mismatch(_rs())
    rec = get_records()[-1]
    assert rec.reason == "wrong_result"
    assert rec.kind == "crypto"


def test_pss_mismatch_accept_then_valid_sig_is_honest_deviation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A module that accepts and produces a VALID sig -> honest_deviation (fidelity finding)."""
    # Use a real local keypair so recover_mgf and recover_salt_len succeed.
    real_key = rsa.generate_private_key(65537, 2048)
    msg = pss_mod._MSG

    def _real_sign(*_a: Any, **_kw: Any) -> bytes:
        return real_key.sign(
            msg,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=20),
            hashes.SHA256(),
        )

    _wire_pss(
        monkeypatch,
        sign=_real_sign,
        read_pub=lambda rs, pub, *, label: real_key.public_key(),
    )
    clear()
    with pytest.raises(XFailed):
        pss_mod.TestPssParamMismatch().test_pss_hash_mismatch(_rs())
    rec = get_records()[-1]
    assert rec.reason == "honest_deviation"
    assert rec.kind == "metadata"


def test_pss_mismatch_skipped_when_mechanism_absent(monkeypatch: pytest.MonkeyPatch) -> None:
    """Probe is skipped when mechanism is not advertised."""
    _wire_pss(monkeypatch)
    with pytest.raises(pytest.skip.Exception):
        pss_mod.TestPssParamMismatch().test_pss_hash_mismatch(_rs(has_mech=False))


# ---- OAEP source-param self-contradiction ----


def _wire_oaep(
    monkeypatch: pytest.MonkeyPatch,
    *,
    import_kp: Any = None,
    encrypt: Any = None,
) -> None:
    monkeypatch.setattr(oaep_mod, "destroy_quietly", lambda *a, **k: None)
    monkeypatch.setattr(oaep_mod, "mech_oaep_source_contradiction", lambda *a, **k: object())
    if import_kp is not None:
        monkeypatch.setattr(oaep_mod, "_import_known_keypair", import_kp)
    if encrypt is not None:
        monkeypatch.setattr(oaep_mod, "encrypt_single", encrypt)


def test_oaep_mismatch_clean_reject_is_xfail(monkeypatch: pytest.MonkeyPatch) -> None:
    """A module that rejects the self-contradictory OAEP params -> xfail(not_operational)."""
    clear()
    real_key = rsa.generate_private_key(65537, 2048)
    _wire_oaep(
        monkeypatch,
        import_kp=lambda rs: (real_key, 3, 4),
        encrypt=_ckr_refuse,
    )
    with pytest.raises(XFailed):
        oaep_mod.TestOaepParamMismatch().test_oaep_source_param_self_contradiction(_rs())
    assert get_records()[-1].reason == "not_operational"


def test_oaep_mismatch_accept_recoverable_is_honest_deviation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A module accepting the self-contradictory struct with recoverable output -> honest_deviation."""  # noqa: E501
    real_key = rsa.generate_private_key(65537, 2048)
    plaintext = oaep_mod._PLAINTEXT

    def _encrypt_sha1(*_a: Any, **_kw: Any) -> bytes:
        # Produce a valid ciphertext (module accepted the self-contradictory struct)
        return real_key.public_key().encrypt(
            plaintext,
            padding.OAEP(
                mgf=padding.MGF1(hashes.SHA1()),  # nosec B303
                algorithm=hashes.SHA1(),  # nosec B303
                label=None,
            ),
        )

    _wire_oaep(
        monkeypatch,
        import_kp=lambda rs: (real_key, 3, 4),
        encrypt=_encrypt_sha1,
    )
    clear()
    with pytest.raises(XFailed):
        oaep_mod.TestOaepParamMismatch().test_oaep_source_param_self_contradiction(_rs())
    rec = get_records()[-1]
    assert rec.reason == "honest_deviation"
    assert rec.kind == "metadata"


def test_oaep_mismatch_accept_unrecoverable_is_not_operational(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """If module encrypts but recover_oaep_params fails -> not_operational (interpretable=False)."""
    real_key = rsa.generate_private_key(65537, 2048)

    def _encrypt_bad(*_a: Any, **_kw: Any) -> bytes:
        return b"\x00" * 256  # not a valid OAEP ciphertext

    _wire_oaep(
        monkeypatch,
        import_kp=lambda rs: (real_key, 3, 4),
        encrypt=_encrypt_bad,
    )
    clear()
    with pytest.raises(XFailed):
        oaep_mod.TestOaepParamMismatch().test_oaep_source_param_self_contradiction(_rs())
    rec = get_records()[-1]
    assert rec.reason == "not_operational"


def test_oaep_mismatch_skipped_when_mechanism_absent(monkeypatch: pytest.MonkeyPatch) -> None:
    """Probe is skipped when OAEP is not advertised."""
    _wire_oaep(monkeypatch)
    with pytest.raises(pytest.skip.Exception):
        oaep_mod.TestOaepParamMismatch().test_oaep_source_param_self_contradiction(
            _rs(has_mech=False)
        )
