"""Classification meta-tests for RSA key-transport unwrap advertised-but-not-operational (FIPS).

FIPS 140-3 restricts RSA PKCS#1 v1.5 key transport, so kryoptic-FIPS advertises
``CKM_RSA_PKCS`` but returns ``CKR_DEVICE_ERROR`` on the private-key ``C_UnwrapKey``
call.  A clean refusal produces no unwrapped key, so per the classification model it is
an "advertised but not operational" deviation (xfail), not a hard fail.

Three invariants tested here:

(a) Unwrap refusal with a clean CKR (CKR_DEVICE_ERROR) -> xfail "not operational".
(b) Wrap + unwrap succeeding with matching key material -> test passes.
(c) Unwrap succeeds but follow-on usage assertion fails (wrong ciphertext / wrong value)
    -> hard fail (Type-C territory: C_UnwrapKey claimed success, usage contradicts it).
(d) A non-CKR AssertionError from unwrap (harness/ctypes bug) propagates unchanged.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest
from _pytest.outcomes import Failed, XFailed

from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import CKR_DEVICE_ERROR
from pkcs11_check.testcases import test_rsa_key_wrapping as rw


def _rs() -> SimpleNamespace:
    return SimpleNamespace(raw=object(), sh=1, slot_id=0, has_mechanism=lambda _n: True)


def _p11_config() -> SimpleNamespace:
    return SimpleNamespace(pin=None)


def _device_error(*_a: Any, **_k: Any) -> Any:
    raise CkrAssertionError("Unexpected CK_RV CKR_DEVICE_ERROR", int(CKR_DEVICE_ERROR))


# ===========================================================================
# (a) Unwrap refusal (CKR_DEVICE_ERROR) -> xfail "not operational"
# ===========================================================================


def test_aes128_unwrap_clean_refusal_xfails(monkeypatch: pytest.MonkeyPatch) -> None:
    """CKR_DEVICE_ERROR on the unwrap leg of test_wrap_unwrap_aes128 -> xfail."""
    monkeypatch.setattr(rw, "_make_rsa_pair", lambda rs: (1, 2))
    monkeypatch.setattr(rw, "_make_extractable_aes", lambda rs, bits=128: 3)
    monkeypatch.setattr(rw, "read_attributes", lambda *_a, **_k: {rw.CKA_VALUE: b"orig"})
    monkeypatch.setattr(rw, "wrap_key_recipe", lambda *_a, **_k: b"\x00" * 256)
    monkeypatch.setattr(rw, "unwrap_key_for_mechanism_roundtrip", _device_error)
    monkeypatch.setattr(rw, "destroy_quietly", lambda *_a, **_k: None)
    with pytest.raises(XFailed, match="not operational"):
        rw.TestRSAPKCSWrap().test_wrap_unwrap_aes128(_rs(), _p11_config())


def test_aes256_unwrap_clean_refusal_xfails(monkeypatch: pytest.MonkeyPatch) -> None:
    """CKR_DEVICE_ERROR on the unwrap leg of test_wrap_unwrap_aes256 -> xfail."""
    monkeypatch.setattr(rw, "_make_rsa_pair", lambda rs: (1, 2))
    monkeypatch.setattr(rw, "_make_extractable_aes", lambda rs, bits=128: 3)
    monkeypatch.setattr(rw, "read_attributes", lambda *_a, **_k: {rw.CKA_VALUE: b"orig"})
    monkeypatch.setattr(rw, "wrap_key_recipe", lambda *_a, **_k: b"\x00" * 256)
    monkeypatch.setattr(rw, "unwrap_key_for_mechanism_roundtrip", _device_error)
    monkeypatch.setattr(rw, "destroy_quietly", lambda *_a, **_k: None)
    with pytest.raises(XFailed, match="not operational"):
        rw.TestRSAPKCSWrap().test_wrap_unwrap_aes256(_rs(), _p11_config())


def test_usability_unwrap_clean_refusal_xfails(monkeypatch: pytest.MonkeyPatch) -> None:
    """CKR_DEVICE_ERROR on the unwrap leg of test_unwrapped_key_encrypts -> xfail."""
    monkeypatch.setattr(rw, "_make_rsa_pair", lambda rs: (1, 2))
    monkeypatch.setattr(
        rw,
        "gen_aes_key",
        lambda *_a, **_k: 3,
    )
    monkeypatch.setattr(rw, "encrypt_single", lambda *_a, **_k: b"ct")
    monkeypatch.setattr(rw, "wrap_key_recipe", lambda *_a, **_k: b"\x00" * 256)
    monkeypatch.setattr(rw, "unwrap_key_for_mechanism_roundtrip", _device_error)
    monkeypatch.setattr(rw, "destroy_quietly", lambda *_a, **_k: None)
    with pytest.raises(XFailed, match="not operational"):
        rw.TestWrappedKeyUsability().test_unwrapped_key_encrypts(_rs(), _p11_config())


# ===========================================================================
# (b) Full roundtrip OK -> test passes
# ===========================================================================


def test_aes128_roundtrip_ok_passes(monkeypatch: pytest.MonkeyPatch) -> None:
    """Wrap + unwrap OK with matching value -> test passes."""
    monkeypatch.setattr(rw, "_make_rsa_pair", lambda rs: (1, 2))
    monkeypatch.setattr(rw, "_make_extractable_aes", lambda rs, bits=128: 3)
    original = b"key-material-128"
    monkeypatch.setattr(
        rw,
        "read_attributes",
        lambda raw, sh, handle, keys: {rw.CKA_VALUE: original},
    )
    monkeypatch.setattr(rw, "wrap_key_recipe", lambda *_a, **_k: b"\x00" * 256)
    monkeypatch.setattr(rw, "unwrap_key_for_mechanism_roundtrip", lambda *_a, **_k: 99)
    monkeypatch.setattr(rw, "destroy_quietly", lambda *_a, **_k: None)
    rw.TestRSAPKCSWrap().test_wrap_unwrap_aes128(_rs(), _p11_config())


def test_aes256_roundtrip_ok_passes(monkeypatch: pytest.MonkeyPatch) -> None:
    """Wrap + unwrap OK with matching value -> test passes."""
    monkeypatch.setattr(rw, "_make_rsa_pair", lambda rs: (1, 2))
    monkeypatch.setattr(rw, "_make_extractable_aes", lambda rs, bits=128: 3)
    original = b"key-material-256-bytes-long-here"
    monkeypatch.setattr(
        rw,
        "read_attributes",
        lambda raw, sh, handle, keys: {rw.CKA_VALUE: original},
    )
    monkeypatch.setattr(rw, "wrap_key_recipe", lambda *_a, **_k: b"\x00" * 256)
    monkeypatch.setattr(rw, "unwrap_key_for_mechanism_roundtrip", lambda *_a, **_k: 99)
    monkeypatch.setattr(rw, "destroy_quietly", lambda *_a, **_k: None)
    rw.TestRSAPKCSWrap().test_wrap_unwrap_aes256(_rs(), _p11_config())


def test_usability_roundtrip_ok_passes(monkeypatch: pytest.MonkeyPatch) -> None:
    """Unwrap OK and decrypted plaintext matches -> test passes."""
    plaintext = b"wrap-test-data!!" * 2
    monkeypatch.setattr(rw, "_make_rsa_pair", lambda rs: (1, 2))
    monkeypatch.setattr(rw, "gen_aes_key", lambda *_a, **_k: 3)
    monkeypatch.setattr(rw, "encrypt_single", lambda *_a, **_k: b"ct")
    monkeypatch.setattr(rw, "wrap_key_recipe", lambda *_a, **_k: b"\x00" * 256)
    monkeypatch.setattr(rw, "unwrap_key_for_mechanism_roundtrip", lambda *_a, **_k: 99)
    monkeypatch.setattr(rw, "decrypt_single", lambda *_a, **_k: plaintext)
    monkeypatch.setattr(rw, "destroy_quietly", lambda *_a, **_k: None)
    rw.TestWrappedKeyUsability().test_unwrapped_key_encrypts(_rs(), _p11_config())


# ===========================================================================
# (c) Unwrap OK but follow-on assertion fails -> hard fail (Type-C territory)
#     The helper must NOT swallow post-unwrap assertion failures.
# ===========================================================================


def test_aes128_wrong_value_after_unwrap_hard_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    """Unwrap OK but value mismatch is a real break (not swallowed by helper)."""
    monkeypatch.setattr(rw, "_make_rsa_pair", lambda rs: (1, 2))
    monkeypatch.setattr(rw, "_make_extractable_aes", lambda rs, bits=128: 3)
    call_count = [0]

    def _read_attrs(raw: Any, sh: Any, handle: Any, keys: Any) -> dict[Any, Any]:
        call_count[0] += 1
        if call_count[0] == 1:
            return {rw.CKA_VALUE: b"original-value!!"}
        return {rw.CKA_VALUE: b"WRONG-VALUE!!!!"}  # post-unwrap read

    monkeypatch.setattr(rw, "read_attributes", _read_attrs)
    monkeypatch.setattr(rw, "wrap_key_recipe", lambda *_a, **_k: b"\x00" * 256)
    monkeypatch.setattr(rw, "unwrap_key_for_mechanism_roundtrip", lambda *_a, **_k: 99)
    monkeypatch.setattr(rw, "destroy_quietly", lambda *_a, **_k: None)
    # The post-unwrap value mismatch is now typed via assert_correct -> a
    # wrong_result classification (pytest.fail / Failed), not a bare assert.
    with pytest.raises(Failed, match="does not match known answer"):
        rw.TestRSAPKCSWrap().test_wrap_unwrap_aes128(_rs(), _p11_config())


def test_usability_wrong_plaintext_after_unwrap_hard_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Unwrap OK but decrypt produces wrong plaintext -> hard fail."""
    monkeypatch.setattr(rw, "_make_rsa_pair", lambda rs: (1, 2))
    monkeypatch.setattr(rw, "gen_aes_key", lambda *_a, **_k: 3)
    monkeypatch.setattr(rw, "encrypt_single", lambda *_a, **_k: b"ct")
    monkeypatch.setattr(rw, "wrap_key_recipe", lambda *_a, **_k: b"\x00" * 256)
    monkeypatch.setattr(rw, "unwrap_key_for_mechanism_roundtrip", lambda *_a, **_k: 99)
    monkeypatch.setattr(rw, "decrypt_single", lambda *_a, **_k: b"WRONG-PLAINTEXT")
    monkeypatch.setattr(rw, "destroy_quietly", lambda *_a, **_k: None)
    # The wrong decrypted plaintext is now typed via assert_correct -> a
    # wrong_result classification (pytest.fail / Failed), not a bare assert.
    with pytest.raises(Failed, match="does not match known answer"):
        rw.TestWrappedKeyUsability().test_unwrapped_key_encrypts(_rs(), _p11_config())


# ===========================================================================
# (d) Non-CKR AssertionError from unwrap (harness/ctypes bug) propagates
# ===========================================================================


def test_aes128_non_ckr_unwrap_error_propagates(monkeypatch: pytest.MonkeyPatch) -> None:
    """A plain AssertionError (no .rv) from unwrap must propagate unchanged."""
    monkeypatch.setattr(rw, "_make_rsa_pair", lambda rs: (1, 2))
    monkeypatch.setattr(rw, "_make_extractable_aes", lambda rs, bits=128: 3)
    monkeypatch.setattr(rw, "read_attributes", lambda *_a, **_k: {rw.CKA_VALUE: b"orig"})
    monkeypatch.setattr(rw, "wrap_key_recipe", lambda *_a, **_k: b"\x00" * 256)

    def _bug(*_a: Any, **_k: Any) -> Any:
        raise AssertionError("ctypes packing bug")

    monkeypatch.setattr(rw, "unwrap_key_for_mechanism_roundtrip", _bug)
    monkeypatch.setattr(rw, "destroy_quietly", lambda *_a, **_k: None)
    with pytest.raises(AssertionError, match="packing bug"):
        rw.TestRSAPKCSWrap().test_wrap_unwrap_aes128(_rs(), _p11_config())


def test_usability_non_ckr_unwrap_error_propagates(monkeypatch: pytest.MonkeyPatch) -> None:
    """A plain AssertionError (no .rv) from unwrap must propagate unchanged."""
    monkeypatch.setattr(rw, "_make_rsa_pair", lambda rs: (1, 2))
    monkeypatch.setattr(rw, "gen_aes_key", lambda *_a, **_k: 3)
    monkeypatch.setattr(rw, "encrypt_single", lambda *_a, **_k: b"ct")
    monkeypatch.setattr(rw, "wrap_key_recipe", lambda *_a, **_k: b"\x00" * 256)

    def _bug(*_a: Any, **_k: Any) -> Any:
        raise AssertionError("ctypes packing bug")

    monkeypatch.setattr(rw, "unwrap_key_for_mechanism_roundtrip", _bug)
    monkeypatch.setattr(rw, "destroy_quietly", lambda *_a, **_k: None)
    with pytest.raises(AssertionError, match="packing bug"):
        rw.TestWrappedKeyUsability().test_unwrapped_key_encrypts(_rs(), _p11_config())
