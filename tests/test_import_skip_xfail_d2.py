"""TDD meta-tests for D2 import-skip -> xfail conversion.

Audit doc: docs/findings/import-skip-audit.md category D, D2.

D2 covers the EC/Montgomery *private*-key import sites used to set up an ECDH
derive:

* wycheproof/test_wycheproof_x25519.py::test_xdh (Montgomery X25519/X448 private
  import), broad branch ``_MONTGOMERY_PRIVATE_IMPORT_UNSUPPORTED_CKRS``;
* wycheproof/test_wycheproof_ecdh.py::test_ecdh (named-curve EC private import),
  broad branch ``_EC_PRIVATE_IMPORT_UNSUPPORTED_CKRS``.

Both already SPLIT the reject:

* a genuine-capability-absence branch keyed on CKR_CURVE_NOT_SUPPORTED /
  CKR_DOMAIN_PARAMS_INVALID -- the specific curve is absent -> stays a ``skip``;
* a broad import-failure branch (CKR_ATTRIBUTE_VALUE_INVALID,
  CKR_FUNCTION_FAILED, ...) on a module that ADVERTISES (and operationally
  derives) ECDH1_DERIVE -> "advertised but not operational" -> ``xfail``.

The artifacts2 evidence overturns the audit's tentative B-lean: softhsm2 / tpm2 /
wolfpkcs11 / kryoptic all derive ECDH operationally (hundreds-to-thousands of
test_ecdh / test_xdh *passes*) yet refuse the canonical *valid*-vector private
import with a broad CKR -- the import is the only gap, so the leak is real.

Only the broad branch flips; the curve-unsupported branch and the
``result=="invalid"`` vacuous-return path are preserved.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import (
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_CURVE_NOT_SUPPORTED,
    CKR_DOMAIN_PARAMS_INVALID,
    CKR_FUNCTION_FAILED,
)
from pkcs11_check.testcases.wycheproof.test_wycheproof_x25519 import X25519_OID

_ATTR_INVALID = CkrAssertionError(
    "Unexpected CK_RV CKR_ATTRIBUTE_VALUE_INVALID", int(CKR_ATTRIBUTE_VALUE_INVALID)
)
_FUNCTION_FAILED = CkrAssertionError(
    "Unexpected CK_RV CKR_FUNCTION_FAILED", int(CKR_FUNCTION_FAILED)
)
_CURVE_NOT_SUPPORTED = CkrAssertionError(
    "Unexpected CK_RV CKR_CURVE_NOT_SUPPORTED", int(CKR_CURVE_NOT_SUPPORTED)
)
_DOMAIN_PARAMS_INVALID = CkrAssertionError(
    "Unexpected CK_RV CKR_DOMAIN_PARAMS_INVALID", int(CKR_DOMAIN_PARAMS_INVALID)
)
_NON_CKR = AssertionError("derive returned wrong shared secret")


def _raiser(exc: BaseException) -> Any:
    def _raise(*_a: Any, **_kw: Any) -> Any:
        raise exc

    return _raise


def _session() -> SimpleNamespace:
    return SimpleNamespace(raw=object(), sh=1, has_mechanism=lambda _name: True)


# ===========================================================================
# D2a: wycheproof/test_wycheproof_x25519.py  test_xdh
#      broad branch (_MONTGOMERY_PRIVATE_IMPORT_UNSUPPORTED_CKRS) -> xfail
#      curve-unsupported branch (_CURVE_UNSUPPORTED_CKRS) -> skip
# ===========================================================================


def _xdh_vec(result: str = "valid") -> dict[str, Any]:
    return {
        "tcId": 1,
        "private": "11" * 32,
        "public": "22" * 32,
        "shared": "33" * 32,
        "result": result,
        "_oid": X25519_OID,
        "_key_size": 32,
        "_encoding": "raw",
    }


def _patch_xdh_decoders(monkeypatch: pytest.MonkeyPatch, mod: Any) -> None:
    monkeypatch.setattr(mod, "decode_xdh_private_bytes", lambda *_a, **_kw: b"\x11" * 32)
    monkeypatch.setattr(mod, "decode_xdh_public_bytes", lambda *_a, **_kw: b"\x22" * 32)
    monkeypatch.setattr(mod, "_UNSUPPORTED_CURVE_OIDS", set())


def test_d2a_xdh_broad_import_reject_xfails(monkeypatch: pytest.MonkeyPatch) -> None:
    """D2a: broad CKR from the Montgomery private import -> xfail."""
    import pkcs11_check.testcases.wycheproof.test_wycheproof_x25519 as mod

    _patch_xdh_decoders(monkeypatch, mod)
    monkeypatch.setattr(mod, "provision_ec_private_key", _raiser(_ATTR_INVALID))

    try:
        with pytest.raises(pytest.xfail.Exception, match="advertised but not operational"):
            mod.test_xdh(_session(), None, "x25519_test.json:tc1-valid", _xdh_vec("valid"))
    except pytest.skip.Exception as exc:
        pytest.fail(f"skipped instead of xfailing: {exc}")


def test_d2a_xdh_curve_unsupported_still_skips(monkeypatch: pytest.MonkeyPatch) -> None:
    """D2a: curve-unsupported CKR keeps the genuine-absence skip (split preserved)."""
    import pkcs11_check.testcases.wycheproof.test_wycheproof_x25519 as mod

    _patch_xdh_decoders(monkeypatch, mod)
    monkeypatch.setattr(mod, "provision_ec_private_key", _raiser(_CURVE_NOT_SUPPORTED))

    with pytest.raises(pytest.skip.Exception, match="Cannot import Montgomery private key"):
        mod.test_xdh(_session(), None, "x25519_test.json:tc1-valid", _xdh_vec("valid"))


def test_d2a_xdh_invalid_vector_broad_reject_returns(monkeypatch: pytest.MonkeyPatch) -> None:
    """D2a: an invalid vector that cannot be imported passes vacuously (returns)."""
    import pkcs11_check.testcases.wycheproof.test_wycheproof_x25519 as mod

    _patch_xdh_decoders(monkeypatch, mod)
    monkeypatch.setattr(mod, "provision_ec_private_key", _raiser(_ATTR_INVALID))

    # No xfail / skip raised: invalid vector + un-importable key returns cleanly.
    mod.test_xdh(_session(), None, "x25519_test.json:tc1-invalid", _xdh_vec("invalid"))


def test_d2a_xdh_non_ckr_propagates(monkeypatch: pytest.MonkeyPatch) -> None:
    """D2a negative pin: a non-CKR AssertionError propagates (not xfail, not skip)."""
    import pkcs11_check.testcases.wycheproof.test_wycheproof_x25519 as mod

    _patch_xdh_decoders(monkeypatch, mod)
    monkeypatch.setattr(mod, "provision_ec_private_key", _raiser(_NON_CKR))

    with pytest.raises(AssertionError, match="derive returned wrong shared secret"):
        mod.test_xdh(_session(), None, "x25519_test.json:tc1-valid", _xdh_vec("valid"))


# ===========================================================================
# D2b: wycheproof/test_wycheproof_ecdh.py  test_ecdh
#      broad branch (_EC_PRIVATE_IMPORT_UNSUPPORTED_CKRS) -> xfail
#      curve-unsupported branch (_CURVE_UNSUPPORTED_CKRS) -> skip
# ===========================================================================


def _ecdh_vec(result: str = "valid") -> dict[str, Any]:
    return {
        "tcId": 1,
        "private": "11" * 32,
        "public": "04" + "22" * 64,
        "shared": "33" * 32,
        "result": result,
        "_curve": "secp256r1",
        "_encoding": "ecpoint",
    }


def _patch_ecdh_decoders(monkeypatch: pytest.MonkeyPatch, mod: Any) -> None:
    monkeypatch.setattr(mod, "ec_params_for_curve", lambda *_a, **_kw: b"\x06\x03\x2a")
    monkeypatch.setattr(mod, "decode_ec_public_point", lambda *_a, **_kw: b"\x04" + b"\x22" * 64)
    monkeypatch.setattr(mod, "decode_ec_private_scalar", lambda *_a, **_kw: b"\x11" * 32)
    monkeypatch.setattr(mod, "_UNSUPPORTED_CURVES", set())


def test_d2b_ecdh_broad_import_reject_xfails(monkeypatch: pytest.MonkeyPatch) -> None:
    """D2b: broad CKR from the named-curve EC private import -> xfail."""
    import pkcs11_check.testcases.wycheproof.test_wycheproof_ecdh as mod

    _patch_ecdh_decoders(monkeypatch, mod)
    monkeypatch.setattr(mod, "provision_ec_private_key", _raiser(_FUNCTION_FAILED))

    try:
        with pytest.raises(pytest.xfail.Exception, match="advertised but not operational"):
            mod.test_ecdh(_session(), None, "ecdh_secp256r1:tc1-valid", _ecdh_vec("valid"))
    except pytest.skip.Exception as exc:
        pytest.fail(f"skipped instead of xfailing: {exc}")


def test_d2b_ecdh_curve_unsupported_still_skips(monkeypatch: pytest.MonkeyPatch) -> None:
    """D2b: curve-unsupported CKR keeps the genuine-absence skip (split preserved)."""
    import pkcs11_check.testcases.wycheproof.test_wycheproof_ecdh as mod

    _patch_ecdh_decoders(monkeypatch, mod)
    monkeypatch.setattr(mod, "provision_ec_private_key", _raiser(_DOMAIN_PARAMS_INVALID))

    with pytest.raises(pytest.skip.Exception, match="Cannot import EC private key for ECDH"):
        mod.test_ecdh(_session(), None, "ecdh_secp256r1:tc1-valid", _ecdh_vec("valid"))


def test_d2b_ecdh_invalid_vector_broad_reject_returns(monkeypatch: pytest.MonkeyPatch) -> None:
    """D2b: an invalid vector that cannot be imported passes vacuously (returns)."""
    import pkcs11_check.testcases.wycheproof.test_wycheproof_ecdh as mod

    _patch_ecdh_decoders(monkeypatch, mod)
    monkeypatch.setattr(mod, "provision_ec_private_key", _raiser(_FUNCTION_FAILED))

    mod.test_ecdh(_session(), None, "ecdh_secp256r1:tc1-invalid", _ecdh_vec("invalid"))


def test_d2b_ecdh_non_ckr_propagates(monkeypatch: pytest.MonkeyPatch) -> None:
    """D2b negative pin: a non-CKR AssertionError propagates (not xfail, not skip)."""
    import pkcs11_check.testcases.wycheproof.test_wycheproof_ecdh as mod

    _patch_ecdh_decoders(monkeypatch, mod)
    monkeypatch.setattr(mod, "provision_ec_private_key", _raiser(_NON_CKR))

    with pytest.raises(AssertionError, match="derive returned wrong shared secret"):
        mod.test_ecdh(_session(), None, "ecdh_secp256r1:tc1-valid", _ecdh_vec("valid"))
