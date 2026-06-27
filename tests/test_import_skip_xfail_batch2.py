"""TDD meta-tests for Batch 2 import-skip -> xfail conversion (A5/A7/A8/A14).

Audit reference: import-skip-audit §4 Batch 2.

Batch 2 covers EC/Edwards public-key-import sites that already SPLIT the import
reject into two branches:

* a genuine-capability-absence branch keyed on CKR_CURVE_NOT_SUPPORTED /
  CKR_DOMAIN_PARAMS_INVALID -- the specific curve is absent -> stays a ``skip``;
* a broad import-failure branch (CKR_ATTRIBUTE_VALUE_INVALID,
  CKR_TEMPLATE_INCONSISTENT, CKR_MECHANISM_INVALID, CKR_KEY_SIZE_RANGE, ...) on an
  ADVERTISED mechanism -> "advertised but not operational" -> ``xfail``.

Only the broad branch flips. These tests pin the split survives:

* (a) broad CKR (CKR_ATTRIBUTE_VALUE_INVALID) -> XFailed "advertised but not
  operational"  [RED first: the pre-fix code Skipped]
* (b) curve-unsupported CKR (CKR_CURVE_NOT_SUPPORTED / CKR_DOMAIN_PARAMS_INVALID)
  -> still Skipped  [pin the split is preserved]
* (c) a non-CKR AssertionError propagates (harness-bug path; never xfail/skip).

Hard-pin (mirrors commit e0340c2d): an unexpected ``Skipped`` escaping where an
``XFailed`` is expected is caught and converted to ``pytest.fail`` so CI cannot
silently swallow a regression.
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
)

# ---------------------------------------------------------------------------
# Shared CKR fixtures
# ---------------------------------------------------------------------------

_ATTR_INVALID = CkrAssertionError(
    "Unexpected CK_RV CKR_ATTRIBUTE_VALUE_INVALID", int(CKR_ATTRIBUTE_VALUE_INVALID)
)
_CURVE_NOT_SUPPORTED = CkrAssertionError(
    "Unexpected CK_RV CKR_CURVE_NOT_SUPPORTED", int(CKR_CURVE_NOT_SUPPORTED)
)
_DOMAIN_PARAMS_INVALID = CkrAssertionError(
    "Unexpected CK_RV CKR_DOMAIN_PARAMS_INVALID", int(CKR_DOMAIN_PARAMS_INVALID)
)
_NON_CKR = AssertionError("verify returned False after valid sign")


def _raiser(exc: BaseException) -> Any:
    def _raise(*_a: Any, **_kw: Any) -> Any:
        raise exc

    return _raise


def _session() -> SimpleNamespace:
    return SimpleNamespace(
        raw=object(), sh=1, has_mechanism=lambda _name: True, has_mechanism_flag=lambda _m, _f: True
    )


# ===========================================================================
# A5: wycheproof/test_wycheproof_ecdsa.py  test_ecdsa_wycheproof
#     broad branch (_EC_PUBLIC_IMPORT_UNSUPPORTED_CKRS) -> xfail
#     curve-unsupported branch (_CURVE_UNSUPPORTED_CKRS) -> skip
# ===========================================================================


def _ecdsa_vec(result: str = "valid") -> dict[str, Any]:
    # secp256r1, P1363-encoded 64-byte signature (no DER decode needed).
    uncompressed = "04" + "11" * 64  # 0x04 || X(32) || Y(32)
    return {
        "tcId": 1,
        "msg": "deadbeef",
        "sig": "aa" * 64,
        "result": result,
        "_curve": "secp256r1",
        "_coord_size": 32,
        "_is_p1363": True,
        "_hash_fn": __import__("hashlib").sha256,
        "_group": {"publicKey": {"uncompressed": uncompressed}},
    }


def test_a5_ecdsa_broad_import_reject_xfails(monkeypatch: pytest.MonkeyPatch) -> None:
    """A5: broad CKR from negotiated EC import -> xfail (advertised but not operational)."""
    import pkcs11_check.testcases.wycheproof.test_wycheproof_ecdsa as mod

    monkeypatch.setattr(mod, "import_ec_public_key_negotiated", _raiser(_ATTR_INVALID))

    try:
        with pytest.raises(pytest.xfail.Exception, match="advertised but not operational"):
            mod.test_ecdsa_wycheproof(_session(), "tc1-valid", _ecdsa_vec())
    except pytest.skip.Exception as exc:
        pytest.fail(f"skipped instead of xfailing: {exc}")


def test_a5_ecdsa_curve_unsupported_still_skips(monkeypatch: pytest.MonkeyPatch) -> None:
    """A5: curve-unsupported CKR keeps the genuine-absence skip (split preserved)."""
    import pkcs11_check.testcases.wycheproof.test_wycheproof_ecdsa as mod

    monkeypatch.setattr(mod, "import_ec_public_key_negotiated", _raiser(_CURVE_NOT_SUPPORTED))
    # Avoid the module-level _UNSUPPORTED_CURVES cache leaking across tests.
    monkeypatch.setattr(mod, "_UNSUPPORTED_CURVES", set())

    with pytest.raises(pytest.skip.Exception, match="Cannot import EC key for"):
        mod.test_ecdsa_wycheproof(_session(), "tc1-valid", _ecdsa_vec())


def test_a5_ecdsa_non_ckr_propagates(monkeypatch: pytest.MonkeyPatch) -> None:
    """A5 negative pin: a non-CKR AssertionError propagates (not xfail, not skip)."""
    import pkcs11_check.testcases.wycheproof.test_wycheproof_ecdsa as mod

    monkeypatch.setattr(mod, "import_ec_public_key_negotiated", _raiser(_NON_CKR))

    with pytest.raises(AssertionError, match="verify returned False"):
        mod.test_ecdsa_wycheproof(_session(), "tc1-valid", _ecdsa_vec())


# ===========================================================================
# A7: wycheproof/test_wycheproof_ed25519.py  test_ed25519_wycheproof
#     broad branch (_EDWARDS_PUBLIC_IMPORT_UNSUPPORTED_CKRS) -> xfail
#     curve-unsupported branch (_CURVE_UNSUPPORTED_CKRS) -> skip
# ===========================================================================


def _ed25519_vec() -> dict[str, Any]:
    return {
        "tcId": 1,
        "msg": "deadbeef",
        "sig": "aa" * 64,
        "result": "valid",
        "_pk": {"pk": "11" * 32},
    }


def test_a7_ed25519_broad_import_reject_xfails(monkeypatch: pytest.MonkeyPatch) -> None:
    """A7: broad CKR from the Edwards multi-encoding import -> xfail."""
    import pkcs11_check.testcases.wycheproof.test_wycheproof_ed25519 as mod

    # The encoding probe runs first; make it a no-op so the import path is reached.
    monkeypatch.setattr(mod, "select_eddsa_public_key_encoding", lambda *_a, **_kw: None)
    monkeypatch.setattr(
        mod, "import_eddsa_public_key_with_supported_encoding", _raiser(_ATTR_INVALID)
    )
    monkeypatch.setattr(mod, "_UNSUPPORTED_CURVE_OIDS", set())

    try:
        with pytest.raises(pytest.xfail.Exception, match="advertised but not operational"):
            mod.test_ed25519_wycheproof(_session(), "tc1-valid", _ed25519_vec())
    except pytest.skip.Exception as exc:
        pytest.fail(f"skipped instead of xfailing: {exc}")


def test_a7_ed25519_curve_unsupported_still_skips(monkeypatch: pytest.MonkeyPatch) -> None:
    """A7: curve-unsupported CKR keeps the genuine-absence skip (split preserved)."""
    import pkcs11_check.testcases.wycheproof.test_wycheproof_ed25519 as mod

    monkeypatch.setattr(mod, "select_eddsa_public_key_encoding", lambda *_a, **_kw: None)
    monkeypatch.setattr(
        mod, "import_eddsa_public_key_with_supported_encoding", _raiser(_DOMAIN_PARAMS_INVALID)
    )
    monkeypatch.setattr(mod, "_UNSUPPORTED_CURVE_OIDS", set())

    with pytest.raises(pytest.skip.Exception, match="Cannot import Ed25519 public key"):
        mod.test_ed25519_wycheproof(_session(), "tc1-valid", _ed25519_vec())


def test_a7_ed25519_non_ckr_propagates(monkeypatch: pytest.MonkeyPatch) -> None:
    """A7 negative pin: a non-CKR AssertionError propagates."""
    import pkcs11_check.testcases.wycheproof.test_wycheproof_ed25519 as mod

    monkeypatch.setattr(mod, "select_eddsa_public_key_encoding", lambda *_a, **_kw: None)
    monkeypatch.setattr(mod, "import_eddsa_public_key_with_supported_encoding", _raiser(_NON_CKR))
    monkeypatch.setattr(mod, "_UNSUPPORTED_CURVE_OIDS", set())

    with pytest.raises(AssertionError, match="verify returned False"):
        mod.test_ed25519_wycheproof(_session(), "tc1-valid", _ed25519_vec())


# ===========================================================================
# A8: acvp/test_acvp_eddsa.py  test_acvp_eddsa_sigver
#     broad branch (_EDWARDS_PUBLIC_IMPORT_UNSUPPORTED_RVS) -> xfail
#     curve-absent branch (_EDWARDS_CURVE_ABSENT_RVS) -> skip
# ===========================================================================


def _acvp_eddsa_vec() -> dict[str, Any]:
    return {
        "ec_params": b"params",
        "q": b"Q" * 32,
        "ec_point": b"Q" * 32,
        "curve": "ED-25519",
        "expected_pass": True,
    }


def test_a8_acvp_eddsa_broad_import_reject_xfails(monkeypatch: pytest.MonkeyPatch) -> None:
    """A8: broad CKR from the EdDSA public-key import -> xfail."""
    import pkcs11_check.testcases.acvp.test_acvp_eddsa as mod

    # The encoding probe runs first; make it a no-op so the import path is reached.
    monkeypatch.setattr(mod, "select_eddsa_public_key_encoding", lambda *_a, **_kw: None)
    monkeypatch.setattr(
        mod, "import_eddsa_public_key_with_supported_encoding", _raiser(_ATTR_INVALID)
    )

    try:
        with pytest.raises(pytest.xfail.Exception, match="advertised but not operational"):
            mod.test_acvp_eddsa_sigver(_session(), "EDDSA-SigVer-ED-25519-tc1", _acvp_eddsa_vec())
    except pytest.skip.Exception as exc:
        pytest.fail(f"skipped instead of xfailing: {exc}")


def test_a8_acvp_eddsa_curve_absent_still_skips(monkeypatch: pytest.MonkeyPatch) -> None:
    """A8: curve-absent CKR keeps the genuine-absence skip (split preserved)."""
    import pkcs11_check.testcases.acvp.test_acvp_eddsa as mod

    monkeypatch.setattr(mod, "select_eddsa_public_key_encoding", lambda *_a, **_kw: None)
    monkeypatch.setattr(
        mod, "import_eddsa_public_key_with_supported_encoding", _raiser(_CURVE_NOT_SUPPORTED)
    )

    with pytest.raises(pytest.skip.Exception, match="Cannot import EdDSA public key for"):
        mod.test_acvp_eddsa_sigver(_session(), "EDDSA-SigVer-ED-25519-tc1", _acvp_eddsa_vec())


def test_a8_acvp_eddsa_non_ckr_propagates(monkeypatch: pytest.MonkeyPatch) -> None:
    """A8 negative pin: a non-CKR AssertionError propagates."""
    import pkcs11_check.testcases.acvp.test_acvp_eddsa as mod

    monkeypatch.setattr(mod, "select_eddsa_public_key_encoding", lambda *_a, **_kw: None)
    monkeypatch.setattr(mod, "import_eddsa_public_key_with_supported_encoding", _raiser(_NON_CKR))

    with pytest.raises(AssertionError, match="verify returned False"):
        mod.test_acvp_eddsa_sigver(_session(), "EDDSA-SigVer-ED-25519-tc1", _acvp_eddsa_vec())


# ===========================================================================
# A14: acvp/test_acvp_ecdsa.py  test_acvp_ecdsa_sigver
#      broad branch (_EC_PUBLIC_IMPORT_UNSUPPORTED_RVS) -> xfail
#      curve-absent branch (_EC_CURVE_ABSENT_RVS) -> skip
# ===========================================================================


def _acvp_ecdsa_vec() -> dict[str, Any]:
    from pkcs11_check.raw.types_std import CKM_ECDSA_SHA256

    return {
        "mech_int": int(CKM_ECDSA_SHA256),
        "mech_name": "ECDSA_SHA256",
        "ec_params": b"params",
        "ec_point_der": b"point",
        "curve": "P-256",
        "expected_pass": True,
        "msg": b"message",
        "sig": b"S" * 64,
    }


def test_a14_acvp_ecdsa_broad_import_reject_xfails(monkeypatch: pytest.MonkeyPatch) -> None:
    """A14: broad CKR from provision_public_key (create path) -> xfail."""
    import pkcs11_check.testcases.acvp.test_acvp_ecdsa as mod

    monkeypatch.setattr(mod, "provision_public_key", _raiser(_ATTR_INVALID))

    try:
        with pytest.raises(pytest.xfail.Exception, match="advertised but not operational"):
            mod.test_acvp_ecdsa_sigver(
                _session(), None, "ECDSA-SigVer-P-256-tc1", _acvp_ecdsa_vec()
            )
    except pytest.skip.Exception as exc:
        pytest.fail(f"skipped instead of xfailing: {exc}")


def test_a14_acvp_ecdsa_curve_absent_still_skips(monkeypatch: pytest.MonkeyPatch) -> None:
    """A14: curve-absent CKR keeps the genuine-absence skip (split preserved)."""
    import pkcs11_check.testcases.acvp.test_acvp_ecdsa as mod

    monkeypatch.setattr(mod, "provision_public_key", _raiser(_DOMAIN_PARAMS_INVALID))

    with pytest.raises(pytest.skip.Exception, match="Cannot import EC public key for"):
        mod.test_acvp_ecdsa_sigver(_session(), None, "ECDSA-SigVer-P-256-tc1", _acvp_ecdsa_vec())


def test_a14_acvp_ecdsa_non_ckr_propagates(monkeypatch: pytest.MonkeyPatch) -> None:
    """A14 negative pin: a non-CKR AssertionError propagates."""
    import pkcs11_check.testcases.acvp.test_acvp_ecdsa as mod

    monkeypatch.setattr(mod, "provision_public_key", _raiser(_NON_CKR))

    with pytest.raises(AssertionError, match="verify returned False"):
        mod.test_acvp_ecdsa_sigver(_session(), None, "ECDSA-SigVer-P-256-tc1", _acvp_ecdsa_vec())
