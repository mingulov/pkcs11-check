"""TDD meta-tests for Batch 1 import-skip -> xfail conversion.

Audit doc: docs/findings/import-skip-audit.md §4 Batch 1.

Each Batch-1 site uses a *negotiated* importer (import_rsa_public_key_negotiated,
import_secret_key_negotiated) guarded by has_mechanism.  When negotiation exhaustion
raises CkrAssertionError on an ADVERTISED mechanism that is the subject of the test,
the classification model says "advertised but not operational" -> xfail, never skip.

Red phase: assertions that the CURRENT code *skips*.
Green phase (after production fix): flip to assert *xfails* with not_operational_reason.

Also pins the negative: a non-CKR AssertionError from the importer must propagate
(not xfail, not skip).
"""

from __future__ import annotations

import pytest

from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import (
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_FUNCTION_FAILED,
    CKR_TEMPLATE_INCONSISTENT,
)
from pkcs11_check.testcases._operability import reset_operability_cache

# ---------------------------------------------------------------------------
# Shared CKR fixture
# ---------------------------------------------------------------------------

_ATTR_INVALID = CkrAssertionError(
    "Unexpected CK_RV CKR_ATTRIBUTE_VALUE_INVALID", int(CKR_ATTRIBUTE_VALUE_INVALID)
)
_TEMPLATE_INCONS = CkrAssertionError(
    "Unexpected CK_RV CKR_TEMPLATE_INCONSISTENT", int(CKR_TEMPLATE_INCONSISTENT)
)
_FUNC_FAILED = CkrAssertionError("Unexpected CK_RV CKR_FUNCTION_FAILED", int(CKR_FUNCTION_FAILED))

_NON_CKR = AssertionError("verify returned False after valid sign")


@pytest.fixture(autouse=True)
def _reset_cache() -> None:
    reset_operability_cache()


# ---------------------------------------------------------------------------
# Helpers to build minimal fake session / vec objects
# ---------------------------------------------------------------------------


class _FakeRs:
    """Minimal stand-in for a p11_module_session that has a named mechanism."""

    def __init__(self, has: bool = True) -> None:
        self._has = has
        self.raw = object()
        self.sh = 1

    def has_mechanism(self, name: str) -> bool:  # noqa: ARG002
        return self._has


# ---------------------------------------------------------------------------
# A1: acvp/test_acvp_rsa.py  _skip_rsa_public_import_reject
# ---------------------------------------------------------------------------


def test_a1_skip_rsa_public_import_reject_xfails_on_ckr(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A1: CkrAssertionError from negotiated RSA import -> xfail, advertised but not operational."""
    import pkcs11_check.testcases.acvp.test_acvp_rsa as mod

    monkeypatch.setattr(
        mod,
        "import_rsa_public_key_negotiated",
        lambda *_a, **_kw: (_ for _ in ()).throw(_ATTR_INVALID),
    )

    with pytest.raises(pytest.xfail.Exception, match="advertised but not operational"):
        mod._skip_rsa_public_import_reject(_ATTR_INVALID, mech_name="SHA256_RSA_PKCS")


def test_a1_skip_rsa_public_import_reject_propagates_non_ckr(
    monkeypatch: pytest.MonkeyPatch,  # noqa: ARG001
) -> None:
    """A1 negative pin: non-CKR AssertionError must not be xfailed or skipped."""
    import pkcs11_check.testcases.acvp.test_acvp_rsa as mod

    with pytest.raises(AssertionError, match="verify returned False"):
        mod._skip_rsa_public_import_reject(_NON_CKR, mech_name="SHA256_RSA_PKCS")


# ---------------------------------------------------------------------------
# A4: wycheproof/test_wycheproof.py TestRSASigWycheproof.test_rsa_sig_2048_sha256
# ---------------------------------------------------------------------------


def test_a4_rsa_import_xfails_on_ckr(monkeypatch: pytest.MonkeyPatch) -> None:
    """A4: CkrAssertionError from negotiated RSA import -> xfail, not skip."""
    import pkcs11_check.testcases.wycheproof.test_wycheproof as mod

    rs = _FakeRs(has=True)

    # Patch the negotiated importer to raise
    monkeypatch.setattr(
        mod,
        "import_rsa_public_key_negotiated",
        lambda *_a, **_kw: (_ for _ in ()).throw(_ATTR_INVALID),
    )

    # Minimal vec (only the keys read before import is called)
    vec = {
        "tcId": 1,
        "msg": "deadbeef",
        "sig": "cafebabe",
        "result": "valid",
        "_group": {
            "publicKey": {
                "modulus": "00" + "aa" * 256,  # 2048-bit
                "publicExponent": "010001",
            },
        },
    }

    with pytest.raises(pytest.xfail.Exception, match="advertised but not operational"):
        _call_test_rsa_sig_2048_sha256(mod, rs, vec)


def test_a4_rsa_import_propagates_non_ckr(monkeypatch: pytest.MonkeyPatch) -> None:
    """A4 negative pin: non-CKR AssertionError propagates (harness bug path)."""
    import pkcs11_check.testcases.wycheproof.test_wycheproof as mod

    rs = _FakeRs(has=True)

    monkeypatch.setattr(
        mod,
        "import_rsa_public_key_negotiated",
        lambda *_a, **_kw: (_ for _ in ()).throw(_NON_CKR),
    )

    vec = {
        "tcId": 1,
        "msg": "deadbeef",
        "sig": "cafebabe",
        "result": "valid",
        "_group": {
            "publicKey": {
                "modulus": "00" + "aa" * 256,
                "publicExponent": "010001",
            },
        },
    }

    with pytest.raises(AssertionError, match="verify returned False"):
        _call_test_rsa_sig_2048_sha256(mod, rs, vec)


def _call_test_rsa_sig_2048_sha256(mod: object, rs: _FakeRs, vec: dict) -> None:  # type: ignore[type-arg]
    """Drive the A4 test body by instantiating TestRSASigWycheproof."""
    test_obj = mod.TestRSASigWycheproof()  # type: ignore[attr-defined]
    test_obj.test_rsa_sig_2048_sha256(rs, vec)


# ---------------------------------------------------------------------------
# A6a: wycheproof/test_wycheproof_aes.py AES_KEY_WRAP unwrap key import (:245)
# ---------------------------------------------------------------------------


def test_a6a_aes_kw_unwrap_key_import_xfails_on_ckr(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A6a: CkrAssertionError from negotiated AES unwrapping key import -> xfail."""
    import pkcs11_check.testcases.wycheproof.test_wycheproof_aes as mod

    monkeypatch.setattr(
        mod,
        "import_secret_key_negotiated",
        lambda *_a, **_kw: (_ for _ in ()).throw(_ATTR_INVALID),
    )

    rs = _FakeRs(has=True)
    vec = {
        "tcId": 1,
        "key": "00" * 16,
        "msg": "00" * 16,
        "ct": "00" * 24,
        "result": "valid",
    }

    with pytest.raises(pytest.xfail.Exception, match="advertised but not operational"):
        mod.test_aes_key_wrap(rs, "tc1-valid", vec)  # type: ignore[attr-defined]


def test_a6a_aes_kw_non_ckr_propagates(monkeypatch: pytest.MonkeyPatch) -> None:
    """A6a negative pin: non-CKR AssertionError from secret key import propagates."""
    import pkcs11_check.testcases.wycheproof.test_wycheproof_aes as mod

    monkeypatch.setattr(
        mod,
        "import_secret_key_negotiated",
        lambda *_a, **_kw: (_ for _ in ()).throw(_NON_CKR),
    )

    rs = _FakeRs(has=True)
    vec = {
        "tcId": 1,
        "key": "00" * 16,
        "msg": "00" * 16,
        "ct": "00" * 24,
        "result": "valid",
    }

    with pytest.raises(AssertionError, match="verify returned False"):
        mod.test_aes_key_wrap(rs, "tc1-valid", vec)  # type: ignore[attr-defined]


# ---------------------------------------------------------------------------
# A6b: wycheproof/test_wycheproof_aes.py AES_KEY_WRAP_KWP wrapping key import (:336)
# ---------------------------------------------------------------------------


def test_a6b_aes_kwp_wrap_key_import_xfails_on_ckr(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A6b: CkrAssertionError from negotiated AES KWP wrapping key import -> xfail."""
    import pkcs11_check.testcases.wycheproof.test_wycheproof_aes as mod

    monkeypatch.setattr(
        mod,
        "import_secret_key_negotiated",
        lambda *_a, **_kw: (_ for _ in ()).throw(_TEMPLATE_INCONS),
    )

    rs = _FakeRs(has=True)
    vec = {
        "tcId": 2,
        "key": "00" * 16,
        "msg": "00" * 16,
        "ct": "00" * 24,
        "result": "valid",
    }

    with pytest.raises(pytest.xfail.Exception, match="advertised but not operational"):
        mod.test_aes_kwp(rs, "tc2-valid", vec)  # type: ignore[attr-defined]


# ---------------------------------------------------------------------------
# A6c: wycheproof/test_wycheproof_aes.py AES-XTS key import (:570)
# ---------------------------------------------------------------------------


def test_a6c_aes_xts_key_import_xfails_on_ckr(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A6c: CkrAssertionError from negotiated AES-XTS key import -> xfail."""
    import pkcs11_check.testcases.wycheproof.test_wycheproof_aes as mod

    monkeypatch.setattr(
        mod,
        "import_secret_key_negotiated",
        lambda *_a, **_kw: (_ for _ in ()).throw(_FUNC_FAILED),
    )

    rs = _FakeRs(has=True)
    vec = {
        "tcId": 3,
        "key": "00" * 32,
        "iv": "00" * 16,
        "msg": "00" * 16,
        "ct": "00" * 16,
        "result": "valid",
    }

    with pytest.raises(pytest.xfail.Exception, match="advertised but not operational"):
        mod.test_aes_xts(rs, "tc3-valid", vec)  # type: ignore[attr-defined]


def test_a6c_aes_xts_invalid_vector_non_ckr_skips_not_xfails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A6c: for 'invalid' vectors, import failure on a non-CKR (AttributeError) is vacuous.

    When the key cannot be imported, the invalid input was never evaluated -> return (vacuous).
    """
    import pkcs11_check.testcases.wycheproof.test_wycheproof_aes as mod

    monkeypatch.setattr(
        mod,
        "import_secret_key_negotiated",
        lambda *_a, **_kw: (_ for _ in ()).throw(AttributeError("CKK_AES_XTS not defined")),
    )

    rs = _FakeRs(has=True)
    vec = {
        "tcId": 4,
        "key": "00" * 32,
        "iv": "00" * 16,
        "msg": "00" * 16,
        "ct": "00" * 16,
        "result": "invalid",
    }

    # For "invalid" vectors: when the key can't even be imported, the test returns
    # (vacuous -- the invalid input was never evaluated).  No exception expected.
    mod.test_aes_xts(rs, "tc4-invalid", vec)  # type: ignore[attr-defined]
