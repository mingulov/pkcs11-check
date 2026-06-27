"""TDD meta-tests for Batch 4 import-skip -> xfail conversion (HKDF IKM + ChaCha key).

Audit reference: import-skip-audit §4 "Batch 4" + rows A16 (SLH-DSA --
already DONE via D3/9a040f98), A17 (DSA -- DEFERRED, no provider hits the leak),
A18 (HKDF IKM secret-key import), A19 (ChaCha20 key import).

Batch 4 moves the two remaining *secret-key* raw ``create_object`` import sites
onto the existing ``import_secret_key_negotiated`` importer and then converts the
setup-stage import-reject ``pytest.skip`` to
``pytest.xfail(not_operational_reason(...))`` -- because once ``has_mechanism``
has passed (the mechanism is ADVERTISED) and negotiation has exhausted every
storage shape, a clean import-failure CKR is "advertised but not operational",
never genuine capability absence. The imported key IS the subject key of the
advertised operation (the HKDF IKM is derived FROM; the ChaCha key decrypts).

Each converted site asserts (mirroring batch1/batch2/batch3a/e0340c2d):
  (a) a broad CKR from the negotiated importer -> XFailed "advertised but not
      operational" -- with a hard-pin skip-guard (an unexpected Skipped escaping
      instead of an xfail is converted to ``pytest.fail``);
  (b) a non-CKR AssertionError propagates (harness/coding-bug path preserved);
  (c) gate not advertised (``has_mechanism`` False) -> Skipped (above the import).

Plus an integration test where the negotiation is REAL: only the C-level
``create_object`` recipe is patched to refuse ALL storage shapes, so
``negotiate_request`` genuinely walks and exhausts every variant -- proving the
xfail means "negotiation exhausted", not "first attempt failed".
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import CKR_ATTRIBUTE_VALUE_INVALID, CKR_TEMPLATE_INCONSISTENT
from pkcs11_check.testcases import conftest as tc

# Pre-import at collection time so _ALL_HKDF_VECTORS / _CHACHA_VECTORS are
# cached under a clean environment.  This mirrors the chacha-guards pattern
# (tests/test_wycheproof_chacha_guards.py:16) and makes the tests robust
# against any future ordering-induced WYCHEPROOF_DIR pollution.
from pkcs11_check.testcases.wycheproof import test_wycheproof_chacha as _chacha_mod  # noqa: F401
from pkcs11_check.testcases.wycheproof import test_wycheproof_hkdf as _hkdf_mod  # noqa: F401

_ATTR_INVALID = CkrAssertionError(
    "Unexpected CK_RV CKR_ATTRIBUTE_VALUE_INVALID", int(CKR_ATTRIBUTE_VALUE_INVALID)
)
_TEMPLATE_INCONS = CkrAssertionError(
    "Unexpected CK_RV CKR_TEMPLATE_INCONSISTENT", int(CKR_TEMPLATE_INCONSISTENT)
)
# A non-CKR AssertionError (no .rv) -- a harness/ctypes/coding bug, must propagate.
_NON_CKR = AssertionError("harness bug: ctypes packing error")


def _raiser(exc: BaseException) -> Any:
    def _raise(*_a: Any, **_kw: Any) -> Any:
        raise exc

    return _raise


def _session(*, has_mech: bool = True) -> Any:
    return SimpleNamespace(raw=object(), sh=1, has_mechanism=lambda _name: has_mech)


@pytest.fixture(autouse=True)
def _fresh_caches() -> None:
    tc.reset_import_negotiation_cache()


# ===========================================================================
# A18 -- test_wycheproof_hkdf.py IKM generic-secret import
# ===========================================================================


def _first_valid_hkdf_vector(hk: Any) -> tuple[str, dict[str, Any]]:
    for vid, v in hk._ALL_HKDF_VECTORS:
        if v["result"] == "valid" and v["_sha"] in hk._SHA_HASH_MECHS:
            return vid, v
    pytest.skip("no usable HKDF vector")


def test_a18_hkdf_import_site_xfails_on_broad_ckr(monkeypatch: pytest.MonkeyPatch) -> None:
    """A18: the real test_hkdf xfails when the negotiated IKM import is rejected.

    Hard-pin: an unexpected skip escaping instead of an xfail is a regression.
    """
    from pkcs11_check.testcases.wycheproof import test_wycheproof_hkdf as hk

    vec_id, vec = _first_valid_hkdf_vector(hk)
    monkeypatch.setattr(hk, "import_secret_key_negotiated", _raiser(_ATTR_INVALID))
    monkeypatch.setattr(
        hk.pytest, "skip", lambda message: pytest.fail(f"unexpected skip: {message}")
    )

    with pytest.raises(pytest.xfail.Exception, match="HKDF_DERIVE:key-import"):
        hk.test_hkdf(_session(), vec_id, vec)


def test_a18_hkdf_import_site_propagates_non_ckr(monkeypatch: pytest.MonkeyPatch) -> None:
    """A18 negative pin: a non-CKR AssertionError from the negotiated importer propagates."""
    from pkcs11_check.testcases.wycheproof import test_wycheproof_hkdf as hk

    vec_id, vec = _first_valid_hkdf_vector(hk)
    monkeypatch.setattr(hk, "import_secret_key_negotiated", _raiser(_NON_CKR))

    with pytest.raises(AssertionError, match="harness bug"):
        hk.test_hkdf(_session(), vec_id, vec)


def test_a18_hkdf_gate_not_advertised_skips(monkeypatch: pytest.MonkeyPatch) -> None:
    """A18: when HKDF_DERIVE is NOT advertised, the test skips above the import."""
    from pkcs11_check.testcases.wycheproof import test_wycheproof_hkdf as hk

    vec_id, vec = _first_valid_hkdf_vector(hk)
    # Importer must never be reached when the gate skip fires.
    monkeypatch.setattr(hk, "import_secret_key_negotiated", _raiser(_ATTR_INVALID))

    with pytest.raises(pytest.skip.Exception, match="HKDF_DERIVE not supported"):
        hk.test_hkdf(_session(has_mech=False), vec_id, vec)


# ===========================================================================
# A19 -- test_wycheproof_chacha.py ChaCha20 key import
# ===========================================================================


def _first_valid_chacha_vector(ch: Any) -> tuple[str, dict[str, Any]]:
    for vid, v in ch._CHACHA_VECTORS:
        if v["result"] == "valid":
            return vid, v
    pytest.skip("no usable ChaCha vector")


def test_a19_chacha_import_site_xfails_on_broad_ckr(monkeypatch: pytest.MonkeyPatch) -> None:
    """A19: the real test_chacha20_poly1305 xfails when the negotiated import is rejected.

    Hard-pin: an unexpected skip escaping instead of an xfail is a regression.
    """
    from pkcs11_check.testcases.wycheproof import test_wycheproof_chacha as ch

    vec_id, vec = _first_valid_chacha_vector(ch)
    monkeypatch.setattr(ch, "import_secret_key_negotiated", _raiser(_TEMPLATE_INCONS))
    monkeypatch.setattr(
        ch.pytest, "skip", lambda message: pytest.fail(f"unexpected skip: {message}")
    )

    with pytest.raises(pytest.xfail.Exception, match="CHACHA20_POLY1305:key-import"):
        ch.test_chacha20_poly1305(_session(), vec_id, vec)


def test_a19_chacha_import_site_propagates_non_ckr(monkeypatch: pytest.MonkeyPatch) -> None:
    """A19 negative pin: a non-CKR AssertionError from the negotiated importer propagates."""
    from pkcs11_check.testcases.wycheproof import test_wycheproof_chacha as ch

    vec_id, vec = _first_valid_chacha_vector(ch)
    monkeypatch.setattr(ch, "import_secret_key_negotiated", _raiser(_NON_CKR))

    with pytest.raises(AssertionError, match="harness bug"):
        ch.test_chacha20_poly1305(_session(), vec_id, vec)


def test_a19_chacha_gate_not_advertised_skips(monkeypatch: pytest.MonkeyPatch) -> None:
    """A19: when CHACHA20_POLY1305 is NOT advertised, the test skips above the import."""
    from pkcs11_check.testcases.wycheproof import test_wycheproof_chacha as ch

    vec_id, vec = _first_valid_chacha_vector(ch)
    monkeypatch.setattr(ch, "import_secret_key_negotiated", _raiser(_ATTR_INVALID))

    with pytest.raises(pytest.skip.Exception, match="CHACHA20_POLY1305 not supported"):
        ch.test_chacha20_poly1305(_session(has_mech=False), vec_id, vec)


# ===========================================================================
# REAL negotiation exhaustion -- the xfail genuinely means "exhausted"
# ===========================================================================


def test_a18_negotiation_genuinely_exhausts_before_xfail(monkeypatch: pytest.MonkeyPatch) -> None:
    """A18 xfail means negotiation EXHAUSTED, not 'first attempt failed'.

    Patch ONLY the C-level create_object recipe (not the negotiated importer) to
    refuse EVERY storage shape with CKR_ATTRIBUTE_VALUE_INVALID -- a code in
    IMPORT_STORAGE_SHAPE_REJECTS, so negotiate_request retries every variant and
    then re-raises after exhaustion. The HKDF test must then xfail
    'advertised but not operational'. We count the create_object calls to prove
    more than one storage variant was actually attempted.
    """
    from pkcs11_check.testcases.wycheproof import test_wycheproof_hkdf as hk

    calls: list[dict[Any, Any]] = []

    def _refuse_all_shapes(_raw: Any, _sh: int, attrs: dict[Any, Any]) -> int:
        calls.append(dict(attrs))
        raise CkrAssertionError(
            "Unexpected CK_RV CKR_ATTRIBUTE_VALUE_INVALID", int(CKR_ATTRIBUTE_VALUE_INVALID)
        )

    # Select the vector BEFORE patching pytest.skip: monkeypatch mutates the
    # shared global pytest.skip, and the selector legitimately skips when the
    # wycheproof corpus is absent -- that genuine skip must not be converted to
    # a failure.
    vec_id, vec = _first_valid_hkdf_vector(hk)

    monkeypatch.setattr("pkcs11_check.raw.recipes.create_object", _refuse_all_shapes)
    monkeypatch.setattr(
        hk.pytest, "skip", lambda message: pytest.fail(f"unexpected skip: {message}")
    )

    with pytest.raises(pytest.xfail.Exception, match="HKDF_DERIVE:key-import"):
        hk.test_hkdf(_session(), vec_id, vec)

    assert len(calls) >= 2, f"expected >=2 storage-shape attempts, got {len(calls)}: {calls}"
