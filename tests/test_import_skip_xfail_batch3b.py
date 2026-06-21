"""TDD meta-tests for Batch 3b import-skip -> xfail conversion (EC sites).

Audit doc: docs/findings/import-skip-audit.md §4 "Batch 3" + rows A13, A15, and
the A9 EC-private leg.  RSA sites (A9 RSA legs, A10-A12) were Batch 3a; the
EC/Montgomery *private* derive sites (D2) were a separate determination.

Batch 3b moves the EC *public*-key raw importers onto the existing negotiated
importer (``import_ec_public_key_negotiated``) and then converts the setup-stage
broad import-reject ``pytest.skip`` to ``pytest.xfail(not_operational_reason(...))``
-- because once ``has_mechanism`` has passed (ECDSA / ECDSA_SHA256 is ADVERTISED)
and negotiation has exhausted every storage shape, a broad import-failure CKR is
"advertised but not operational", never genuine capability absence.

Each site SPLITS the reject (mirroring Batch 2):

* a genuine-capability-absence branch keyed on CKR_CURVE_NOT_SUPPORTED /
  CKR_DOMAIN_PARAMS_INVALID -- the specific curve is absent -> stays a ``skip``;
* a broad import-failure branch (CKR_ATTRIBUTE_VALUE_INVALID, ...) -> ``xfail``.

Sites:

* A13 -- wycheproof/test_wycheproof.py ``test_ecdsa_p256_sha256_verify`` /
  ``test_ecdsa_p384_sha384_verify`` (negotiated EC public import);
* A15 -- test_cctv_rfc6979.py public-key site (negotiated) + private-key site
  (raw single-template ``import_ec_private_key`` -- no negotiated EC-private
  importer; the canonical raw import IS the spec path, D2, b56c3f8c);
* A9 EC-private leg -- test_mech_sign.py ``_run_asymmetric_sign_kat`` EC branch
  (raw ``import_ec_private_key`` -> ``_xfail_ec_kat_import_not_operational``).

Each converted site asserts (mirroring batch3a / e0340c2d):
  (a) a broad CKR -> XFailed "advertised but not operational", with a hard-pin
      skip-guard (an unexpected Skipped escaping is converted to pytest.fail);
  (b) a curve-absence CKR -> still Skipped (the split is preserved);
  (c) a non-CKR AssertionError propagates (harness/coding-bug path preserved).

Plus an integration test for an A13 site where the negotiation is REAL: only the
C-level ``create_object`` recipe is patched to refuse ALL storage shapes, so
``negotiate_request`` genuinely walks and exhausts every variant -- proving the
xfail means "negotiation exhausted", not "first attempt failed".
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
    CKR_KEY_SIZE_RANGE,
    CKR_TEMPLATE_INCONSISTENT,
)
from pkcs11_check.testcases import conftest as tc
from pkcs11_check.testcases.mechanism_catalog import MechEntry
from pkcs11_check.testcases.mechanism_registry import KeygenRecipe, MechConfig, ParamRecipe

# ---------------------------------------------------------------------------
# Shared CKR fixtures
# ---------------------------------------------------------------------------

_ATTR_INVALID = CkrAssertionError(
    "Unexpected CK_RV CKR_ATTRIBUTE_VALUE_INVALID", int(CKR_ATTRIBUTE_VALUE_INVALID)
)
_KEY_SIZE_RANGE = CkrAssertionError("Unexpected CK_RV CKR_KEY_SIZE_RANGE", int(CKR_KEY_SIZE_RANGE))
_TEMPLATE_INCONS = CkrAssertionError(
    "Unexpected CK_RV CKR_TEMPLATE_INCONSISTENT", int(CKR_TEMPLATE_INCONSISTENT)
)
_CURVE_NOT_SUPPORTED = CkrAssertionError(
    "Unexpected CK_RV CKR_CURVE_NOT_SUPPORTED", int(CKR_CURVE_NOT_SUPPORTED)
)
_DOMAIN_PARAMS_INVALID = CkrAssertionError(
    "Unexpected CK_RV CKR_DOMAIN_PARAMS_INVALID", int(CKR_DOMAIN_PARAMS_INVALID)
)
# A non-CKR AssertionError (no .rv) -- a harness/ctypes/coding bug, must propagate.
_NON_CKR = AssertionError("KAT sign mismatch: got deadbeef, expected cafebabe")


def _raiser(exc: BaseException) -> Any:
    def _raise(*_a: Any, **_kw: Any) -> Any:
        raise exc

    return _raise


def _session() -> Any:
    return SimpleNamespace(raw=object(), sh=1, has_mechanism=lambda _name: True)


@pytest.fixture(autouse=True)
def _fresh_caches() -> None:
    tc.reset_import_negotiation_cache()


# ===========================================================================
# A13 -- wycheproof/test_wycheproof.py EC public import (negotiated, split)
# ===========================================================================


def test_a13_classify_helper_xfails_on_broad_ckr() -> None:
    """A13: a broad import CKR -> xfail 'advertised but not operational', not skip.

    Hard-pin: an unexpected skip escaping instead of an xfail is a regression.
    """
    from pkcs11_check.testcases.wycheproof import test_wycheproof as wy

    try:
        with pytest.raises(pytest.xfail.Exception, match="advertised but not operational"):
            wy._classify_ec_public_import_reject(_ATTR_INVALID, "secp256r1")
    except pytest.skip.Exception as exc:
        pytest.fail(f"skipped instead of xfailing: {exc}")


def test_a13_classify_helper_xfail_carries_probe_key() -> None:
    """A13: the xfail wording is the shared ECDSA:key-import probe key + curve + CKR."""
    from pkcs11_check.testcases.wycheproof import test_wycheproof as wy

    with pytest.raises(pytest.xfail.Exception, match="ECDSA:key-import"):
        wy._classify_ec_public_import_reject(_TEMPLATE_INCONS, "secp384r1")


def test_a13_classify_helper_curve_unsupported_skips() -> None:
    """A13: a curve-absence CKR keeps the genuine-absence skip (split preserved)."""
    from pkcs11_check.testcases.wycheproof import test_wycheproof as wy

    with pytest.raises(pytest.skip.Exception, match="Cannot import EC public key on this module"):
        wy._classify_ec_public_import_reject(_CURVE_NOT_SUPPORTED, "secp256r1")


def test_a13_classify_helper_domain_params_skips() -> None:
    """A13: CKR_DOMAIN_PARAMS_INVALID also keeps the genuine-absence skip."""
    from pkcs11_check.testcases.wycheproof import test_wycheproof as wy

    with pytest.raises(pytest.skip.Exception, match="Cannot import EC public key on this module"):
        wy._classify_ec_public_import_reject(_DOMAIN_PARAMS_INVALID, "secp384r1")


def test_a13_classify_helper_propagates_non_ckr() -> None:
    """A13 negative pin: a non-CKR AssertionError must not be xfailed or skipped."""
    from pkcs11_check.testcases.wycheproof import test_wycheproof as wy

    with pytest.raises(AssertionError, match="KAT sign mismatch"):
        wy._classify_ec_public_import_reject(_NON_CKR, "secp256r1")


def _first_valid_ecdsa_p256_vec(wy: Any) -> dict[str, Any]:
    for vec in wy._load_ecdsa_p256_vectors():
        if vec["result"] == "valid" and vec["_group"].get("publicKey", {}).get("uncompressed"):
            return vec
    pytest.skip("no usable ECDSA P-256 vector")


def test_a13_p256_real_function_xfails_on_broad_ckr(monkeypatch: pytest.MonkeyPatch) -> None:
    """A13: the real test_ecdsa_p256_sha256_verify xfails when the negotiated import is rejected."""
    from pkcs11_check.testcases.wycheproof import test_wycheproof as wy

    monkeypatch.setattr(wy, "import_ec_public_key_negotiated", _raiser(_KEY_SIZE_RANGE))
    monkeypatch.setattr(
        wy.pytest, "skip", lambda message: pytest.fail(f"unexpected skip: {message}")
    )

    vec = _first_valid_ecdsa_p256_vec(wy)
    try:
        with pytest.raises(pytest.xfail.Exception, match="ECDSA:key-import"):
            wy.TestECDSAP256Wycheproof().test_ecdsa_p256_sha256_verify(_session(), vec)
    except pytest.skip.Exception as exc:
        pytest.fail(f"skipped instead of xfailing: {exc}")


def test_a13_p256_curve_unsupported_real_function_skips(monkeypatch: pytest.MonkeyPatch) -> None:
    """A13: the real test still SKIPS on a genuine curve-absence CKR (split preserved)."""
    from pkcs11_check.testcases.wycheproof import test_wycheproof as wy

    monkeypatch.setattr(wy, "import_ec_public_key_negotiated", _raiser(_DOMAIN_PARAMS_INVALID))

    vec = _first_valid_ecdsa_p256_vec(wy)
    with pytest.raises(pytest.skip.Exception, match="Cannot import EC public key on this module"):
        wy.TestECDSAP256Wycheproof().test_ecdsa_p256_sha256_verify(_session(), vec)


def test_a13_negotiation_genuinely_exhausts_before_xfail(monkeypatch: pytest.MonkeyPatch) -> None:
    """A13: the xfail means negotiation EXHAUSTED, not 'first attempt failed'.

    Patch ONLY the C-level create_object recipe (not the negotiated importer) to
    refuse EVERY storage shape with CKR_ATTRIBUTE_VALUE_INVALID -- a code in
    IMPORT_STORAGE_SHAPE_REJECTS, so negotiate_request retries every variant and
    then re-raises after exhaustion. The P-256 verify test must then xfail
    'advertised but not operational'. We count the create_object calls to prove
    more than one storage variant was actually attempted.
    """
    from pkcs11_check.testcases.wycheproof import test_wycheproof as wy

    calls: list[dict[Any, Any]] = []

    def _refuse_all_shapes(_raw: Any, _sh: int, attrs: dict[Any, Any]) -> int:
        calls.append(dict(attrs))
        raise CkrAssertionError(
            "Unexpected CK_RV CKR_ATTRIBUTE_VALUE_INVALID", int(CKR_ATTRIBUTE_VALUE_INVALID)
        )

    monkeypatch.setattr("pkcs11_check.raw.recipes.create_object", _refuse_all_shapes)
    monkeypatch.setattr(
        wy.pytest, "skip", lambda message: pytest.fail(f"unexpected skip: {message}")
    )

    vec = _first_valid_ecdsa_p256_vec(wy)
    try:
        with pytest.raises(pytest.xfail.Exception, match="ECDSA:key-import"):
            wy.TestECDSAP256Wycheproof().test_ecdsa_p256_sha256_verify(_session(), vec)
    finally:
        tc.reset_import_negotiation_cache()

    # Negotiation REALLY walked the storage variants (canonical + at least one
    # retry) before exhausting -- not a single-shot failure.
    assert len(calls) >= 2, f"expected >=2 storage-shape attempts, got {len(calls)}: {calls}"


# ===========================================================================
# A15 -- test_cctv_rfc6979.py EC import (public negotiated + private raw, split)
# ===========================================================================


def test_a15_helper_xfails_on_broad_ckr() -> None:
    """A15: a broad import CKR -> xfail 'advertised but not operational', not skip.

    Hard-pin: an unexpected skip escaping instead of an xfail is a regression.
    """
    from pkcs11_check.testcases import test_cctv_rfc6979 as cctv

    try:
        with pytest.raises(pytest.xfail.Exception, match="advertised but not operational"):
            cctv._skip_or_xfail_cctv_ec_import_reject(_ATTR_INVALID, "P-256 public-key")
    except pytest.skip.Exception as exc:
        pytest.fail(f"skipped instead of xfailing: {exc}")


def test_a15_helper_xfail_carries_probe_key() -> None:
    """A15: the xfail wording is the shared ECDSA_SHA256:key-import probe key."""
    from pkcs11_check.testcases import test_cctv_rfc6979 as cctv

    with pytest.raises(pytest.xfail.Exception, match="ECDSA_SHA256:key-import"):
        cctv._skip_or_xfail_cctv_ec_import_reject(_KEY_SIZE_RANGE, "P-256 private-key")


def test_a15_helper_curve_unsupported_skips() -> None:
    """A15: a curve-absence CKR keeps the genuine-absence skip (split preserved)."""
    from pkcs11_check.testcases import test_cctv_rfc6979 as cctv

    with pytest.raises(pytest.skip.Exception, match="Cannot import P-256 public-key"):
        cctv._skip_or_xfail_cctv_ec_import_reject(_CURVE_NOT_SUPPORTED, "P-256 public-key")


def test_a15_helper_domain_params_skips() -> None:
    """A15: CKR_DOMAIN_PARAMS_INVALID also keeps the genuine-absence skip."""
    from pkcs11_check.testcases import test_cctv_rfc6979 as cctv

    with pytest.raises(pytest.skip.Exception, match="Cannot import P-256 private-key"):
        cctv._skip_or_xfail_cctv_ec_import_reject(_DOMAIN_PARAMS_INVALID, "P-256 private-key")


def test_a15_helper_propagates_non_ckr(monkeypatch: pytest.MonkeyPatch) -> None:
    """A15 negative pin: a non-CKR AssertionError propagates.

    Driven through the real test function so the helper's terminal ``raise`` runs
    inside an active ``except`` block (the established convention).
    """
    from pkcs11_check.testcases import test_cctv_rfc6979 as cctv

    monkeypatch.setattr(cctv, "import_ec_public_key_negotiated", _raiser(_NON_CKR))

    with pytest.raises(AssertionError, match="KAT sign mismatch"):
        cctv.test_rfc6979_ecdsa_verify(_session())


def test_a15_public_site_xfails_real_function(monkeypatch: pytest.MonkeyPatch) -> None:
    """A15: the real test_rfc6979_ecdsa_verify xfails on a broad negotiated-import CKR."""
    from pkcs11_check.testcases import test_cctv_rfc6979 as cctv

    monkeypatch.setattr(cctv, "import_ec_public_key_negotiated", _raiser(_ATTR_INVALID))
    monkeypatch.setattr(
        cctv.pytest, "skip", lambda message: pytest.fail(f"unexpected skip: {message}")
    )

    try:
        with pytest.raises(pytest.xfail.Exception, match="ECDSA_SHA256:key-import"):
            cctv.test_rfc6979_ecdsa_verify(_session())
    except pytest.skip.Exception as exc:
        pytest.fail(f"skipped instead of xfailing: {exc}")


def test_a15_private_site_xfails_real_function(monkeypatch: pytest.MonkeyPatch) -> None:
    """A15: the private-key site xfails on a broad import CKR (provision_ec_private_key path)."""
    from pkcs11_check.testcases import test_cctv_rfc6979 as cctv

    monkeypatch.setattr(cctv, "provision_ec_private_key", _raiser(_ATTR_INVALID))
    monkeypatch.setattr(
        cctv.pytest, "skip", lambda message: pytest.fail(f"unexpected skip: {message}")
    )

    try:
        with pytest.raises(pytest.xfail.Exception, match="ECDSA_SHA256:key-import"):
            cctv.test_rfc6979_ecdsa_sign_deterministic(_session(), None)
    except pytest.skip.Exception as exc:
        pytest.fail(f"skipped instead of xfailing: {exc}")


# ===========================================================================
# A9 EC-private leg -- test_mech_sign.py _run_asymmetric_sign_kat EC branch
# ===========================================================================


def _kat_ec_entry() -> MechEntry:
    from pkcs11_check.raw.types_std import CKM_ECDSA_SHA256

    return MechEntry(
        mech_id=int(CKM_ECDSA_SHA256),
        mech_name="ECDSA_SHA256",
        flags=0,
        min_key_size=0,
        max_key_size=0,
        config=MechConfig(
            is_keypair=True,
            keygen_recipe=KeygenRecipe("ec"),
            param_recipe=ParamRecipe("none"),
            vector_file="dummy.json",
        ),
    )


def test_a9ec_helper_xfails_on_broad_ckr() -> None:
    """A9 EC: the EC KAT import helper xfails 'advertised but not operational'.

    Hard-pin: an unexpected skip escaping instead of an xfail is a regression.
    """
    from pkcs11_check.testcases import test_mech_sign as tms

    try:
        with pytest.raises(pytest.xfail.Exception, match="advertised but not operational"):
            tms._xfail_ec_kat_import_not_operational(
                _ATTR_INVALID, _kat_ec_entry(), "EC private key"
            )
    except pytest.skip.Exception as exc:
        pytest.fail(f"skipped instead of xfailing: {exc}")


def test_a9ec_helper_xfail_carries_probe_key() -> None:
    """A9 EC: the xfail wording is the shared {mech}:key-import probe key."""
    from pkcs11_check.testcases import test_mech_sign as tms

    with pytest.raises(pytest.xfail.Exception, match="ECDSA_SHA256:key-import"):
        tms._xfail_ec_kat_import_not_operational(
            _TEMPLATE_INCONS, _kat_ec_entry(), "EC private key"
        )


def test_a9ec_helper_curve_unsupported_skips() -> None:
    """A9 EC: a curve-absence CKR keeps the genuine-absence skip (split preserved)."""
    from pkcs11_check.testcases import test_mech_sign as tms

    with pytest.raises(pytest.skip.Exception, match="cannot import EC private key"):
        tms._xfail_ec_kat_import_not_operational(
            _CURVE_NOT_SUPPORTED, _kat_ec_entry(), "EC private key"
        )


def test_a9ec_helper_domain_params_skips() -> None:
    """A9 EC: CKR_DOMAIN_PARAMS_INVALID also keeps the genuine-absence skip."""
    from pkcs11_check.testcases import test_mech_sign as tms

    with pytest.raises(pytest.skip.Exception, match="cannot import EC private key"):
        tms._xfail_ec_kat_import_not_operational(
            _DOMAIN_PARAMS_INVALID, _kat_ec_entry(), "EC private key"
        )


def test_a9ec_helper_propagates_non_ckr() -> None:
    """A9 EC negative pin: a non-CKR AssertionError must not be xfailed or skipped."""
    from pkcs11_check.testcases import test_mech_sign as tms

    with pytest.raises(AssertionError, match="KAT sign mismatch"):
        tms._xfail_ec_kat_import_not_operational(_NON_CKR, _kat_ec_entry(), "EC private key")


def test_a9ec_helper_removed_old_skip_helper() -> None:
    """A9 EC: the old skip-only helper was removed (no remaining users after the split)."""
    from pkcs11_check.testcases import test_mech_sign as tms

    assert not hasattr(tms, "_skip_kat_import_capability_reject")
