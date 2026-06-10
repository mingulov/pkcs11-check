"""TDD meta-tests for Batch 3a import-skip -> xfail conversion (RSA family).

Audit doc: docs/findings/import-skip-audit.md §4 "Batch 3" + rows A9 (RSA legs),
A10, A11.  EC sites (A13-A15) and the A9 EC private leg are Batch 3b -- NOT here.

Batch 3a moves the RSA-family *raw* importers onto the existing negotiated
importers (``import_rsa_private_key_negotiated`` / ``import_rsa_public_key_negotiated``)
and then converts the setup-stage broad import-reject ``pytest.skip`` to
``pytest.xfail(not_operational_reason(...))`` -- because once ``has_mechanism``
has passed (the mechanism is ADVERTISED) and negotiation has exhausted every
storage shape, a broad import-failure CKR is "advertised but not operational",
never genuine capability absence.

Each converted site asserts (mirroring batch1/batch2/e0340c2d):
  (a) a broad CKR from the negotiated importer -> XFailed "advertised but not
      operational" -- with a hard-pin skip-guard (an unexpected Skipped escaping
      instead of an xfail is converted to ``pytest.fail``);
  (b) a non-CKR AssertionError propagates (harness/coding-bug path preserved).

Plus an integration test where the negotiation is REAL: only the C-level
``create_object`` recipe is patched to refuse ALL storage shapes, so
``negotiate_request`` genuinely walks and exhausts every variant -- proving the
xfail means "negotiation exhausted", not "first attempt failed".

A9 helper-split: ``_skip_kat_import_capability_reject`` (EC residual) keeps the
skip; the RSA legs route through ``_xfail_rsa_kat_import_not_operational`` (xfail).
The EC private import has no negotiated importer (D2, commit b56c3f8c) and stays
on the skip path for Batch 3b -- pinned here so the split cannot silently regress.
"""

from __future__ import annotations

from typing import Any

import pytest

from pkcs11_check.raw.rv import CkrAssertionError
from pkcs11_check.raw.types_std import (
    CKR_ATTRIBUTE_VALUE_INVALID,
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
# A non-CKR AssertionError (no .rv) -- a harness/ctypes/coding bug, must propagate.
_NON_CKR = AssertionError("KAT sign mismatch: got deadbeef, expected cafebabe")


def _raiser(exc: BaseException) -> Any:
    def _raise(*_a: Any, **_kw: Any) -> Any:
        raise exc

    return _raise


@pytest.fixture(autouse=True)
def _fresh_caches() -> None:
    tc.reset_import_negotiation_cache()


# ===========================================================================
# A9 -- test_mech_sign.py KAT RSA private + RSA public import (helper split)
# ===========================================================================


def _kat_rsa_entry() -> MechEntry:
    from pkcs11_check.raw.types_std import CKM_SHA256_RSA_PKCS

    return MechEntry(
        mech_id=int(CKM_SHA256_RSA_PKCS),
        mech_name="SHA256_RSA_PKCS",
        flags=0,
        min_key_size=0,
        max_key_size=0,
        config=MechConfig(
            is_keypair=True,
            keygen_recipe=KeygenRecipe("rsa"),
            param_recipe=ParamRecipe("none"),
            vector_file="dummy.json",
        ),
    )


def test_a9_rsa_kat_import_helper_xfails_on_broad_ckr() -> None:
    """A9 RSA: the RSA KAT import helper xfails 'advertised but not operational'.

    Hard-pin: an unexpected skip escaping instead of an xfail is a regression.
    """
    from pkcs11_check.testcases import test_mech_sign as tms

    try:
        with pytest.raises(pytest.xfail.Exception, match="advertised but not operational"):
            tms._xfail_rsa_kat_import_not_operational(
                _ATTR_INVALID, _kat_rsa_entry(), "RSA private key"
            )
    except pytest.skip.Exception as exc:
        pytest.fail(f"skipped instead of xfailing: {exc}")


def test_a9_rsa_kat_import_helper_propagates_non_ckr() -> None:
    """A9 RSA negative pin: a non-CKR AssertionError must not be xfailed or skipped."""
    from pkcs11_check.testcases import test_mech_sign as tms

    with pytest.raises(AssertionError, match="KAT sign mismatch"):
        tms._xfail_rsa_kat_import_not_operational(_NON_CKR, _kat_rsa_entry(), "RSA private key")


def test_a9_rsa_private_import_site_xfails_real_function(monkeypatch: pytest.MonkeyPatch) -> None:
    """A9 RSA: the real _run_asymmetric_sign_kat RSA branch xfails on a broad import CKR.

    Drives the production function (not just the helper) so the swap to
    import_rsa_private_key_negotiated + helper routing is exercised end-to-end.
    """
    from pkcs11_check.testcases import test_mech_sign as tms

    monkeypatch.setattr(tms, "import_rsa_private_key_negotiated", _raiser(_KEY_SIZE_RANGE))

    vec = {
        "n_hex": "aa" * 256,
        "e_hex": "010001",
        "d_hex": "bb" * 256,
        "p_hex": "cc" * 128,
        "q_hex": "dd" * 128,
        "dmp1_hex": "ee" * 128,
        "dmq1_hex": "ff" * 128,
        "iqmp_hex": "11" * 128,
        "input_hex": "22" * 32,
        "signature_hex": "33" * 256,
    }
    entry = _kat_rsa_entry()

    try:
        with pytest.raises(pytest.xfail.Exception, match="SHA256_RSA_PKCS:key-import"):
            tms._run_asymmetric_sign_kat(_session(), entry, entry.config, vec)
    except pytest.skip.Exception as exc:
        pytest.fail(f"skipped instead of xfailing: {exc}")


def test_a9_ec_private_import_keeps_skip_path() -> None:
    """A9 residual pin: the EC private KAT import still SKIPS (Batch 3b).

    There is no negotiated EC-private importer (D2, b56c3f8c); the EC leg keeps
    _skip_kat_import_capability_reject so the helper split cannot silently flip
    the EC site to xfail before Batch 3b wires it.
    """
    from pkcs11_check.testcases import test_mech_sign as tms

    with pytest.raises(pytest.skip.Exception, match="cannot import EC private key"):
        tms._skip_kat_import_capability_reject(_ATTR_INVALID, _ec_entry(), "EC private key")


def _ec_entry() -> MechEntry:
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


def _session() -> Any:
    from types import SimpleNamespace

    return SimpleNamespace(raw=object(), sh=1, has_mechanism=lambda _name: True)


# ===========================================================================
# A10 -- test_wycheproof_rsa_siggen.py RSA private import
# ===========================================================================


def test_a10_siggen_import_helper_xfails_on_broad_ckr() -> None:
    """A10: broad import reject -> xfail (advertised but not operational), not skip.

    Hard-pin: unexpected skip escaping -> hard fail.
    """
    from pkcs11_check.testcases.wycheproof import test_wycheproof_rsa_siggen as sg

    try:
        with pytest.raises(pytest.xfail.Exception, match="SHA256_RSA_PKCS:key-import"):
            sg._skip_or_xfail_rsa_private_import_reject(
                _ATTR_INVALID, 2048, "SHA-256", "SHA256_RSA_PKCS"
            )
    except pytest.skip.Exception as exc:
        pytest.fail(f"skipped instead of xfailing: {exc}")


def test_a10_siggen_import_helper_propagates_non_ckr(monkeypatch: pytest.MonkeyPatch) -> None:
    """A10 negative pin: a non-CKR AssertionError from the negotiated importer propagates.

    Driven through the real test function so the helper's terminal ``raise`` runs
    inside an active ``except`` block (the established convention -- mirrors
    test_wycheproof_rsa_siggen_runtime_classification).
    """
    from pkcs11_check.testcases.wycheproof import test_wycheproof_rsa_siggen as sg

    vec_id, vec = sg._ALL_SIGGEN_VECTORS[0]
    monkeypatch.setattr(sg, "import_rsa_private_key_negotiated", _raiser(_NON_CKR))

    with pytest.raises(AssertionError, match="KAT sign mismatch"):
        sg.test_rsa_pkcs1_siggen(_session(), vec_id, vec)


def test_a10_siggen_real_function_xfails_on_broad_ckr(monkeypatch: pytest.MonkeyPatch) -> None:
    """A10: the real test_rsa_pkcs1_siggen xfails when the negotiated import is rejected."""
    from pkcs11_check.testcases.wycheproof import test_wycheproof_rsa_siggen as sg

    vec_id, vec = sg._ALL_SIGGEN_VECTORS[0]
    monkeypatch.setattr(sg, "import_rsa_private_key_negotiated", _raiser(_ATTR_INVALID))
    monkeypatch.setattr(
        sg.pytest, "skip", lambda message: pytest.fail(f"unexpected skip: {message}")
    )

    with pytest.raises(pytest.xfail.Exception, match="advertised but not operational"):
        sg.test_rsa_pkcs1_siggen(_session(), vec_id, vec)


# ===========================================================================
# A11 -- test_wycheproof_rsa_oaep.py RSA private import (+ cached early-exit)
# ===========================================================================


def test_a11_oaep_import_helper_xfails_on_broad_ckr() -> None:
    """A11: broad import reject -> xfail (advertised but not operational), not skip.

    Hard-pin: unexpected skip escaping -> hard fail.
    """
    from pkcs11_check.testcases.wycheproof import test_wycheproof_rsa_oaep as oa

    oa._UNSUPPORTED_RSA_KEY_SIZES.clear()
    try:
        with pytest.raises(pytest.xfail.Exception, match="RSA_PKCS_OAEP:key-import"):
            oa._skip_or_xfail_rsa_oaep_private_import_reject(_TEMPLATE_INCONS, 2048)
    except pytest.skip.Exception as exc:
        pytest.fail(f"skipped instead of xfailing: {exc}")
    finally:
        oa._UNSUPPORTED_RSA_KEY_SIZES.clear()


def test_a11_oaep_import_helper_propagates_non_ckr(monkeypatch: pytest.MonkeyPatch) -> None:
    """A11 negative pin: a non-CKR AssertionError from the negotiated importer propagates.

    Driven through the real test function so the helper's terminal ``raise`` runs
    inside an active ``except`` block (mirrors the OAEP runtime-classification meta).
    """
    from pkcs11_check.testcases.wycheproof import test_wycheproof_rsa_oaep as oa

    oa._UNSUPPORTED_RSA_KEY_SIZES.clear()
    vec_id, vec = _first_valid_oaep_vector(oa)
    monkeypatch.setattr(oa, "import_rsa_private_key_negotiated", _raiser(_NON_CKR))

    try:
        with pytest.raises(AssertionError, match="KAT sign mismatch"):
            oa.test_rsa_oaep(_session(), vec_id, vec)
    finally:
        oa._UNSUPPORTED_RSA_KEY_SIZES.clear()


def test_a11_oaep_cached_keysize_early_exit_xfails(monkeypatch: pytest.MonkeyPatch) -> None:
    """A11: the cached unsupported-key-size early exit xfails (was skip).

    A broad import reject populates _UNSUPPORTED_RSA_KEY_SIZES; the next vector
    of that size short-circuits. That early-exit must carry the same
    advertised-but-not-operational xfail, not a capability skip.
    """
    from pkcs11_check.testcases.wycheproof import test_wycheproof_rsa_oaep as oa

    vec_id, vec = _first_valid_oaep_vector(oa)
    key_bits = len(bytes.fromhex(vec["_group"]["privateKey"]["modulus"].lstrip("0") or "00")) * 8
    # Seed the cache with whatever key size this vector reports.
    modulus = oa.pkcs11_bigint_from_hex(vec["_group"]["privateKey"]["modulus"])
    oa._UNSUPPORTED_RSA_KEY_SIZES.clear()
    oa._UNSUPPORTED_RSA_KEY_SIZES.add(len(modulus) * 8)
    monkeypatch.setattr(
        oa.pytest, "skip", lambda message: pytest.fail(f"unexpected skip: {message}")
    )

    try:
        with pytest.raises(pytest.xfail.Exception, match="not operational \\(cached\\)"):
            oa.test_rsa_oaep(_session(), vec_id, vec)
    finally:
        oa._UNSUPPORTED_RSA_KEY_SIZES.clear()
    del key_bits  # silence unused (documents the cache-key derivation)


def _first_valid_oaep_vector(oa: Any) -> tuple[str, dict[str, Any]]:
    for vid, v in oa._ALL_OAEP_VECTORS:
        pk = v["_group"].get("privateKey", {})
        if v["result"] == "valid" and pk.get("modulus") and pk.get("privateExponent"):
            sha = v["_sha"]
            mgf = v["_mgfSha"]
            # Need a vec the param mapping understands so it reaches the import.
            if sha in oa._SHA_HASH_MECHS and mgf in oa._SHA_MGFS:
                return vid, v
    pytest.skip("no usable OAEP vector")


# ===========================================================================
# REAL negotiation exhaustion -- the xfail genuinely means "exhausted"
# ===========================================================================


def test_negotiation_genuinely_exhausts_before_xfail(monkeypatch: pytest.MonkeyPatch) -> None:
    """The xfail means negotiation EXHAUSTED, not 'first attempt failed'.

    Patch ONLY the C-level create_object recipe (not the negotiated importer) to
    refuse EVERY storage shape with CKR_ATTRIBUTE_VALUE_INVALID -- a code in
    IMPORT_STORAGE_SHAPE_REJECTS, so negotiate_request retries every variant and
    then re-raises after exhaustion. The OAEP test must then xfail
    'advertised but not operational'. We count the create_object calls to prove
    more than one storage variant was actually attempted.
    """
    from pkcs11_check.testcases.wycheproof import test_wycheproof_rsa_oaep as oa

    calls: list[dict[Any, Any]] = []

    def _refuse_all_shapes(_raw: Any, _sh: int, attrs: dict[Any, Any]) -> int:
        calls.append(dict(attrs))
        raise CkrAssertionError(
            "Unexpected CK_RV CKR_ATTRIBUTE_VALUE_INVALID", int(CKR_ATTRIBUTE_VALUE_INVALID)
        )

    monkeypatch.setattr("pkcs11_check.raw.recipes.create_object", _refuse_all_shapes)
    monkeypatch.setattr(
        oa.pytest, "skip", lambda message: pytest.fail(f"unexpected skip: {message}")
    )

    vec_id, vec = _first_valid_oaep_vector(oa)
    oa._UNSUPPORTED_RSA_KEY_SIZES.clear()

    try:
        with pytest.raises(pytest.xfail.Exception, match="RSA_PKCS_OAEP:key-import"):
            oa.test_rsa_oaep(_session(), vec_id, vec)
    finally:
        oa._UNSUPPORTED_RSA_KEY_SIZES.clear()

    # Negotiation REALLY walked the storage variants (canonical + at least one
    # retry) before exhausting -- not a single-shot failure.
    assert len(calls) >= 2, f"expected >=2 storage-shape attempts, got {len(calls)}: {calls}"
