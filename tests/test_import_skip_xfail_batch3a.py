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

A9 helper-split: the RSA legs route through ``_xfail_rsa_kat_import_not_operational``
(xfail).  Batch 3b then converted the EC private leg -- it has no negotiated
importer (D2, commit b56c3f8c) so the raw single-template import IS the spec path;
the broad reject now xfails via ``_xfail_ec_kat_import_not_operational`` while
curve-absence keeps skip.  Reconciled here; the full EC split is pinned in
tests/test_import_skip_xfail_batch3b.py.
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
    provision_rsa_private_key + helper routing is exercised end-to-end.
    """
    from pkcs11_check.testcases import test_mech_sign as tms

    monkeypatch.setattr(tms, "provision_rsa_private_key", _raiser(_KEY_SIZE_RANGE))

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
            tms._run_asymmetric_sign_kat(_session(), entry, entry.config, vec, None)
    except pytest.skip.Exception as exc:
        pytest.fail(f"skipped instead of xfailing: {exc}")


def test_a9_ec_private_import_broad_reject_xfails_after_batch3b() -> None:
    """A9 EC leg (Batch 3b reconciliation): broad CKR -> xfail, not skip.

    Batch 3b removed ``_skip_kat_import_capability_reject`` and routed the EC
    private KAT import through ``_xfail_ec_kat_import_not_operational``: a broad
    import-failure CKR is now "advertised but not operational" -> xfail (the EC
    private key now routes through ``provision_ec_private_key``). The
    curve-absence -> skip split is pinned in tests/test_import_skip_xfail_batch3b.py.
    """
    from pkcs11_check.testcases import test_mech_sign as tms

    try:
        with pytest.raises(pytest.xfail.Exception, match="advertised but not operational"):
            tms._xfail_ec_kat_import_not_operational(_ATTR_INVALID, _ec_entry(), "EC private key")
    except pytest.skip.Exception as exc:
        pytest.fail(f"skipped instead of xfailing: {exc}")


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
    monkeypatch.setattr(sg, "provision_rsa_private_key", _raiser(_NON_CKR))

    with pytest.raises(AssertionError, match="KAT sign mismatch"):
        sg.test_rsa_pkcs1_siggen(_session(), None, vec_id, vec)


def test_a10_siggen_real_function_xfails_on_broad_ckr(monkeypatch: pytest.MonkeyPatch) -> None:
    """A10: the real test_rsa_pkcs1_siggen xfails when the negotiated import is rejected."""
    from pkcs11_check.testcases.wycheproof import test_wycheproof_rsa_siggen as sg

    vec_id, vec = sg._ALL_SIGGEN_VECTORS[0]
    monkeypatch.setattr(sg, "provision_rsa_private_key", _raiser(_ATTR_INVALID))
    monkeypatch.setattr(
        sg.pytest, "skip", lambda message: pytest.fail(f"unexpected skip: {message}")
    )

    with pytest.raises(pytest.xfail.Exception, match="advertised but not operational"):
        sg.test_rsa_pkcs1_siggen(_session(), None, vec_id, vec)


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
    monkeypatch.setattr(oa, "provision_rsa_private_key", _raiser(_NON_CKR))

    try:
        with pytest.raises(AssertionError, match="KAT sign mismatch"):
            oa.test_rsa_oaep(_session(), None, vec_id, vec)
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
            oa.test_rsa_oaep(_session(), None, vec_id, vec)
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

    The provisioning profile probe also calls create_object (via import_secret_key),
    so we additionally force a create_available profile to ensure provision_rsa_private_key
    delegates to import_rsa_private_key_negotiated, which is where negotiation exhaustion
    and the xfail happen.
    """
    from pkcs11_check.testcases._provisioning import ProvisioningProfile
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

    # Force the profile to report create_available so provision_rsa_private_key delegates
    # to import_rsa_private_key_negotiated (where negotiation exhaustion and xfail happen).
    fake_session = _session()
    fake_profile = ProvisioningProfile(rs=fake_session)
    fake_profile._verdicts["private"] = "create_available"  # type: ignore[attr-defined]
    monkeypatch.setattr(
        "pkcs11_check.testcases._provisioning._PROFILE_CACHE",
        {fake_session.sh: fake_profile},
    )

    vec_id, vec = _first_valid_oaep_vector(oa)
    oa._UNSUPPORTED_RSA_KEY_SIZES.clear()

    try:
        with pytest.raises(pytest.xfail.Exception, match="RSA_PKCS_OAEP:key-import"):
            oa.test_rsa_oaep(fake_session, None, vec_id, vec)
    finally:
        oa._UNSUPPORTED_RSA_KEY_SIZES.clear()
        monkeypatch.setattr("pkcs11_check.testcases._provisioning._PROFILE_CACHE", {})

    # Negotiation REALLY walked the storage variants (canonical + at least one
    # retry) before exhausting -- not a single-shot failure.
    assert len(calls) >= 2, f"expected >=2 storage-shape attempts, got {len(calls)}: {calls}"


# ===========================================================================
# F1 -- test_mech_sign.py symmetric-MAC KAT secret-key import (fix follow-ups)
# ===========================================================================
# The raw ``import_secret_key`` at the symmetric-MAC KAT site was never wrapped
# in a negotiated importer + helper: a clean import-reject CKR propagated as a
# hard FAIL instead of "advertised but not operational" xfail.
# Fix: wire to ``import_secret_key_negotiated`` + route clean exhaustion to xfail
# via ``_xfail_kat_import_not_operational`` (new generic helper, parallel to
# ``_xfail_rsa_kat_import_not_operational``).  Probe key: ``{mech_name}:key-import``.


def _kat_hmac_entry() -> MechEntry:
    from pkcs11_check.raw.types_std import CKK_AES, CKM_AES_CMAC

    return MechEntry(
        mech_id=int(CKM_AES_CMAC),
        mech_name="AES_CMAC",
        flags=0,
        min_key_size=0,
        max_key_size=0,
        config=MechConfig(
            is_keypair=False,
            key_type=int(CKK_AES),
            keygen_recipe=KeygenRecipe("aes"),
            param_recipe=ParamRecipe("none"),
            vector_file="dummy.json",
        ),
    )


def test_f1_secret_key_import_helper_xfails_on_broad_ckr() -> None:
    """F1: _xfail_kat_import_not_operational xfails on a broad import-reject CKR.

    Hard-pin: an unexpected skip escaping instead of an xfail is a regression.
    """
    from pkcs11_check.testcases import test_mech_sign as tms

    try:
        with pytest.raises(pytest.xfail.Exception, match="advertised but not operational"):
            tms._xfail_kat_import_not_operational(
                _ATTR_INVALID, _kat_hmac_entry(), "AES secret key"
            )
    except pytest.skip.Exception as exc:
        pytest.fail(f"skipped instead of xfailing: {exc}")


def test_f1_secret_key_import_helper_propagates_non_ckr() -> None:
    """F1 negative pin: a non-CKR AssertionError must not be xfailed or skipped."""
    from pkcs11_check.testcases import test_mech_sign as tms

    with pytest.raises(AssertionError, match="KAT sign mismatch"):
        tms._xfail_kat_import_not_operational(_NON_CKR, _kat_hmac_entry(), "AES secret key")


def test_f1_kat_vector_site_xfails_on_broad_ckr(monkeypatch: pytest.MonkeyPatch) -> None:
    """F1: the test_kat_vector symmetric-MAC site xfails when import is rejected.

    Drives the production class method (not just the helper) so the swap to
    import_secret_key_negotiated + _xfail_kat_import_not_operational is exercised
    end-to-end through test_kat_vector.

    load_positive_vectors is imported locally inside the function, so we patch
    it at the mechanism_vectors module level where the local import resolves.
    """
    from pkcs11_check.testcases import test_mech_sign as tms

    monkeypatch.setattr(tms, "import_secret_key_negotiated", _raiser(_ATTR_INVALID))

    entry = _kat_hmac_entry()
    assert entry.config is not None
    vec = {
        "key_hex": "aa" * 16,
        "mac_hex": "bb" * 16,
        "input_hex": "cc" * 32,
    }

    # Patch load_positive_vectors at its definition site; the local import
    # inside test_kat_vector picks it up from there.
    monkeypatch.setattr(
        "pkcs11_check.testcases.mechanism_vectors.load_positive_vectors",
        lambda _f: [vec],
    )

    try:
        with pytest.raises(pytest.xfail.Exception, match="AES_CMAC:key-import"):
            tms.TestMechSignKAT().test_kat_vector(_session(), entry, None)
    except pytest.skip.Exception as exc:
        pytest.fail(f"skipped instead of xfailing: {exc}")


# ===========================================================================
# F5 -- _run_asymmetric_sign_kat: priv_key destroyed before pub-import xfail
# ===========================================================================
# When verify_only=True and the public-key negotiated import raises with a broad
# CKR, _xfail_rsa_kat_import_not_operational fires (raises pytest.xfail) BEFORE
# the try/finally block that calls destroy_quietly on priv_key.  On storage-
# oriented modules the leaked priv handle is a TOKEN object that persists across
# the test file.  Fix: wrap the pub-key import in try/finally that destroys
# priv_key regardless of whether the xfail fires.


def test_f5_priv_key_destroyed_before_pub_import_xfail(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """F5: destroy_quietly is called for priv_key before pub-import xfail raises.

    Drives _run_asymmetric_sign_kat with verify_only=True.  Private import
    succeeds (returns a fake handle).  Public import raises a broad CKR (triggers
    xfail).  The test asserts destroy_quietly was called with the priv handle
    BEFORE the XFailed propagates.
    """
    from pkcs11_check.testcases import test_mech_sign as tms

    fake_priv = 0xDEAD

    destroyed: list[int] = []

    def _fake_destroy(_raw: Any, _sh: Any, handle: int) -> None:
        destroyed.append(handle)

    # Priv import succeeds, pub import refuses with a broad CKR.
    monkeypatch.setattr(tms, "provision_rsa_private_key", lambda *_a, **_kw: fake_priv)
    monkeypatch.setattr(tms, "import_rsa_public_key_negotiated", _raiser(_KEY_SIZE_RANGE))
    monkeypatch.setattr(tms, "destroy_quietly", _fake_destroy)

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
        "verify_only": True,
    }
    entry = _kat_rsa_entry()

    with pytest.raises(pytest.xfail.Exception, match="SHA256_RSA_PKCS:key-import"):
        tms._run_asymmetric_sign_kat(_session(), entry, entry.config, vec, None)

    assert fake_priv in destroyed, (
        f"priv handle {fake_priv:#x} was NOT destroyed before xfail; destroyed handles: {destroyed}"
    )
