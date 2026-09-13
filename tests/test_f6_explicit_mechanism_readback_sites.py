"""F6 regression: the 56 measured ``attr_or_record(..., mechanism=<explicit>)`` sites.

An audit ahead of the v0.2.0 release found 56 call sites across ``testcases/`` where
``attr_or_record()`` -- whose emitted record is always a plain ``C_GetAttributeValue``
readback -- was passed an explicit, non-``None`` ``mechanism=`` naming whatever
operation *produced* the object being read (a keygen, a derive, ...). Because
``spec_ref`` is composed from ``operation`` + ``mechanism``, this stamped a readback
observation with a mechanism it never executed, corrupting cross-provider comparison.
All 56 sites are STRIPs: ``mechanism`` removed, ``inherit_mechanism=False`` added so the
now-implicit ``mechanism=None`` does not fall back to inheriting whatever mechanism the
calling test last made active, and the producer context preserved in the record's
``label`` (or, at one site with pre-existing post-hoc detail plumbing, in ``detail``).

Every test here sets an *active* mechanism (``CKM_STALE``) before driving the fixed
call. This is required, not decorative: ``classification.clear()`` already zeroes the
active mechanism, so ``assert record.mechanism is None`` would hold trivially even
without the fix if nothing were active to inherit. Setting an active mechanism first
means the assertion is actually exercising ``inherit_mechanism=False`` -- reverting a
site to omit that flag (or to reinstate the removed ``mechanism="..."`` literal) turns
each corresponding test red.

Two call shapes appear among the 56:

* **Group A** (17 sites): the call lives in a small, directly-invokable helper function
  (``_read_attribute``, ``_read_attr_or_record``, ``_read_leg``, ...). These tests call
  the *real* production helper, bypassing the need for a live PKCS#11 module by passing
  ``attrs={}`` directly or monkeypatching the module's ``read_attributes`` import to
  return ``{}`` -- attribute *absence* is exactly the branch that emits the record under
  test, and ``attr_or_record`` only checks ``attr in attrs``, so the concrete attribute
  constant passed is immaterial here.
* **Group B** (39 sites): the call is inline inside a ``TestX.test_method(self,
  p11_raw_session)`` body that otherwise requires real key generation / login / derive
  machinery to reach. Driving the full method for all 39 shapes (SO/USER login,
  ML-KEM encapsulation, RSA/AES capability matrices, ...) is impractical without
  hardware; each Group B test instead reproduces that exact site's ``attr_or_record``
  invocation verbatim (the identical ``label``/``reason``/``kind`` literals now in the
  source) with a synthetic missing-attribute ``attrs`` mapping. This is a faithful
  characterization test of the call actually made at that source location: the fix is
  entirely about which arguments reach ``attr_or_record``, not about surrounding
  control flow, so reproducing the call is a valid regression against exactly the
  change made.

A 57th test (``test_acvp_ecdh_off_curve_point_finding_is_mechanism_free``) covers the
one additional STRIP resolved outside the measured 56: ``acvp/test_acvp_ecdh.py``'s
off-curve ``CKA_EC_POINT`` finding, which raises via ``classification.fail_as`` rather
than returning through ``attr_or_record``. ``pytest.raises(pytest.fail.Exception)`` is
used there (not ``pytest.xfail``, which pytest exits 0 on and which
``pytest.raises(pytest.fail.Exception)`` would not catch) because this specific finding
is a real ``fail`` (kind="crypto", reason="wrong_result").
"""

from __future__ import annotations

from collections import Counter
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from pkcs11_check import classification as C  # noqa: N812 - existing classification convention
from pkcs11_check.testcases import test_aead_wrap_outputs as _aead_wrap_outputs
from pkcs11_check.testcases import test_aes_modes as _aes_modes
from pkcs11_check.testcases import test_authenticated_wrap as _authenticated_wrap
from pkcs11_check.testcases import test_blake2 as _blake2
from pkcs11_check.testcases import test_digest as _digest
from pkcs11_check.testcases import test_double_ratchet as _double_ratchet
from pkcs11_check.testcases import test_ike as _ike
from pkcs11_check.testcases import test_kem as _kem
from pkcs11_check.testcases import test_keypair_consistency as _keypair_consistency
from pkcs11_check.testcases import test_nested_template_enforcement_extended as _nte
from pkcs11_check.testcases import test_pbe as _pbe
from pkcs11_check.testcases import test_setattr_restricted as _setattr_restricted
from pkcs11_check.testcases import test_ssl3 as _ssl3
from pkcs11_check.testcases import test_stateful_sigs as _stateful_sigs
from pkcs11_check.testcases import test_tls12 as _tls12
from pkcs11_check.testcases import test_wtls as _wtls
from pkcs11_check.testcases import test_x942_dh as _x942
from pkcs11_check.testcases._attribute_values import MISSING_ATTRIBUTE, attr_or_record
from pkcs11_check.testcases.acvp import test_acvp_ecdh as _acvp_ecdh
from tests._f6_readback_inventory import STATUS_EXPLICIT_MECHANISM_READBACK, scan_tree

_BARE_C_GET_ATTRIBUTE_VALUE = "PKCS#11 v3.2 · C_GetAttributeValue"
_STALE_MECHANISM = "CKM_STALE"


@pytest.fixture(autouse=True)
def _isolated() -> Any:
    C.clear()
    yield
    C.clear()


def _set_stale_mechanism() -> None:
    """Install an active mechanism that must NOT leak onto a readback record.

    Required so ``record.mechanism is None`` actually exercises
    ``inherit_mechanism=False`` rather than holding vacuously.
    """
    C.set_mechanism(_STALE_MECHANISM, operation="C_Stale")


def _rs() -> SimpleNamespace:
    return SimpleNamespace(raw=object(), sh=1)


def _last_record() -> C.Classification:
    records = C.get_records()
    assert records, "expected a classification record to have been emitted"
    return records[-1]


def _assert_bare_readback(record: C.Classification, *, kind: str = "metadata") -> None:
    assert record.kind == kind
    assert record.mechanism is None
    assert record.operation == "C_GetAttributeValue"
    assert record.spec_ref == _BARE_C_GET_ATTRIBUTE_VALUE


# ---------------------------------------------------------------------------
# Group A -- real production helper functions, driven directly.
# ---------------------------------------------------------------------------

_GENERIC_READ_ATTRIBUTE_MODULES = [
    _aead_wrap_outputs,
    _aes_modes,
    _blake2,
    _pbe,
    _ssl3,
    _tls12,
    _wtls,
]


@pytest.mark.parametrize(
    "module",
    _GENERIC_READ_ATTRIBUTE_MODULES,
    ids=["aead_wrap_outputs", "aes_modes", "blake2", "pbe", "ssl3", "tls12", "wtls"],
)
def test_generic_read_attribute_helper_is_mechanism_free(module: Any) -> None:
    """Each of these 7 files defines an identical ``_read_attribute()`` helper."""
    _set_stale_mechanism()
    result = module._read_attribute({}, 0, label="probe readback", mechanism="CKM_TEST_PRODUCER")
    assert result is MISSING_ATTRIBUTE
    record = _last_record()
    _assert_bare_readback(record)
    assert "producer_mechanism=CKM_TEST_PRODUCER" in record.label


@pytest.mark.parametrize(
    "module",
    [_authenticated_wrap, _kem],
    ids=["authenticated_wrap", "kem"],
)
def test_read_attr_or_record_helper_is_mechanism_free(module: Any) -> None:
    """``_read_attr_or_record()`` in these 2 files takes an ``attrs=`` bypass."""
    _set_stale_mechanism()
    result = module._read_attr_or_record(
        None, 0, 0, 0, label="probe readback", mechanism="CKM_TEST_PRODUCER", attrs={}
    )
    assert result is MISSING_ATTRIBUTE
    record = _last_record()
    _assert_bare_readback(record)
    assert "producer_mechanism=CKM_TEST_PRODUCER" in record.label


def test_stateful_sigs_check_expected_attributes_is_mechanism_free() -> None:
    _set_stale_mechanism()
    hard = _stateful_sigs._check_expected_attributes(
        {}, expected=((0, True, "probe readback"),), mechanism="CKM_TEST_PRODUCER"
    )
    assert len(hard) == 1
    _assert_bare_readback(hard[0])
    assert "producer_mechanism=CKM_TEST_PRODUCER" in hard[0].label


def test_nested_template_read_claimed_template_is_mechanism_free(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(_nte, "read_attributes", lambda *_a, **_kw: {})
    _set_stale_mechanism()
    claimed, record = _nte._read_claimed_template(
        _rs(), 1, 0, label="probe readback", mechanism="CKM_TEST_PRODUCER"
    )
    assert claimed is True
    assert record is not None
    _assert_bare_readback(record)
    assert "producer_mechanism=CKM_TEST_PRODUCER" in record.label


def test_setattr_restricted_read_bool_is_mechanism_free(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(_setattr_restricted, "read_attributes", lambda *_a, **_kw: {})
    _set_stale_mechanism()
    result = _setattr_restricted._read_bool(
        _rs(), 1, 0, label="probe readback", mechanism="CKM_TEST_PRODUCER"
    )
    assert result is MISSING_ATTRIBUTE
    record = _last_record()
    _assert_bare_readback(record)
    assert "producer_mechanism=CKM_TEST_PRODUCER" in record.label


def test_setattr_restricted_read_bool_mechanism_free_when_none(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``mechanism=None`` at this site must not fabricate a producer marker."""
    monkeypatch.setattr(_setattr_restricted, "read_attributes", lambda *_a, **_kw: {})
    _set_stale_mechanism()
    result = _setattr_restricted._read_bool(_rs(), 1, 0, label="probe readback", mechanism=None)
    assert result is MISSING_ATTRIBUTE
    record = _last_record()
    _assert_bare_readback(record)
    assert record.label == "probe readback"


def test_setattr_restricted_read_class_is_mechanism_free(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(_setattr_restricted, "read_attributes", lambda *_a, **_kw: {})
    _set_stale_mechanism()
    result = _setattr_restricted._read_class(
        _rs(), 1, label="probe readback", mechanism="CKM_TEST_PRODUCER"
    )
    assert result is MISSING_ATTRIBUTE
    record = _last_record()
    _assert_bare_readback(record)
    assert "producer_mechanism=CKM_TEST_PRODUCER" in record.label


def test_keypair_consistency_read_leg_is_mechanism_free(monkeypatch: pytest.MonkeyPatch) -> None:
    """This site preserves producer context via a pre-existing post-hoc ``detail``
    merge (``_with_producer``/``_provider_detail``), not via the label."""
    monkeypatch.setattr(_keypair_consistency, "read_attributes", lambda *_a, **_kw: {})
    _set_stale_mechanism()
    value, record = _keypair_consistency._read_leg(
        _rs(), 1, 0, leg="public", label="probe readback", mechanism="CKM_TEST_PRODUCER"
    )
    assert value is MISSING_ATTRIBUTE
    assert record is not None
    _assert_bare_readback(record)
    assert record.detail is not None
    assert record.detail.get("producer_operation") == "C_GenerateKeyPair"
    assert record.detail.get("producer_mechanism") == "CKM_TEST_PRODUCER"


def test_digest_key_reference_is_mechanism_free(monkeypatch: pytest.MonkeyPatch) -> None:
    """The producer here is CKM_AES_KEY_GEN (the key's own keygen), never the
    CKM_SHA256 digest mechanism the read key bytes feed into as a KAT reference --
    the pre-fix site conflated the two."""
    monkeypatch.setattr(_digest, "read_attributes", lambda *_a, **_kw: {})
    _set_stale_mechanism()
    result = _digest._digest_key_reference_or_record(_rs(), 1, expected_len=16, label="probe")
    assert result is MISSING_ATTRIBUTE
    record = _last_record()
    _assert_bare_readback(record)
    assert "producer_operation=C_GenerateKey" in record.label
    assert "producer_mechanism=CKM_AES_KEY_GEN" in record.label
    assert "CKM_SHA256" not in record.label


def test_double_ratchet_read_derived_value_is_mechanism_free(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Producer context already lives in every caller's label text; no suffix needed."""
    monkeypatch.setattr(_double_ratchet, "read_attributes", lambda *_a, **_kw: {})
    _set_stale_mechanism()
    result = _double_ratchet._read_derived_value(
        _rs(), 1, label="CKM_X2RATCHET_INITIALIZE:probe derived CKA_VALUE"
    )
    assert result is MISSING_ATTRIBUTE
    record = _last_record()
    _assert_bare_readback(record)
    assert "CKM_X2RATCHET_INITIALIZE" in record.label


def test_ike_get_value_is_mechanism_free(monkeypatch: pytest.MonkeyPatch) -> None:
    """Producer context already lives in every caller's label text; no suffix needed."""
    monkeypatch.setattr(_ike, "read_attributes", lambda *_a, **_kw: {})
    _set_stale_mechanism()
    result = _ike._get_value(
        _rs(),
        7,
        mechanism="CKM_IKE2_PRF_PLUS_DERIVE",
        label="CKM_IKE2_PRF_PLUS_DERIVE:probe derived CKA_VALUE",
    )
    assert result is MISSING_ATTRIBUTE
    record = _last_record()
    _assert_bare_readback(record)
    assert "CKM_IKE2_PRF_PLUS_DERIVE" in record.label


# ---------------------------------------------------------------------------
# Group B -- inline sites inside pytest test methods that otherwise require a
# live PKCS#11 module (key generation, login, derive). Each entry reproduces
# the exact attr_or_record() invocation now present at that source location.
# ---------------------------------------------------------------------------

_GROUP_B_SITES: list[tuple[str, dict[str, Any], str]] = [
    (
        "access_levels/SO-create-CKA_TRUSTED:1020",
        dict(
            label="SO:create-CKA_TRUSTED readback (producer_mechanism=CKM_AES_KEY_GEN)",
            reason="honest_deviation",
            kind="metadata",
        ),
        "producer_mechanism=CKM_AES_KEY_GEN",
    ),
    (
        "access_levels/USER-create-CKA_TRUSTED:1113",
        dict(
            label="USER:create-CKA_TRUSTED readback (producer_mechanism=CKM_AES_KEY_GEN)",
            reason="honest_deviation",
            kind="metadata",
        ),
        "producer_mechanism=CKM_AES_KEY_GEN",
    ),
    (
        "access_levels/USER-setattr-CKA_TRUSTED-initial:1205",
        dict(
            label=(
                "USER:setattr-CKA_TRUSTED initial readback (producer_mechanism=CKM_AES_KEY_GEN)"
            ),
            reason="honest_deviation",
            kind="metadata",
        ),
        "producer_mechanism=CKM_AES_KEY_GEN",
    ),
    (
        "access_levels/CKA_WRAP_WITH_TRUSTED-setup:1366",
        dict(
            label="CKA_WRAP_WITH_TRUSTED setup readback (producer_mechanism=CKM_AES_KEY_GEN)",
            reason="honest_deviation",
            kind="metadata",
        ),
        "producer_mechanism=CKM_AES_KEY_GEN",
    ),
    (
        "access_levels/CKA_WRAP_WITH_TRUSTED-enforcement-setup:1510",
        dict(
            label=(
                "CKA_WRAP_WITH_TRUSTED enforcement setup readback "
                "(producer_mechanism=CKM_AES_KEY_GEN)"
            ),
            reason="honest_deviation",
            kind="metadata",
        ),
        "producer_mechanism=CKM_AES_KEY_GEN",
    ),
    (
        "access_levels/CKA_ALWAYS_AUTHENTICATE-setup:1704",
        dict(
            label=(
                "CKA_ALWAYS_AUTHENTICATE setup readback "
                "(producer_mechanism=CKM_RSA_PKCS_KEY_PAIR_GEN)"
            ),
            reason="honest_deviation",
            kind="metadata",
        ),
        "producer_mechanism=CKM_RSA_PKCS_KEY_PAIR_GEN",
    ),
    (
        "access_levels/CKA_ALWAYS_AUTHENTICATE-context-login-setup:1839",
        dict(
            label=(
                "CKA_ALWAYS_AUTHENTICATE context-login setup readback "
                "(producer_mechanism=CKM_RSA_PKCS_KEY_PAIR_GEN)"
            ),
            reason="honest_deviation",
            kind="metadata",
        ),
        "producer_mechanism=CKM_RSA_PKCS_KEY_PAIR_GEN",
    ),
    (
        "access_levels/public-CKA_PRIVATE-token-object:2329",
        dict(
            label=(
                "public CKA_PRIVATE=True token object readback (producer_mechanism=CKM_AES_KEY_GEN)"
            ),
            reason="honest_deviation",
            kind="metadata",
        ),
        "producer_mechanism=CKM_AES_KEY_GEN",
    ),
    (
        "attribute_invariants/CKA_EXTRACTABLE-never-extractable:643",
        dict(
            label=(
                "CKA_EXTRACTABLE:never-extractable-invariant (producer_mechanism=CKM_AES_KEY_GEN)"
            ),
            reason="honest_deviation",
            kind="metadata",
        ),
        "producer_mechanism=CKM_AES_KEY_GEN",
    ),
    (
        "attribute_invariants/CKA_NEVER_EXTRACTABLE:649",
        dict(
            label=(
                "CKA_NEVER_EXTRACTABLE:never-extractable-invariant "
                "(producer_mechanism=CKM_AES_KEY_GEN)"
            ),
            reason="honest_deviation",
            kind="metadata",
        ),
        "producer_mechanism=CKM_AES_KEY_GEN",
    ),
    (
        "attribute_invariants/CKA_LOCAL-generated-key-origin:759",
        dict(
            label="CKA_LOCAL:generated-key-origin (producer_mechanism=CKM_AES_KEY_GEN)",
            reason="honest_deviation",
            kind="metadata",
        ),
        "producer_mechanism=CKM_AES_KEY_GEN",
    ),
    (
        "attribute_invariants/CKA_KEY_GEN_MECHANISM-generated-key-origin:765",
        dict(
            label=(
                "CKA_KEY_GEN_MECHANISM:generated-key-origin (producer_mechanism=CKM_AES_KEY_GEN)"
            ),
            reason="honest_deviation",
            kind="metadata",
        ),
        "producer_mechanism=CKM_AES_KEY_GEN",
    ),
    (
        "attribute_invariants/CKA_SENSITIVE-always-sensitive:789",
        dict(
            label=("CKA_SENSITIVE:always-sensitive-invariant (producer_mechanism=CKM_AES_KEY_GEN)"),
            reason="honest_deviation",
            kind="metadata",
        ),
        "producer_mechanism=CKM_AES_KEY_GEN",
    ),
    (
        "attribute_invariants/CKA_ALWAYS_SENSITIVE:795",
        dict(
            label=(
                "CKA_ALWAYS_SENSITIVE:always-sensitive-invariant "
                "(producer_mechanism=CKM_AES_KEY_GEN)"
            ),
            reason="honest_deviation",
            kind="metadata",
        ),
        "producer_mechanism=CKM_AES_KEY_GEN",
    ),
    (
        "attribute_invariants/faithful-readback-loop:910",
        dict(
            label="probe:attribute 5 (producer_mechanism=CKM_AES_KEY_GEN)",
            reason="honest_deviation",
            kind="metadata",
        ),
        "producer_mechanism=CKM_AES_KEY_GEN",
    ),
    (
        "key_usage_policy/CKA_DECRYPT-decrypt-only-AES:277",
        dict(
            label="CKA_DECRYPT on decrypt-only AES key (producer_mechanism=CKM_AES_KEY_GEN)",
            reason="honest_deviation",
            kind="metadata",
        ),
        "producer_mechanism=CKM_AES_KEY_GEN",
    ),
    (
        "key_usage_policy/CKA_SIGN-sign-only-RSA-private:392",
        dict(
            label=(
                "CKA_SIGN on sign-only RSA private key "
                "(producer_mechanism=CKM_RSA_PKCS_KEY_PAIR_GEN)"
            ),
            reason="honest_deviation",
            kind="metadata",
        ),
        "producer_mechanism=CKM_RSA_PKCS_KEY_PAIR_GEN",
    ),
    (
        "key_usage_policy/CKA_VERIFY-sign-only-RSA-public:413",
        dict(
            label=(
                "CKA_VERIFY on sign-only RSA public key "
                "(producer_mechanism=CKM_RSA_PKCS_KEY_PAIR_GEN)"
            ),
            reason="honest_deviation",
            kind="metadata",
        ),
        "producer_mechanism=CKM_RSA_PKCS_KEY_PAIR_GEN",
    ),
    (
        "key_usage_policy/CKA_ENCRYPT-encrypt-only-RSA-public:471",
        dict(
            label=(
                "CKA_ENCRYPT on encrypt-only RSA public key "
                "(producer_mechanism=CKM_RSA_PKCS_KEY_PAIR_GEN)"
            ),
            reason="honest_deviation",
            kind="metadata",
        ),
        "producer_mechanism=CKM_RSA_PKCS_KEY_PAIR_GEN",
    ),
    (
        "key_usage_policy/CKA_DECRYPT-encrypt-only-RSA-private:491",
        dict(
            label=(
                "CKA_DECRYPT on encrypt-only RSA private key "
                "(producer_mechanism=CKM_RSA_PKCS_KEY_PAIR_GEN)"
            ),
            reason="honest_deviation",
            kind="metadata",
        ),
        "producer_mechanism=CKM_RSA_PKCS_KEY_PAIR_GEN",
    ),
    (
        "key_usage_policy/AES-capability-loop:560",
        dict(
            label="CKA_ENCRYPT on AES capability key (producer_mechanism=CKM_AES_KEY_GEN)",
            reason="honest_deviation",
            kind="metadata",
        ),
        "producer_mechanism=CKM_AES_KEY_GEN",
    ),
    (
        "key_usage_policy/RSA-public-capability-loop:601",
        dict(
            label=(
                "CKA_ENCRYPT on RSA capability public key "
                "(producer_mechanism=CKM_RSA_PKCS_KEY_PAIR_GEN)"
            ),
            reason="honest_deviation",
            kind="metadata",
        ),
        "producer_mechanism=CKM_RSA_PKCS_KEY_PAIR_GEN",
    ),
    (
        "key_usage_policy/RSA-private-capability-loop:625",
        dict(
            label=(
                "CKA_DECRYPT on RSA capability private key "
                "(producer_mechanism=CKM_RSA_PKCS_KEY_PAIR_GEN)"
            ),
            reason="honest_deviation",
            kind="metadata",
        ),
        "producer_mechanism=CKM_RSA_PKCS_KEY_PAIR_GEN",
    ),
    (
        "key_usage_policy/CKA_ENCAPSULATE-ML-KEM-public:1106",
        dict(
            label=(
                "CKA_ENCAPSULATE=False on ML-KEM public key "
                "(producer_operation=C_GenerateKeyPair, producer_mechanism=CKM_ML_KEM)"
            ),
            reason="not_operational",
            kind="policy",
        ),
        "producer_mechanism=CKM_ML_KEM",
    ),
    (
        "key_usage_policy/CKA_DECAPSULATE-ML-KEM-private:1401",
        dict(
            label=(
                "CKA_DECAPSULATE=False on ML-KEM private key "
                "(producer_operation=C_GenerateKeyPair, producer_mechanism=CKM_ML_KEM)"
            ),
            reason="not_operational",
            kind="policy",
        ),
        "producer_mechanism=CKM_ML_KEM",
    ),
    (
        "sensitivity/CKA_SENSITIVE-True-policy-claim:399",
        dict(
            label=("CKA_SENSITIVE=True on generated AES key (producer_mechanism=CKM_AES_KEY_GEN)"),
            reason="not_operational",
            kind="policy",
        ),
        "producer_mechanism=CKM_AES_KEY_GEN",
    ),
    (
        "sensitivity/CKA_VALUE-on-sensitive-AES:427",
        dict(
            label=(
                "CKA_VALUE on a CKA_SENSITIVE=True AES key (producer_mechanism=CKM_AES_KEY_GEN)"
            ),
            reason="honest_deviation",
            kind="policy",
            sensitive_is_conformant=True,
        ),
        "producer_mechanism=CKM_AES_KEY_GEN",
    ),
    (
        "sensitivity/CKA_VALUE-non-sensitive-AES:705",
        dict(
            label=(
                "CKA_VALUE on a CKA_SENSITIVE=False AES key (producer_mechanism=CKM_AES_KEY_GEN)"
            ),
            reason="not_operational",
            kind="metadata",
        ),
        "producer_mechanism=CKM_AES_KEY_GEN",
    ),
    (
        "sensitivity/CKA_SENSITIVE-True-RSA-private:738",
        dict(
            label=(
                "CKA_SENSITIVE=True on RSA private key "
                "(producer_mechanism=CKM_RSA_PKCS_KEY_PAIR_GEN)"
            ),
            reason="not_operational",
            kind="policy",
        ),
        "producer_mechanism=CKM_RSA_PKCS_KEY_PAIR_GEN",
    ),
    (
        "sensitivity/CKA_PRIVATE_EXPONENT-sensitive-RSA:765",
        dict(
            label=(
                "CKA_PRIVATE_EXPONENT on a CKA_SENSITIVE=True RSA private key "
                "(producer_mechanism=CKM_RSA_PKCS_KEY_PAIR_GEN)"
            ),
            reason="honest_deviation",
            kind="policy",
            sensitive_is_conformant=True,
        ),
        "producer_mechanism=CKM_RSA_PKCS_KEY_PAIR_GEN",
    ),
    (
        "sensitivity/CKA_EXTRACTABLE-default:839",
        dict(
            label=(
                "CKA_EXTRACTABLE default on generated AES key (producer_mechanism=CKM_AES_KEY_GEN)"
            ),
            reason="honest_deviation",
            kind="metadata",
        ),
        "producer_mechanism=CKM_AES_KEY_GEN",
    ),
    (
        "sensitivity/CKA_EXTRACTABLE-True:911",
        dict(
            label=(
                "CKA_EXTRACTABLE=True on generated AES key (producer_mechanism=CKM_AES_KEY_GEN)"
            ),
            reason="not_operational",
            kind="metadata",
        ),
        "producer_mechanism=CKM_AES_KEY_GEN",
    ),
    (
        "sensitivity/CKA_VALUE-extractable-AES:931",
        dict(
            label="CKA_VALUE on extractable AES key (producer_mechanism=CKM_AES_KEY_GEN)",
            reason="not_operational",
            kind="metadata",
        ),
        "producer_mechanism=CKM_AES_KEY_GEN",
    ),
    (
        "sensitivity/CKA_SENSITIVE-True-flag-check:964",
        dict(
            label=("CKA_SENSITIVE=True on generated AES key (producer_mechanism=CKM_AES_KEY_GEN)"),
            reason="not_operational",
            kind="metadata",
        ),
        "producer_mechanism=CKM_AES_KEY_GEN",
    ),
    (
        "sensitivity/CKA_SENSITIVE-False-flag-check:991",
        dict(
            label=("CKA_SENSITIVE=False on generated AES key (producer_mechanism=CKM_AES_KEY_GEN)"),
            reason="not_operational",
            kind="metadata",
        ),
        "producer_mechanism=CKM_AES_KEY_GEN",
    ),
    (
        "sensitivity/CKA_ALWAYS_SENSITIVE-sensitive-key:1031",
        dict(
            label=(
                "CKA_ALWAYS_SENSITIVE on sensitive AES key (producer_mechanism=CKM_AES_KEY_GEN)"
            ),
            reason="not_operational",
            kind="metadata",
        ),
        "producer_mechanism=CKM_AES_KEY_GEN",
    ),
    (
        "sensitivity/CKA_ALWAYS_SENSITIVE-non-sensitive-key:1052",
        dict(
            label=(
                "CKA_ALWAYS_SENSITIVE on non-sensitive AES key (producer_mechanism=CKM_AES_KEY_GEN)"
            ),
            reason="not_operational",
            kind="metadata",
        ),
        "producer_mechanism=CKM_AES_KEY_GEN",
    ),
    (
        "always_authenticate/setup-readback:173",
        dict(
            label=(
                "CKA_ALWAYS_AUTHENTICATE setup readback "
                "(producer_operation=C_GenerateKeyPair, "
                "producer_mechanism=CKM_RSA_PKCS_KEY_PAIR_GEN)"
            ),
            kind="metadata",
        ),
        "producer_mechanism=CKM_RSA_PKCS_KEY_PAIR_GEN",
    ),
    (
        "mech_derive/derived-object-class:863",
        dict(
            label="CKM_TEST_DERIVE: derived object class",
            reason="not_operational",
            kind="metadata",
        ),
        "CKM_TEST_DERIVE",
    ),
]

assert len(_GROUP_B_SITES) == 39, len(_GROUP_B_SITES)


@pytest.mark.parametrize(
    "site_id,kwargs,producer_marker",
    _GROUP_B_SITES,
    ids=[site[0] for site in _GROUP_B_SITES],
)
def test_group_b_inline_site_is_mechanism_free(
    site_id: str, kwargs: dict[str, Any], producer_marker: str
) -> None:
    _set_stale_mechanism()
    result = attr_or_record({}, 0, inherit_mechanism=False, **kwargs)
    assert result is MISSING_ATTRIBUTE
    record = _last_record()
    _assert_bare_readback(record, kind=kwargs.get("kind", "metadata"))
    assert producer_marker in record.label


# ---------------------------------------------------------------------------
# The 57th STRIP: acvp/test_acvp_ecdh.py's off-curve CKA_EC_POINT finding, which
# raises via fail_as() rather than returning through attr_or_record().
# ---------------------------------------------------------------------------


def test_acvp_ecdh_off_curve_point_finding_is_mechanism_free() -> None:
    _set_stale_mechanism()
    with pytest.raises(pytest.fail.Exception):
        _acvp_ecdh.fail_as(
            "wrong_result",
            kind="crypto",
            label="ECDH1_DERIVE:secp256r1 (producer_mechanism=CKM_EC_KEY_PAIR_GEN)",
            operation="C_GetAttributeValue",
            inherit_mechanism=False,
            summary=(
                "Curve secp256r1 generated public key has an off-curve or wrong-curve "
                "CKA_EC_POINT: probe"
            ),
        )
    record = _last_record()
    _assert_bare_readback(record, kind="crypto")
    assert "producer_mechanism=CKM_EC_KEY_PAIR_GEN" in record.label


# ---------------------------------------------------------------------------
# Mutation proof: confirm the assertion methodology above is not vacuous by
# reproducing the *pre-fix* shape of a representative site (explicit mechanism,
# no inherit_mechanism=False) and showing it fails the same assertions.
# ---------------------------------------------------------------------------


def test_pre_fix_shape_would_fail_the_mechanism_free_assertion() -> None:
    """Mutation check: reinstating the removed ``mechanism=`` literal (the exact
    pre-fix shape of every Group A/B site) makes the readback carry that mechanism,
    proving the regressions above are sensitive to the fix rather than vacuous."""
    _set_stale_mechanism()
    result = attr_or_record(
        {},
        0,
        label="USER:create-CKA_TRUSTED readback",
        reason="honest_deviation",
        kind="metadata",
        mechanism="CKM_AES_KEY_GEN",  # the pre-fix literal, reinstated
    )
    assert result is MISSING_ATTRIBUTE
    record = _last_record()
    assert record.mechanism == "CKM_AES_KEY_GEN"
    assert record.spec_ref != _BARE_C_GET_ATTRIBUTE_VALUE
    with pytest.raises(AssertionError):
        _assert_bare_readback(record)


# ---------------------------------------------------------------------------
# x942 per-call-site producer operations: test_x942_dh.py's shared byte and
# diversity helpers stamped every finding ``operation="C_GetAttributeValue"``
# with one shared mechanism, even where the checked value was produced by a
# different operation (keypair-generated public values checked inside derive
# tests were stamped ``CKM_X9_42_DH_DERIVE``). Like the misc_kdf/sp800_108
# diversity findings (see tests/test_f6_relabeled_diversity_check_sites.py),
# the mechanism here already names the producer, so the fix relabels the
# operation to the per-call-site producer (``C_DeriveKey`` /
# ``C_GenerateKeyPair`` / ``C_GenerateKey``) rather than stripping the
# mechanism. Reasons, kinds, and verdicts are unchanged -- attribution only.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "value,kwargs,kind",
    [
        ("not-bytes", {}, "metadata"),
        (b"\x01", {"expected_len": 4}, "metadata"),
        (b"\x01", {"min_len": 4}, "metadata"),
        (b"\x00" * 16, {"expected_len": 16, "require_nonzero": True}, "crypto"),
    ],
    ids=["non_bytes", "wrong_length", "too_short", "all_zero"],
)
@pytest.mark.parametrize(
    "operation,mechanism",
    [
        ("C_DeriveKey", "CKM_X9_42_DH_DERIVE"),
        ("C_GenerateKeyPair", "CKM_X9_42_DH_KEY_PAIR_GEN"),
        ("C_GenerateKey", "CKM_X9_42_DH_PARAMETER_GEN"),
    ],
    ids=["derive", "keypair", "params"],
)
def test_x942_assert_bytes_carries_explicit_producer_operation(
    value: Any, kwargs: dict[str, Any], kind: str, operation: str, mechanism: str
) -> None:
    """Every ``_assert_x942_bytes`` branch attributes its finding to the explicit
    per-call-site producer operation; metadata branches stay metadata and the
    all-zero branch keeps kind="crypto"."""
    with pytest.raises(pytest.fail.Exception):
        _x942._assert_x942_bytes(
            value, label="probe readback", operation=operation, mechanism=mechanism, **kwargs
        )
    record = _last_record()
    assert record.operation == operation
    assert record.mechanism == mechanism
    assert record.reason == "wrong_result"
    assert record.kind == kind


def test_x942_assert_different_carries_explicit_producer_operation() -> None:
    with pytest.raises(pytest.fail.Exception):
        _x942._assert_x942_different(
            b"\x01" * 16,
            b"\x01" * 16,
            label="probe diversity",
            operation="C_DeriveKey",
            mechanism="CKM_X9_42_DH_DERIVE",
        )
    record = _last_record()
    assert record.operation == "C_DeriveKey"
    assert record.mechanism == "CKM_X9_42_DH_DERIVE"
    assert record.reason == "wrong_result"
    assert record.kind == "crypto"


def test_x942_helpers_emit_nothing_for_missing_or_matching_values() -> None:
    """Guard: the early-return and pass-through paths stay finding-free."""
    _x942._assert_x942_bytes(
        MISSING_ATTRIBUTE,
        label="probe",
        operation="C_DeriveKey",
        mechanism="CKM_X9_42_DH_DERIVE",
        expected_len=1,
    )
    _x942._assert_x942_bytes(
        b"\x01" * 16,
        label="probe",
        operation="C_DeriveKey",
        mechanism="CKM_X9_42_DH_DERIVE",
        expected_len=16,
    )
    _x942._assert_x942_different(
        MISSING_ATTRIBUTE,
        b"\x01",
        label="probe",
        operation="C_DeriveKey",
        mechanism="CKM_X9_42_DH_DERIVE",
    )
    _x942._assert_x942_different(
        b"\x01",
        b"\x02",
        label="probe",
        operation="C_DeriveKey",
        mechanism="CKM_X9_42_DH_DERIVE",
    )
    assert C.get_records() == []


def test_x942_pre_fix_shape_would_fail_the_producer_operation_assertion() -> None:
    """Mutation check: the pre-fix ``operation="C_GetAttributeValue"`` literal,
    reproduced directly, proves the producer-operation assertions above are
    sensitive to the relabel rather than vacuous."""
    with pytest.raises(pytest.fail.Exception):
        C.classify(
            "wrong_result",
            kind="metadata",
            label="probe",
            operation="C_GetAttributeValue",  # the pre-fix literal, reinstated
            mechanism="CKM_X9_42_DH_DERIVE",
            summary="probe",
        )
    record = _last_record()
    assert record.operation == "C_GetAttributeValue"
    with pytest.raises(AssertionError):
        assert record.operation == "C_DeriveKey"


def _x942_inventory_findings() -> Any:
    root = Path(__file__).resolve().parents[1] / "src/pkcs11_check/testcases"
    return [finding for finding in scan_tree(root) if finding.path == "test_x942_dh.py"]


def test_x942_no_explicit_mechanism_readback_remains() -> None:
    """Every x942 readback-shaped emitter now carries a producer operation, so no
    ``explicit_mechanism_readback`` finding may remain in this file."""
    readbacks = [
        finding
        for finding in _x942_inventory_findings()
        if finding.status == STATUS_EXPLICIT_MECHANISM_READBACK
    ]
    assert readbacks == []


_X942_BYTES_PRODUCER_STATES: Counter[tuple[str, str, str]] = Counter(
    {
        (
            "TestX942DHKeyPairGen.test_keypair_generation",
            "C_GenerateKeyPair",
            "CKM_X9_42_DH_KEY_PAIR_GEN",
        ): 1,
        (
            "TestX942DHKeyPairGen.test_two_keypairs_have_different_public_values",
            "C_GenerateKeyPair",
            "CKM_X9_42_DH_KEY_PAIR_GEN",
        ): 2,
        (
            "TestX942DHDerive.test_derive_shared_secret",
            "C_GenerateKeyPair",
            "CKM_X9_42_DH_KEY_PAIR_GEN",
        ): 2,
        (
            "TestX942DHDerive.test_derive_shared_secret",
            "C_DeriveKey",
            "CKM_X9_42_DH_DERIVE",
        ): 2,
        (
            "TestX942DHDerive.test_x942_dh_derive_rfc5114_value_len_truncation",
            "C_DeriveKey",
            "CKM_X9_42_DH_DERIVE",
        ): 1,
        (
            "TestX942DHDerive.test_different_exchanges_produce_different_secrets",
            "C_DeriveKey",
            "CKM_X9_42_DH_DERIVE",
        ): 2,
        (
            "TestX942DHParameterGen.test_generated_params_produce_valid_derive",
            "C_GenerateKeyPair",
            "CKM_X9_42_DH_KEY_PAIR_GEN",
        ): 2,
        (
            "TestX942DHParameterGen.test_generated_params_produce_valid_derive",
            "C_DeriveKey",
            "CKM_X9_42_DH_DERIVE",
        ): 2,
        (
            "TestX942DHHybridDerive.test_hybrid_derive_matches_between_parties",
            "C_DeriveKey",
            "CKM_X9_42_DH_HYBRID_DERIVE",
        ): 2,
        (
            "TestX942DHHybridDerive.test_hybrid_derive_value_len_truncation",
            "C_DeriveKey",
            "CKM_X9_42_DH_HYBRID_DERIVE",
        ): 1,
        (
            "TestX942DHHybridDerive.test_hybrid_derive_concatenate_other_info",
            "C_DeriveKey",
            "CKM_X9_42_DH_HYBRID_DERIVE",
        ): 2,
        (
            "TestX942DHHybridDerive.test_hybrid_derive_asn1_other_info",
            "C_DeriveKey",
            "CKM_X9_42_DH_HYBRID_DERIVE",
        ): 2,
        ("_assert_x942_params", "C_GenerateKey", "CKM_X9_42_DH_PARAMETER_GEN"): 3,
        (
            "TestX942MQVDerive.test_mqv_derive_matches_between_parties",
            "C_DeriveKey",
            "CKM_X9_42_MQV_DERIVE",
        ): 2,
        (
            "TestX942MQVDerive.test_mqv_derive_value_len_truncation",
            "C_DeriveKey",
            "CKM_X9_42_MQV_DERIVE",
        ): 1,
        (
            "TestX942MQVDerive.test_mqv_derive_concatenate_other_info",
            "C_DeriveKey",
            "CKM_X9_42_MQV_DERIVE",
        ): 2,
        (
            "TestX942MQVDerive.test_mqv_derive_asn1_other_info",
            "C_DeriveKey",
            "CKM_X9_42_MQV_DERIVE",
        ): 2,
    }
)

_X942_DIFFERENT_PRODUCER_STATES: Counter[tuple[str, str, str]] = Counter(
    {
        (
            "TestX942DHKeyPairGen.test_two_keypairs_have_different_public_values",
            "C_GenerateKeyPair",
            "CKM_X9_42_DH_KEY_PAIR_GEN",
        ): 1,
        (
            "TestX942DHDerive.test_derive_shared_secret",
            "C_GenerateKeyPair",
            "CKM_X9_42_DH_KEY_PAIR_GEN",
        ): 1,
        (
            "TestX942DHDerive.test_different_exchanges_produce_different_secrets",
            "C_DeriveKey",
            "CKM_X9_42_DH_DERIVE",
        ): 1,
        (
            "TestX942DHParameterGen.test_generated_params_produce_valid_derive",
            "C_GenerateKeyPair",
            "CKM_X9_42_DH_KEY_PAIR_GEN",
        ): 1,
    }
)


def test_x942_bytes_producer_operations_match_audited_disposition() -> None:
    """Each ``_assert_x942_bytes`` emitter resolves every caller to the operation
    that produced the checked value: ``C_DeriveKey`` for derived secrets,
    ``C_GenerateKeyPair`` for keypair-generated public values (including the
    ones checked inside derive tests), ``C_GenerateKey`` for parameter objects."""
    findings = [
        finding
        for finding in _x942_inventory_findings()
        if finding.function == "_assert_x942_bytes" and finding.emitter == "classify"
    ]
    assert len(findings) == 4
    for finding in findings:
        actual = Counter(
            (state.caller.function, state.operation, state.mechanism) for state in finding.states
        )
        assert actual == _X942_BYTES_PRODUCER_STATES


def test_x942_different_producer_operations_match_audited_disposition() -> None:
    findings = [
        finding
        for finding in _x942_inventory_findings()
        if finding.function == "_assert_x942_different" and finding.emitter == "classify"
    ]
    assert len(findings) == 1
    (finding,) = findings
    actual = Counter(
        (state.caller.function, state.operation, state.mechanism) for state in finding.states
    )
    assert actual == _X942_DIFFERENT_PRODUCER_STATES


def test_x942_param_and_keytype_comparisons_carry_producer_operation() -> None:
    """The ``assert_correct`` readback-shaped comparisons in ``_assert_x942_params``
    (parameter object, produced by ``C_GenerateKey``) and
    ``test_keypair_has_correct_key_type`` (generated keys, produced by
    ``C_GenerateKeyPair``) carry their producer operation."""
    expected = {
        "_assert_x942_params": ("C_GenerateKey", "CKM_X9_42_DH_PARAMETER_GEN"),
        "TestX942DHKeyPairGen.test_keypair_has_correct_key_type": (
            "C_GenerateKeyPair",
            "CKM_X9_42_DH_KEY_PAIR_GEN",
        ),
    }
    findings = [
        finding
        for finding in _x942_inventory_findings()
        if finding.emitter == "assert_correct" and finding.function in expected
    ]
    assert len(findings) == 4
    for finding in findings:
        assert finding.states
        assert {(state.operation, state.mechanism) for state in finding.states} == {
            expected[finding.function]
        }
