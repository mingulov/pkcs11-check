"""Wycheproof AES-CMAC, AES Key Wrap, AES-KWP, AES-CCM, AES-GMAC, and AES-XTS vectors."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any, NoReturn

import pytest

from pkcs11_check.classification import classify
from pkcs11_check.raw.pack import mech_bytes, mech_ccm
from pkcs11_check.raw.recipes import (
    decrypt_single,
    destroy_quietly,
    encrypt_single,
    generate_random,
    read_attributes,
    unwrap_key,
    verify_single,
)
from pkcs11_check.raw.rv import CkrAssertionError, ckr_name
from pkcs11_check.raw.types_std import (
    CKA_CLASS,
    CKA_DECRYPT,
    CKA_ENCRYPT,
    CKA_EXTRACTABLE,
    CKA_KEY_TYPE,
    CKA_SENSITIVE,
    CKA_SIGN,
    CKA_TOKEN,
    CKA_UNWRAP,
    CKA_VALUE,
    CKA_VALUE_LEN,
    CKA_VERIFY,
    CKA_WRAP,
    CKK_AES,
    CKK_AES_XTS,
    CKK_GENERIC_SECRET,
    CKM_AES_CCM,
    CKM_AES_CMAC,
    CKM_AES_GMAC,
    CKM_AES_KEY_WRAP,
    CKM_AES_KEY_WRAP_KWP,
    CKM_AES_XTS,
    CKO_SECRET_KEY,
    CKR_ARGUMENTS_BAD,
    CKR_ATTRIBUTE_VALUE_INVALID,
    CKR_DATA_LEN_RANGE,
    CKR_DEVICE_ERROR,
    CKR_FUNCTION_FAILED,
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_GENERAL_ERROR,
    CKR_KEY_HANDLE_INVALID,
    CKR_MECHANISM_INVALID,
    CKR_MECHANISM_PARAM_INVALID,
)
from pkcs11_check.testcases._negotiation import (
    TEMPLATE_SHAPE_REJECTS,
    negotiate_request,
    value_len_variant_allowed,
)
from pkcs11_check.testcases._operability import (
    classify_kat_clean_error,
    not_operational_reason,
    xfail_vacuous_reject,
)
from pkcs11_check.testcases.acvp.aes.base_runner_aead import _aead_operability as _ccm_operability
from pkcs11_check.testcases.conftest import (
    assert_correct,
    import_secret_key_negotiated,
    xfail_if_known_ckr,
)
from pkcs11_check.testcases.data import WYCHEPROOF_DIR, load_json_cached

pytestmark = pytest.mark.wycheproof

_AES_RUNTIME_REJECT_CKRS = (
    CKR_ARGUMENTS_BAD,
    CKR_DATA_LEN_RANGE,
    CKR_DEVICE_ERROR,
    CKR_FUNCTION_FAILED,
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_GENERAL_ERROR,
    # Imported-with-CKR_OK key not honored at use time (corePKCS11 returns
    # KEY_HANDLE_INVALID for CMAC keys it claimed to import) -- the deviation
    # is recorded here; the self-contradiction itself belongs to the dedicated
    # object-coherence conformance coverage. Same precedent as wycheproof ECDSA.
    CKR_KEY_HANDLE_INVALID,
    CKR_MECHANISM_INVALID,
    CKR_MECHANISM_PARAM_INVALID,
)


def _xfail_if_aes_runtime_reject(exc: AssertionError, label: str) -> NoReturn:
    """Classify advertised AES operation rejects as non-clean findings."""
    xfail_if_known_ckr(
        exc,
        _AES_RUNTIME_REJECT_CKRS,
        f"{label}: advertised AES operation is not operational",
    )
    raise exc


# Clean reject codes that, on a VALID AES-KW vector after negotiation is exhausted,
# indicate an operational deviation (module cannot create the generic-secret object) ->
# xfail, not fail. Broader than the negotiation retry-trigger set on purpose.
_AES_KW_VALID_VECTOR_CLEAN_REJECTS = TEMPLATE_SHAPE_REJECTS + (CKR_ATTRIBUTE_VALUE_INVALID,)


def _unwrap_aes_kw_adaptive(
    rs: Any, unwrapping_key: int, wrapped: bytes, base_attrs: dict[int, Any], value_len: int | None
) -> int:
    """Unwrap an AES-KW blob, retrying with CKA_VALUE_LEN on a template-shape reject.

    The first variant uses the minimal template (no CKA_VALUE_LEN), which lenient
    modules accept unchanged. Only when the module rejects that template with a
    "shape" code does :func:`negotiate_request` move on to a variant that restates
    the recovered length explicitly. Any other rejection (e.g. an integrity failure
    on a forged blob) propagates to the caller for normal classification, so forgery
    detection is preserved.

    ``value_len`` is ``None`` for *invalid* vectors: a forged blob must never be
    coerced through a restated length (that would let the module recover a wrongly
    sized object and accept material it should reject), so no length variant is added
    and the module's own rejection stands.
    """
    variants = [dict(base_attrs)]
    if value_len is not None and value_len_variant_allowed(
        base_attrs[CKA_KEY_TYPE], CKM_AES_KEY_WRAP
    ):
        variants.append({**base_attrs, CKA_VALUE_LEN: value_len})

    def attempt(delta: Mapping[int, Any]) -> int:
        return unwrap_key(rs.raw, rs.sh, unwrapping_key, wrapped, CKM_AES_KEY_WRAP, attrs=delta)

    result, _idx = negotiate_request(attempt, variants, label="AES-KW unwrap")
    return result


def _load_flat(filename: str) -> list[tuple[str, dict[str, Any]]]:
    """Load vectors from a Wycheproof JSON, flattening groups."""
    path = WYCHEPROOF_DIR / filename
    if not path.exists():
        return []
    data = load_json_cached(path)
    vectors = []
    for group in data["testGroups"]:
        for test in group["tests"]:
            test["_group"] = {k: v for k, v in group.items() if k != "tests"}
            vec_id = f"tc{test['tcId']}-{test['result']}"
            vectors.append((vec_id, test))
    return vectors


# --- AES-CMAC ---

_AES_CMAC_VECTORS = _load_flat("aes_cmac_test.json")


@pytest.mark.parametrize("vec_id,vec", _AES_CMAC_VECTORS, ids=[v[0] for v in _AES_CMAC_VECTORS])
def test_aes_cmac(p11_module_session: Any, vec_id: str, vec: dict[str, Any]) -> None:
    """AES-CMAC tag verification from Wycheproof vectors.

    Verifies the *supplied* tag with C_Verify so that invalid vectors actually
    exercise rejection. A module that verifies an invalid tag as valid is a
    crypto-correctness break (-> fail). The previous produce-direction
    (C_Sign + compare) could never reject an invalid vector because a fresh
    correct tag never matched the modified expected tag.
    """
    rs = p11_module_session
    if not rs.has_mechanism("AES_CMAC"):
        pytest.skip("AES_CMAC not supported")

    key_bytes = bytes.fromhex(vec["key"])
    msg = bytes.fromhex(vec["msg"])
    tag_expected = bytes.fromhex(vec["tag"])
    result = vec["result"]

    try:
        key = import_secret_key_negotiated(
            rs,
            CKK_AES,
            key_bytes,
            attrs={
                CKA_SIGN: True,
                CKA_VERIFY: True,
                CKA_TOKEN: False,
                CKA_SENSITIVE: False,
            },
        )
    except AssertionError:
        if result == "invalid":
            return
        raise

    try:
        verified = verify_single(rs.raw, rs.sh, key, CKM_AES_CMAC, msg, tag_expected)
    except AssertionError as exc:
        if result == "valid":
            _xfail_if_aes_runtime_reject(exc, f"AES-CMAC {vec_id}")
        # acceptable: reject of an invalid vector is fine
        return
    finally:
        destroy_quietly(rs.raw, rs.sh, key)

    if result == "valid" and not verified:
        classify(
            "wrong_result",
            kind="crypto",
            label="AES-CMAC",
            summary=f"AES-CMAC rejected a valid CMAC vector {vec_id}",
            source=vec.get("_source"),
            vector_id=vec.get("_vector_id"),
        )
    if result == "invalid" and verified:
        classify(
            "accepted_invalid",
            kind="crypto",
            label="AES-CMAC",
            summary=f"AES-CMAC {vec_id}: accepted invalid tag (forged tag verified)",
            source=vec.get("_source"),
            vector_id=vec.get("_vector_id"),
        )

    generate_random(rs.raw, rs.sh, 64)


# --- AES Key Wrap (RFC 3394) ---

_AES_WRAP_VECTORS = _load_flat("aes_wrap_test.json")


@pytest.mark.parametrize("vec_id,vec", _AES_WRAP_VECTORS, ids=[v[0] for v in _AES_WRAP_VECTORS])
def test_aes_key_wrap(p11_module_session: Any, vec_id: str, vec: dict[str, Any]) -> None:
    """AES Key Wrap (RFC 3394) unwrap from Wycheproof vectors.

    Unwraps the supplied wrapped blob (``ct``) so invalid vectors actually
    exercise rejection. A module that unwraps an invalid (malformed/forged)
    wrapped blob is a crypto-correctness break (-> fail). The previous
    produce-direction (wrap + compare) could never reject an invalid vector
    because a fresh correct wrap never matched the modified expected blob.
    """
    rs = p11_module_session
    if not rs.has_mechanism("AES_KEY_WRAP"):
        pytest.skip("AES_KEY_WRAP not supported")

    key_bytes = bytes.fromhex(vec["key"])
    msg_expected = bytes.fromhex(vec["msg"])
    ct = bytes.fromhex(vec["ct"])
    result = vec["result"]

    # Import unwrapping key
    try:
        wrap_key_h = import_secret_key_negotiated(
            rs,
            CKK_AES,
            key_bytes,
            attrs={
                CKA_WRAP: True,
                CKA_UNWRAP: True,
                CKA_TOKEN: False,
                CKA_SENSITIVE: False,
            },
        )
    except AssertionError as exc:
        if not isinstance(exc, CkrAssertionError):
            raise
        # Mechanism was advertised (has_mechanism gate passed above); a
        # negotiation-exhausted import refusal is "advertised but not
        # operational" -> xfail per the classification model.
        classify(
            "not_operational",
            label="AES_KEY_WRAP:key-import",
            summary=not_operational_reason(
                "AES_KEY_WRAP:key-import",
                ckr_name(exc.rv),
            ),
        )

    # Unwrap the supplied blob and verify the recovered key material
    unwrapped = None
    try:
        unwrapped = _unwrap_aes_kw_adaptive(
            rs,
            wrap_key_h,
            ct,
            {
                CKA_CLASS: CKO_SECRET_KEY,
                CKA_KEY_TYPE: CKK_GENERIC_SECRET,
                CKA_EXTRACTABLE: True,
                CKA_SENSITIVE: False,
                CKA_TOKEN: False,
            },
            # Restate the recovered length only for VALID vectors. Invalid (forged)
            # blobs pass None so they are never coerced through an explicit length.
            len(msg_expected) if result == "valid" else None,
        )
    except AssertionError as exc:
        if result == "valid":
            # The adaptive unwrap already tried both the minimal template and one with an
            # explicit CKA_VALUE_LEN, so a remaining clean template/attribute reject is an
            # operational deviation, not a crypto break: the module cannot create the
            # generic-secret object either way. Examples seen across modules: NSS refuses
            # the oversized 384-byte CounterOverflow vectors (TEMPLATE_INCONSISTENT) and
            # opencryptoki/softhsm2 reject CKA_VALUE_LEN itself (ATTRIBUTE_READ_ONLY).
            # softhsm2 and kryoptic unwrap these vectors, so the inputs are valid.
            xfail_if_known_ckr(
                exc,
                _AES_RUNTIME_REJECT_CKRS + _AES_KW_VALID_VECTOR_CLEAN_REJECTS,
                f"AES-KW {vec_id}: unwrap into a generic secret not operational",
            )
            classify(
                "not_operational",
                label="AES-KW",
                summary=f"AES-KW unwrap failed for valid vector {vec_id}: {exc}",
                source=vec.get("_source"),
                vector_id=vec.get("_vector_id"),
            )
        # acceptable: reject of an invalid wrapped blob is fine
        return
    finally:
        destroy_quietly(rs.raw, rs.sh, wrap_key_h)

    if result == "invalid":
        destroy_quietly(rs.raw, rs.sh, unwrapped)
        classify(
            "accepted_invalid",
            kind="crypto",
            label="AES-KW",
            summary=f"AES-KW unwrap {vec_id}: accepted invalid wrapped key (forged blob unwrapped)",
            source=vec.get("_source"),
            vector_id=vec.get("_vector_id"),
        )

    # valid: recovered key material must match the original
    try:
        attrs = read_attributes(rs.raw, rs.sh, unwrapped, [CKA_VALUE])
    finally:
        destroy_quietly(rs.raw, rs.sh, unwrapped)
    recovered = attrs.get(CKA_VALUE)
    if recovered is None:
        classify(
            "honest_deviation",
            label="AES-KW",
            summary=f"AES-KW {vec_id}: unwrapped key material unreadable; cannot verify",
            source=vec.get("_source"),
            vector_id=vec.get("_vector_id"),
        )
    assert_correct(
        actual=recovered,
        expected=msg_expected,
        label=f"AES-KW:C_UnwrapKey KAT {vec_id}",
        operation="C_UnwrapKey",
        mechanism="CKM_AES_KEY_WRAP",
        source=vec.get("_source"),
        vector_id=vec.get("_vector_id"),
    )


# --- AES Key Wrap with Padding (RFC 5649) ---

_AES_KWP_VECTORS = _load_flat("aes_kwp_test.json")


@pytest.mark.parametrize("vec_id,vec", _AES_KWP_VECTORS, ids=[v[0] for v in _AES_KWP_VECTORS])
def test_aes_kwp(p11_module_session: Any, vec_id: str, vec: dict[str, Any]) -> None:
    """AES Key Wrap with Padding (RFC 5649) from Wycheproof vectors.

    KWP allows wrapping data that is not a multiple of 8 bytes,
    unlike basic AES-KW which requires 8-byte aligned data.
    """
    rs = p11_module_session
    if not rs.has_mechanism("AES_KEY_WRAP_KWP"):
        pytest.skip("AES_KEY_WRAP_KWP not supported")

    key_bytes = bytes.fromhex(vec["key"])
    msg = bytes.fromhex(vec["msg"])
    ct_expected = bytes.fromhex(vec["ct"])
    result = vec["result"]

    # Import wrapping key
    try:
        wrap_key_h = import_secret_key_negotiated(
            rs,
            CKK_AES,
            key_bytes,
            attrs={
                CKA_WRAP: True,
                CKA_UNWRAP: True,
                CKA_ENCRYPT: True,
                CKA_TOKEN: False,
                CKA_SENSITIVE: False,
            },
        )
    except AssertionError as exc:
        if not isinstance(exc, CkrAssertionError):
            raise
        # Mechanism was advertised (has_mechanism gate passed above); a
        # negotiation-exhausted import refusal is "advertised but not
        # operational" -> xfail per the classification model.
        classify(
            "not_operational",
            label="AES_KEY_WRAP_KWP:key-import",
            summary=not_operational_reason(
                "AES_KEY_WRAP_KWP:key-import",
                ckr_name(exc.rv),
            ),
        )

    # Wycheproof KWP vectors are RFC 5649 raw data vectors.  PKCS#11 exposes
    # that exact operation through CKM_AES_KEY_WRAP_KWP C_Encrypt.
    wrapped = None
    try:
        wrapped = encrypt_single(
            rs.raw,
            rs.sh,
            wrap_key_h,
            CKM_AES_KEY_WRAP_KWP,
            msg,
            output_overhead=16,
        )
    except AssertionError as exc:
        if result == "valid":
            _xfail_if_aes_runtime_reject(exc, f"AES-KWP {vec_id}")
        # acceptable: reject is fine
        return
    finally:
        destroy_quietly(rs.raw, rs.sh, wrap_key_h)

    if result == "valid" and wrapped is not None:
        assert_correct(
            actual=wrapped,
            expected=ct_expected,
            label=f"AES-KWP:C_WrapKey KAT {vec_id}",
            operation="C_WrapKey",
            mechanism="CKM_AES_KEY_WRAP_KWP",
            source=vec.get("_source"),
            vector_id=vec.get("_vector_id"),
        )
    if result == "invalid" and wrapped is not None and wrapped == ct_expected:
        classify(
            "accepted_invalid",
            kind="crypto",
            label="AES-KWP",
            summary=f"AES-KWP wrap {vec_id} produced invalid ciphertext",
            source=vec.get("_source"),
            vector_id=vec.get("_vector_id"),
        )


# --- AES-CCM ---

_AES_CCM_VECTORS = _load_flat("aes_ccm_test.json")


@pytest.mark.parametrize("vec_id,vec", _AES_CCM_VECTORS, ids=[v[0] for v in _AES_CCM_VECTORS])
def test_aes_ccm(p11_module_session: Any, vec_id: str, vec: dict[str, Any]) -> None:
    """AES-CCM AEAD decryption from Wycheproof vectors.

    Decrypts the supplied ct||tag so invalid vectors actually exercise tag
    rejection. A module that decrypts an invalid (forged/modified) ciphertext
    or tag is a crypto-correctness break (-> fail). The previous
    produce-direction (encrypt + compare) could never reject an invalid vector
    because a fresh correct ciphertext never matched the modified expected one.
    """
    rs = p11_module_session
    if not rs.has_mechanism("AES_CCM"):
        pytest.skip("AES_CCM not supported")

    key_bytes = bytes.fromhex(vec["key"])
    iv = bytes.fromhex(vec["iv"])
    aad = bytes.fromhex(vec["aad"])
    msg_expected = bytes.fromhex(vec["msg"])
    ct = bytes.fromhex(vec["ct"])
    tag = bytes.fromhex(vec["tag"])
    result = vec["result"]

    try:
        key = import_secret_key_negotiated(
            rs,
            CKK_AES,
            key_bytes,
            attrs={
                CKA_ENCRYPT: True,
                CKA_DECRYPT: True,
                CKA_TOKEN: False,
                CKA_SENSITIVE: False,
            },
        )
    except AssertionError:
        if result == "invalid":
            return
        raise

    # Decrypt ct||tag and verify
    plaintext = None
    try:
        ccm_param = mech_ccm(
            CKM_AES_CCM,
            iv,
            data_len=len(ct),
            aad=aad if aad else None,
            mac_len=len(tag),
        )
        plaintext = decrypt_single(
            rs.raw,
            rs.sh,
            key,
            CKM_AES_CCM,
            ct + tag,
            mech_param=ccm_param,
        )
    except (AssertionError, TypeError, NotImplementedError) as exc:
        if result == "valid":
            if isinstance(exc, AssertionError):
                # Effect-based (triage H2): a clean decrypt error on a valid CCM
                # vector is classified against the canonical CCM-decrypt probe.
                # Non-operational (bouncyhsm CCM -> GENERAL_ERROR) or an honest
                # clean reject -> xfail; a working probe with WRONG canonical
                # output (a real break) re-raises. The real CCM findings
                # (accepted-invalid, wrong plaintext) are caught below, not here.
                classify_kat_clean_error(
                    exc,
                    result=_ccm_operability(rs, "AES_CCM", "decrypt"),
                    label=f"AES-CCM {vec_id}",
                )
            classify(
                "not_operational",
                label="AES-CCM",
                summary=f"AES-CCM decrypt failed for valid vector {vec_id}: {exc}",
                source=vec.get("_source"),
                vector_id=vec.get("_vector_id"),
            )
        # invalid vector rejected -- genuine only if CCM decrypt actually works.
        # A clean op-reject (AssertionError) on a NOT_OPERATIONAL mechanism is
        # vacuous (the module refuses everything); TypeError/NotImplementedError
        # are not op-rejects and keep returning as before.
        if isinstance(exc, AssertionError):
            xfail_vacuous_reject(
                _ccm_operability(rs, "AES_CCM", "decrypt"),
                label=f"AES-CCM {vec_id} invalid reject",
            )
        return
    finally:
        destroy_quietly(rs.raw, rs.sh, key)

    if result == "valid" and plaintext is not None:
        assert_correct(
            actual=plaintext,
            expected=msg_expected,
            label=f"AES-CCM:C_Decrypt KAT {vec_id}",
            operation="C_Decrypt",
            mechanism="CKM_AES_CCM",
            source=vec.get("_source"),
            vector_id=vec.get("_vector_id"),
        )
    if result == "invalid" and plaintext is not None:
        classify(
            "accepted_invalid",
            kind="crypto",
            label="AES-CCM",
            summary=f"AES-CCM decrypt {vec_id}: accepted invalid ciphertext/tag",
            source=vec.get("_source"),
            vector_id=vec.get("_vector_id"),
        )


# --- AES-GMAC ---

_AES_GMAC_VECTORS = _load_flat("aes_gmac_test.json")


@pytest.mark.parametrize("vec_id,vec", _AES_GMAC_VECTORS, ids=[v[0] for v in _AES_GMAC_VECTORS])
def test_aes_gmac(p11_module_session: Any, vec_id: str, vec: dict[str, Any]) -> None:
    """AES-GMAC (authentication-only GCM) tag verification from Wycheproof vectors.

    GMAC is GCM with empty plaintext - authenticates AAD only. Verifies the
    *supplied* tag with C_Verify so invalid vectors actually exercise
    rejection; an accepted invalid tag is a crypto-correctness break
    (-> fail). The previous produce-direction (C_Sign + compare) could never
    reject an invalid vector.
    """
    rs = p11_module_session
    if not rs.has_mechanism("AES_GMAC"):
        pytest.skip("AES_GMAC not supported")

    key_bytes = bytes.fromhex(vec["key"])
    iv = bytes.fromhex(vec["iv"])
    msg = bytes.fromhex(vec["msg"])  # AAD in GMAC context
    tag_expected = bytes.fromhex(vec["tag"])
    result = vec["result"]

    try:
        key = import_secret_key_negotiated(
            rs,
            CKK_AES,
            key_bytes,
            attrs={
                CKA_SIGN: True,
                CKA_VERIFY: True,
                CKA_TOKEN: False,
                CKA_SENSITIVE: False,
            },
        )
    except AssertionError:
        if result == "invalid":
            return
        raise

    try:
        verified = verify_single(
            rs.raw,
            rs.sh,
            key,
            CKM_AES_GMAC,
            msg,
            tag_expected,
            mech_param=mech_bytes(CKM_AES_GMAC, iv),
        )
    except (AssertionError, TypeError) as exc:
        if result == "valid":
            if isinstance(exc, AssertionError):
                _xfail_if_aes_runtime_reject(exc, f"AES-GMAC {vec_id}")
            classify(
                "not_operational",
                label="AES-GMAC",
                summary=f"AES-GMAC verify failed for valid vector {vec_id}: {exc}",
                source=vec.get("_source"),
                vector_id=vec.get("_vector_id"),
            )
        # acceptable: reject of an invalid vector is fine
        return
    finally:
        destroy_quietly(rs.raw, rs.sh, key)

    if result == "valid" and not verified:
        classify(
            "wrong_result",
            kind="crypto",
            label="AES-GMAC",
            summary=f"AES-GMAC rejected a valid GMAC vector {vec_id}",
            source=vec.get("_source"),
            vector_id=vec.get("_vector_id"),
        )
    if result == "invalid" and verified:
        classify(
            "accepted_invalid",
            kind="crypto",
            label="AES-GMAC",
            summary=f"AES-GMAC {vec_id}: accepted invalid tag (forged tag verified)",
            source=vec.get("_source"),
            vector_id=vec.get("_vector_id"),
        )


# --- AES-XTS ---

_AES_XTS_VECTORS = _load_flat("aes_xts_test.json")


@pytest.mark.parametrize("vec_id,vec", _AES_XTS_VECTORS, ids=[v[0] for v in _AES_XTS_VECTORS])
def test_aes_xts(p11_module_session: Any, vec_id: str, vec: dict[str, Any]) -> None:
    """AES-XTS disk encryption mode from Wycheproof vectors.

    XTS uses a double-size key (e.g. 512 bits = two 256-bit keys)
    and a tweak (IV) for sector-based encryption.
    """
    rs = p11_module_session
    if not rs.has_mechanism("AES_XTS"):
        pytest.skip("AES_XTS not supported")

    key_bytes = bytes.fromhex(vec["key"])
    iv = bytes.fromhex(vec["iv"])
    msg = bytes.fromhex(vec["msg"])
    ct_expected = bytes.fromhex(vec["ct"])
    result = vec["result"]

    # XTS uses AES_XTS key type with double-size key
    try:
        key = import_secret_key_negotiated(
            rs,
            CKK_AES_XTS,
            key_bytes,
            attrs={
                CKA_ENCRYPT: True,
                CKA_DECRYPT: True,
                CKA_TOKEN: False,
                CKA_SENSITIVE: False,
            },
        )
    except (AssertionError, AttributeError) as exc:
        if result == "invalid":
            # Invalid vector: import failure means the operation was never
            # attempted -> vacuous (the invalid input was not evaluated).
            return
        if isinstance(exc, CkrAssertionError):
            # Mechanism was advertised (has_mechanism gate passed above); a
            # negotiation-exhausted import refusal is "advertised but not
            # operational" -> xfail per the classification model.
            classify(
                "not_operational",
                label="AES_XTS:key-import",
                summary=not_operational_reason(
                    "AES_XTS:key-import",
                    ckr_name(exc.rv),
                ),
            )
        raise

    ct = None
    try:
        ct = encrypt_single(
            rs.raw,
            rs.sh,
            key,
            CKM_AES_XTS,
            msg,
            mech_param=mech_bytes(CKM_AES_XTS, iv),
        )
    except (AssertionError, TypeError) as exc:
        if result == "valid":
            if isinstance(exc, AssertionError):
                _xfail_if_aes_runtime_reject(exc, f"AES-XTS {vec_id}")
            classify(
                "not_operational",
                label="AES-XTS",
                summary=f"AES-XTS encrypt failed for valid vector {vec_id}: {exc}",
                source=vec.get("_source"),
                vector_id=vec.get("_vector_id"),
            )
        # acceptable: reject is fine
        return
    finally:
        destroy_quietly(rs.raw, rs.sh, key)

    if result == "valid" and ct is not None:
        assert_correct(
            actual=ct,
            expected=ct_expected,
            label=f"AES-XTS:C_Encrypt KAT {vec_id}",
            operation="C_Encrypt",
            mechanism="CKM_AES_XTS",
            source=vec.get("_source"),
            vector_id=vec.get("_vector_id"),
        )
