"""QC4 policy-effect and malformed-object contracts (#56).

Behavioral contracts for the ALLOWED_MECHANISMS enforcement legs, the
malformed class/type matrix, and the conditional RSA-sign downstream leg:
every production leg is driven through its real test method against a
scriptable fake token at the raw ``C_*`` layer. Fakes only; no provider
is loaded and no Docker is used.

Covered production behavior:

- ``TestAllowedMechanismsDerive`` / ``TestAllowedMechanismsWrap`` /
  ``TestAllowedMechanismsUnwrap`` (QC4a, ``ckr/test_ckr_object.py``) and
  ``TestAllowedMechanismsEncapsulate`` /
  ``TestAllowedMechanismsDecapsulate`` (QC4a, ``ckr/test_ckr_kem.py``):
  per-function PINNED constrained key (derive -> base key, wrap ->
  wrapping key, unwrap -> unwrapping key, encapsulate -> public key,
  decapsulate -> private key); claim-first list readback; included legs
  must succeed where supported with an independently verified effect;
  excluded legs must refuse with the policy-shaped singleton
  (``CKR_KEY_FUNCTION_NOT_PERMITTED``), alternate clean refusals xfail,
  and proved completion fails as policy bypass. Effect verification
  comes in classic single-part and message-based node families with
  separate verdicts (derive/wrap/unwrap only; KEM has no message frame).
- ``TestMalformedObjectCreate`` / ``TestMalformedObjectUnwrap`` /
  ``TestMalformedObjectGenerate`` (QC4b, ``ckr/test_ckr_object.py``):
  Create/Unwrap/Generate x RSA/EC/offered-PQC x class-type swaps and
  missing components. Rejection proves zero inventory delta; acceptance
  inspects the readback identity and uses the material; FAIL only on a
  proved contradiction (usable material under a malformed identity or
  cross-type use). A well-formed same-shape legal control must succeed
  where the operation is supported, else the cell voids as setup-xfail.
- ``TestMalformedRsaSignDownstream`` (QC4c,
  ``ckr/test_ckr_wrong_key_type_hardening.py``): one node per QC4b RSA
  Create malformation. Refused creation skips as inapplicable; admitted
  keys run the RSA-sign path with independent local verification (valid
  signature from a malformed key fails, invalid fails wrong_result,
  clean refusal xfails as defense-in-depth, crashes propagate).
"""

from __future__ import annotations

import ctypes
import sys
from collections.abc import Callable
from types import SimpleNamespace
from typing import Any, TypeVar

import pytest
from _pytest.outcomes import Failed, Skipped, XFailed
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa, utils
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.keywrap import aes_key_unwrap, aes_key_wrap

from pkcs11_check import classification as C  # noqa: N812 - matches project convention
from pkcs11_check._plugin_report_attach import _apply_recorded_outcome
from pkcs11_check.compliance import clear_notes, get_notes
from pkcs11_check.raw.rv import ckr_name
from pkcs11_check.raw.types_std import (
    CKA_ALLOWED_MECHANISMS,
    CKA_CLASS,
    CKA_COEFFICIENT,
    CKA_DECRYPT,
    CKA_EC_PARAMS,
    CKA_EC_POINT,
    CKA_ENCRYPT,
    CKA_EXPONENT_1,
    CKA_EXPONENT_2,
    CKA_EXTRACTABLE,
    CKA_KEY_TYPE,
    CKA_LABEL,
    CKA_MODULUS,
    CKA_MODULUS_BITS,
    CKA_PARAMETER_SET,
    CKA_PRIME_1,
    CKA_PRIME_2,
    CKA_PRIVATE_EXPONENT,
    CKA_PUBLIC_EXPONENT,
    CKA_SENSITIVE,
    CKA_SIGN,
    CKA_TOKEN,
    CKA_UNWRAP,
    CKA_VALUE,
    CKA_VALUE_LEN,
    CKA_VERIFY,
    CKA_WRAP,
    CKK_AES,
    CKK_EC,
    CKK_ML_DSA,
    CKK_ML_KEM,
    CKK_RSA,
    CKK_SLH_DSA,
    CKM_AES_ECB,
    CKM_AES_KEY_WRAP,
    CKM_EC_KEY_PAIR_GEN,
    CKM_ECDSA,
    CKM_ML_DSA,
    CKM_ML_DSA_KEY_PAIR_GEN,
    CKM_ML_KEM,
    CKM_ML_KEM_KEY_PAIR_GEN,
    CKM_RSA_PKCS,
    CKM_RSA_PKCS_KEY_PAIR_GEN,
    CKM_SHA256_RSA_PKCS,
    CKM_SLH_DSA,
    CKM_SLH_DSA_KEY_PAIR_GEN,
    CKO_PRIVATE_KEY,
    CKO_PUBLIC_KEY,
    CKO_SECRET_KEY,
    CKP_ML_DSA_44,
    CKP_ML_DSA_65,
    CKP_ML_DSA_87,
    CKP_ML_KEM_768,
    CKP_SLH_DSA_SHA2_128S,
    CKR_ACTION_PROHIBITED,
    CKR_ARGUMENTS_BAD,
    CKR_ATTRIBUTE_SENSITIVE,
    CKR_ATTRIBUTE_TYPE_INVALID,
    CKR_BUFFER_TOO_SMALL,
    CKR_DATA_LEN_RANGE,
    CKR_DEVICE_ERROR,
    CKR_ENCRYPTED_DATA_LEN_RANGE,
    CKR_FUNCTION_FAILED,
    CKR_FUNCTION_NOT_SUPPORTED,
    CKR_KEY_FUNCTION_NOT_PERMITTED,
    CKR_KEY_TYPE_INCONSISTENT,
    CKR_MECHANISM_INVALID,
    CKR_OK,
    CKR_OPERATION_NOT_INITIALIZED,
    CKR_SIGNATURE_INVALID,
    CKR_TEMPLATE_INCOMPLETE,
    CKR_TEMPLATE_INCONSISTENT,
    CKR_USER_NOT_LOGGED_IN,
)
from pkcs11_check.testcases.ckr import test_ckr_kem as tkem
from pkcs11_check.testcases.ckr import test_ckr_object as tobj
from pkcs11_check.testcases.ckr import test_ckr_wrong_key_type_hardening as twrong
from tests._skip_assert import assert_skips, assert_xfails

_T = TypeVar("_T")

_OK = int(CKR_OK)
_SENSITIVE_RV = int(CKR_ATTRIBUTE_SENSITIVE)
_TYPE_INVALID = int(CKR_ATTRIBUTE_TYPE_INVALID)
_NOT_SUPPORTED = int(CKR_FUNCTION_NOT_SUPPORTED)
_DEVICE_ERROR = int(CKR_DEVICE_ERROR)
_FUNCTION_FAILED = int(CKR_FUNCTION_FAILED)
_MECHANISM_INVALID = int(CKR_MECHANISM_INVALID)
_KEY_NOT_PERMITTED = int(CKR_KEY_FUNCTION_NOT_PERMITTED)
_KEY_TYPE_INCONSISTENT = int(CKR_KEY_TYPE_INCONSISTENT)
_TEMPLATE_INCOMPLETE = int(CKR_TEMPLATE_INCOMPLETE)
_TEMPLATE_INCONSISTENT = int(CKR_TEMPLATE_INCONSISTENT)
_ARGUMENTS_BAD = int(CKR_ARGUMENTS_BAD)
_ACTION_PROHIBITED = int(CKR_ACTION_PROHIBITED)
_SIGNATURE_INVALID = int(CKR_SIGNATURE_INVALID)
_BUFFER_TOO_SMALL = int(CKR_BUFFER_TOO_SMALL)
_OP_NOT_INITIALIZED = int(CKR_OPERATION_NOT_INITIALIZED)
_NOT_LOGGED_IN = int(CKR_USER_NOT_LOGGED_IN)
_DATA_LEN_RANGE = int(CKR_DATA_LEN_RANGE)
_ENC_DATA_LEN_RANGE = int(CKR_ENCRYPTED_DATA_LEN_RANGE)
_UNDEFINED_RV = 0x7FFFFFFF
_VENDOR_RV = 0x80000001
_U64 = 0xFFFFFFFFFFFFFFFF

_AES_ECB = int(CKM_AES_ECB)
_AES_KW = int(CKM_AES_KEY_WRAP)
_RSA_PKCS = int(CKM_RSA_PKCS)
_RSA_PKCS_SIGN = int(CKM_SHA256_RSA_PKCS)
_ECDSA = int(CKM_ECDSA)
_ML_KEM = int(CKM_ML_KEM)
_ML_DSA = int(CKM_ML_DSA)
_SLH_DSA = int(CKM_SLH_DSA)

_KEM_CT_LEN = 1088
_KEM_SECRET_LEN = 32
_ML_DSA_65_PUB_LEN = 1952
_ML_DSA_65_SIG_LEN = 3309
_SLH_DSA_128S_PUB_LEN = 32

_P256_PARAMS = bytes.fromhex("06082a8648ce3d030107")

_BOOL_ATTRS = frozenset(
    {
        int(CKA_SENSITIVE),
        int(CKA_EXTRACTABLE),
        int(CKA_ENCRYPT),
        int(CKA_DECRYPT),
        int(CKA_WRAP),
        int(CKA_UNWRAP),
        int(CKA_TOKEN),
    }
)
_ULONG_ATTRS = frozenset(
    {
        int(CKA_CLASS),
        int(CKA_KEY_TYPE),
        int(CKA_VALUE_LEN),
        int(CKA_MODULUS_BITS),
        int(CKA_PARAMETER_SET),
    }
)
_ARRAY_ATTRS = frozenset({int(CKA_ALLOWED_MECHANISMS)})

#: Effect-object roles whose control twin is distinguished by label (F5):
#: a stored object whose CKA_LABEL contains "control" is filed under
#: "<role>-control", so per-role hooks seed the main and control effect
#: legs independently. Setup roles (create/keypair) are never suffixed.
_EFFECT_ROLES = frozenset({"derive", "unwrap", "encaps", "decaps"})

#: Key/secret blobs the fake minted or handled in the current test (F16).
#: The hygiene gate asserts every encoding of each blob (repr forms, decoded
#: text, hex) is absent from all classification records.
_MINTED_BLOBS: list[bytes] = []


def _register_minted_blob(blob: bytes) -> None:
    """Record a fake-handled blob for the F16 hygiene gate."""
    _MINTED_BLOBS.append(bytes(blob))


@pytest.fixture(autouse=True)
def _isolated() -> Any:
    C.clear()
    clear_notes()
    del _MINTED_BLOBS[:]
    yield
    C.clear()
    clear_notes()
    del _MINTED_BLOBS[:]


_SAVED_NONCE_FACTORY: Any = None


@pytest.fixture(autouse=True)
def _fixed_label_nonce(monkeypatch: pytest.MonkeyPatch) -> Any:
    """Deterministic attempt labels (F12): production nonces them per call."""
    global _SAVED_NONCE_FACTORY
    mod = _policy_module()
    original = getattr(mod, "_LABEL_NONCE_FACTORY", None)
    if original is None:
        yield
        return
    _SAVED_NONCE_FACTORY = original
    monkeypatch.setattr(mod, "_LABEL_NONCE_FACTORY", lambda: "t")
    yield


def _fill_ulong(out: Any, value: int) -> None:
    """Write an out-scalar passed as ``byref(ctypes_scalar)``."""
    ctypes.cast(out, ctypes.POINTER(ctypes.c_ulong)).contents.value = value


def _decode_template(tmpl: Any, count: int) -> dict[int, bytes]:
    """Decode a captured template ptr + count into {attr_type: raw bytes}."""
    decoded: dict[int, bytes] = {}
    if tmpl is None or count == 0:
        return decoded
    for i in range(count):
        atype = int(tmpl[i].type)
        alen = int(tmpl[i].ulValueLen)
        addr = tmpl[i].pValue
        decoded[atype] = bytes(ctypes.string_at(addr, alen)) if addr and alen > 0 else b""
    return decoded


def _decode_bool(raw: bytes) -> bool:
    assert len(raw) == 1, raw
    return raw[0] != 0


def _decode_ulong(raw: bytes) -> int:
    return int.from_bytes(raw, sys.byteorder)


def _decode_array(raw: bytes) -> list[int]:
    width = ctypes.sizeof(ctypes.c_ulong)
    assert len(raw) % width == 0, raw
    return [int.from_bytes(raw[i : i + width], sys.byteorder) for i in range(0, len(raw), width)]


def _encode_value(attr: int, value: Any) -> bytes:
    if attr in _BOOL_ATTRS:
        return b"\x01" if value else b"\x00"
    if attr in _ULONG_ATTRS:
        return int(value).to_bytes(ctypes.sizeof(ctypes.c_ulong), sys.byteorder)
    if attr in _ARRAY_ATTRS:
        width = ctypes.sizeof(ctypes.c_ulong)
        return b"".join(int(v).to_bytes(width, sys.byteorder) for v in value)
    if isinstance(value, str):
        return value.encode("utf-8")
    assert isinstance(value, bytes), (attr, value)
    return value


def _decode_mech(mech: Any) -> tuple[int, bytes]:
    ck = mech._obj
    addr = ck.pParameter
    length = int(ck.ulParameterLen)
    param = bytes(ctypes.string_at(addr, length)) if addr and length > 0 else b""
    return int(ck.mechanism), param


class _CkStringData(ctypes.Structure):
    _fields_ = [("pData", ctypes.c_void_p), ("ulLen", ctypes.c_ulong)]


def _decode_string_data_param(mech: Any) -> tuple[int, bytes]:
    """Decode a CK_KEY_DERIVATION_STRING_DATA mechanism parameter (derive mechs)."""
    ck = mech._obj
    struct_bytes = bytes(ctypes.string_at(ck.pParameter, ctypes.sizeof(_CkStringData)))
    parsed = _CkStringData.from_buffer_copy(struct_bytes)
    data = bytes(ctypes.string_at(parsed.pData, parsed.ulLen))
    return int(ck.mechanism), data


class _StoredObject:
    """One fake-token object: decoded attributes plus crypto behavior."""

    def __init__(self, attrs: dict[int, Any], *, role: str) -> None:
        self.attrs = attrs
        self.role = role
        self.destroyed = False


class _PolicyFake:
    """Scriptable fake token for the QC4 policy/malformed/downstream legs.

    Per-call scripts select uniform RVs (``None`` entries — or an exhausted
    script — mean healthy behavior). Output scripts override healthy crypto
    outputs exactly. Label-gated hooks (``leak_labeled``,
    ``extra_for_label``) apply to the malformed-attempt call without
    positional coupling to the setup-call count.
    """

    # noqa comments below: raw PKCS#11 entry-point names are mandated.

    def __init__(
        self,
        *,
        probe_rv: int = _TEMPLATE_INCOMPLETE,
        create_script: list[int | None] | None = None,
        create_refuse_key_type: dict[int, int] | None = None,
        create_refuse_bool_attr: dict[int, int] | None = None,
        enforce_rsa_encrypt_permission: bool = False,
        find_page_cap: int | None = None,
        sentinel_ok_label: bytes | None = None,
        leak_labeled: bytes | None = None,
        leak_unlabeled: bytes | None = None,
        foreign_delta_for_label: bytes | None = None,
        refusal_out_handle: int | None = None,
        extra_for_label: bytes | None = None,
        extra_attrs: dict[int, Any] | None = None,
        keypair_pub_extra: dict[int, Any] | None = None,
        keypair_priv_extra: dict[int, Any] | None = None,
        keypair_script: list[int | None] | None = None,
        find_fail: dict[int, tuple[str, int]] | None = None,
        derive_script: list[int | None] | None = None,
        derive_value: bytes | None = None,
        derive_value_for: dict[str, bytes] | None = None,
        wrap_script: list[int | None] | None = None,
        wrap_blob: bytes | None = None,
        wrap_blob_for: dict[int, bytes] | None = None,
        unwrap_script: list[int | None] | None = None,
        unwrap_value: bytes | None = None,
        unwrap_value_for: dict[str, bytes] | None = None,
        encaps_script: list[int | None] | None = None,
        encaps_ct: bytes | None = None,
        encaps_secret: bytes | None = None,
        encaps_ct_for: dict[str, bytes] | None = None,
        encaps_secret_for: dict[str, bytes] | None = None,
        decaps_script: list[int | None] | None = None,
        decaps_secret: bytes | None = None,
        decaps_secret_for: dict[str, bytes] | None = None,
        destroy_script: list[BaseException | None] | None = None,
        get_attr_script: list[int | None] | None = None,
        hide: set[int] | None = None,
        hide_for: dict[str, set[int]] | None = None,
        raw_readback: dict[tuple[str, int], bytes] | None = None,
        contradict_readback: dict[tuple[bytes, int], tuple[int, bytes]] | None = None,
        encrypt_rv: dict[tuple[str, int], int] | None = None,
        decrypt_rv: dict[tuple[str, int], int] | None = None,
        encrypt_output_for: dict[tuple[str, int], bytes] | None = None,
        decrypt_output_for: dict[tuple[str, int], bytes] | None = None,
        decrypt_corrupt: bool = False,
        message_supported: bool = True,
        message_encrypt_rv: dict[tuple[str, int], int] | None = None,
        message_decrypt_rv: dict[tuple[str, int], int] | None = None,
        message_encrypt_output_for: dict[tuple[str, int], bytes] | None = None,
        message_decrypt_output_for: dict[tuple[str, int], bytes] | None = None,
        sign_init_script: list[int | None] | None = None,
        sign_script: list[int | None] | None = None,
        sign_output: bytes | None = None,
        sign_raise: BaseException | None = None,
        sign_key: str | None = None,
        verify_script: list[int | None] | None = None,
    ) -> None:
        self._probe_rv = probe_rv
        self._create_script = list(create_script or [])
        self._create_refuse_key_type = dict(create_refuse_key_type or {})
        self._create_refuse_bool_attr = dict(create_refuse_bool_attr or {})
        self._enforce_rsa_encrypt_permission = enforce_rsa_encrypt_permission
        self._find_page_cap = find_page_cap
        self._sentinel_ok_label = sentinel_ok_label
        self.find_pages: list[int] = []
        self._leak_labeled = leak_labeled
        self._leak_unlabeled = leak_unlabeled
        self._foreign_delta_for_label = foreign_delta_for_label
        self.foreign_delta_handle: int | None = None
        self._refusal_out_handle = refusal_out_handle
        self._extra_for_label = extra_for_label
        self._extra_attrs = dict(extra_attrs or {})
        self._keypair_pub_extra = dict(keypair_pub_extra or {})
        self._keypair_priv_extra = dict(keypair_priv_extra or {})
        self._keypair_script = list(keypair_script or [])
        self._find_fail = dict(find_fail or {})
        self._derive_script = list(derive_script or [])
        self._derive_value = derive_value
        self._derive_value_for = dict(derive_value_for or {})
        self._wrap_script = list(wrap_script or [])
        self._wrap_blob = wrap_blob
        self._wrap_blob_for = dict(wrap_blob_for or {})
        self._wrap_op_count = 0
        self._wrap_blob_pending: bytes | None = None
        self._unwrap_script = list(unwrap_script or [])
        self._unwrap_value = unwrap_value
        self._unwrap_value_for = dict(unwrap_value_for or {})
        self._encaps_script = list(encaps_script or [])
        self._encaps_ct = encaps_ct
        self._encaps_secret = encaps_secret
        self._encaps_ct_for = dict(encaps_ct_for or {})
        self._encaps_secret_for = dict(encaps_secret_for or {})
        self._decaps_script = list(decaps_script or [])
        self._decaps_secret = decaps_secret
        self._decaps_secret_for = dict(decaps_secret_for or {})
        self._destroy_script = list(destroy_script or [])
        self._get_attr_script = list(get_attr_script or [])
        self._hide = set(hide or ())
        self._hide_for = {role: set(attrs) for role, attrs in (hide_for or {}).items()}
        self._raw_readback = dict(raw_readback or {})
        self._contradict_readback = dict(contradict_readback or {})
        self.get_attr_calls = 0
        self._encrypt_rv = dict(encrypt_rv or {})
        self._decrypt_rv = dict(decrypt_rv or {})
        self._encrypt_output_for = dict(encrypt_output_for or {})
        self._decrypt_output_for = dict(decrypt_output_for or {})
        self._decrypt_corrupt = decrypt_corrupt
        self._message_supported = message_supported
        self._message_encrypt_rv = dict(message_encrypt_rv or {})
        self._message_decrypt_rv = dict(message_decrypt_rv or {})
        self._message_encrypt_output_for = dict(message_encrypt_output_for or {})
        self._message_decrypt_output_for = dict(message_decrypt_output_for or {})
        self._sign_init_script = list(sign_init_script or [])
        self._sign_script = list(sign_script or [])
        self._pqc_issued: set[tuple[int, bytes, bytes]] = set()
        self._sign_output = sign_output
        self._sign_raise = sign_raise
        self._sign_key = sign_key
        self._verify_script = list(verify_script or [])
        self._next_handle = 100
        self.objects: dict[int, _StoredObject] = {}
        self.created: list[int] = []
        self.destroyed: list[int] = []
        self.destroy_calls: list[int] = []
        self.create_templates: list[dict[int, bytes]] = []
        self.keypair_calls: list[tuple[dict[int, bytes], dict[int, bytes]]] = []
        self.derive_calls: list[tuple[int, bytes]] = []
        self.unwrap_calls: list[dict[int, bytes]] = []
        self._rsa_key: Any = None
        self._ec_key: Any = None
        self._rsa_handles: set[int] = set()
        self._ec_handles: set[int] = set()
        self._pqc_handles: dict[int, str] = {}
        self._enc_op: tuple[int, int, bytes, bytes, str] | None = None
        self._dec_op: tuple[int, int, bytes, bytes, str] | None = None
        self._msg_enc_op: tuple[int, int, bytes, str] | None = None
        self._msg_dec_op: tuple[int, int, bytes, str] | None = None
        self._sign_op: tuple[int, int] | None = None
        self._verify_op: tuple[int, int] | None = None
        self._find_seq = 0
        self._find_offset = 0
        self._find_search: bytes | None = None
        self._find_all = False

    # -- key material --------------------------------------------------------

    def _ensure_rsa(self) -> Any:
        if self._rsa_key is None:
            self._rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        return self._rsa_key

    def rsa_numbers(self) -> tuple[bytes, bytes]:
        """Public halves of the fake's cached RSA key (tests seed readbacks)."""
        numbers = self._ensure_rsa().public_key().public_numbers()
        modulus = int(numbers.n).to_bytes(256, "big")
        exp_len = (int(numbers.e).bit_length() + 7) // 8
        return modulus, int(numbers.e).to_bytes(exp_len, "big")

    def _ensure_ec(self) -> Any:
        if self._ec_key is None:
            self._ec_key = ec.generate_private_key(ec.SECP256R1())
        return self._ec_key

    def ec_point_der(self) -> bytes:
        """DER OCTET STRING wrapping the fake EC key's uncompressed point."""
        numbers = self._ensure_ec().public_key().public_numbers()
        raw = b"\x04" + int(numbers.x).to_bytes(32, "big") + int(numbers.y).to_bytes(32, "big")
        assert len(raw) == 65
        return b"\x04\x41" + raw

    def raw_ecdsa_over(self, digest: bytes) -> bytes:
        """Independent raw ECDSA (Prehashed) signature for seeding oracle checks."""
        key = self._ensure_ec()
        der = key.sign(digest, ec.ECDSA(utils.Prehashed(hashes.SHA256())))
        r, s = utils.decode_dss_signature(der)
        return int(r).to_bytes(32, "big") + int(s).to_bytes(32, "big")

    def rsa_private_components(self) -> dict[int, bytes]:
        """Decoded private components of the fake RSA key for seeding readback."""
        numbers = self._ensure_rsa().private_numbers()

        def blob(value: int) -> bytes:
            return int(value).to_bytes((int(value).bit_length() + 7) // 8, "big")

        pub = numbers.public_numbers
        return {
            int(CKA_MODULUS): blob(pub.n),
            int(CKA_PUBLIC_EXPONENT): blob(pub.e),
            int(CKA_PRIVATE_EXPONENT): blob(numbers.d),
            int(CKA_PRIME_1): blob(numbers.p),
            int(CKA_PRIME_2): blob(numbers.q),
            int(CKA_EXPONENT_1): blob(numbers.dmp1),
            int(CKA_EXPONENT_2): blob(numbers.dmq1),
            int(CKA_COEFFICIENT): blob(numbers.iqmp),
        }

    def ec_private_scalar(self) -> bytes:
        """The fake EC key's private scalar for seeding readback (F10)."""
        value = self._ensure_ec().private_numbers().private_value
        return int(value).to_bytes(32, "big")

    # -- storage --------------------------------------------------------------

    def _issue(self) -> int:
        handle = self._next_handle
        self._next_handle += 1
        return handle

    def _store(self, attrs: dict[int, Any], *, role: str) -> int:
        value = attrs.get(int(CKA_VALUE))
        if isinstance(value, bytes):
            _register_minted_blob(value)
        if role in _EFFECT_ROLES:
            label = self._label_of(attrs)
            if label is not None and b"control" in label:
                role = f"{role}-control"
        handle = self._issue()
        self.objects[handle] = _StoredObject(attrs, role=role)
        self.created.append(handle)
        return handle

    def plant_litter(self, label: bytes, count: int) -> None:
        """Pre-existing objects carrying *label* (F12 inventory baseline)."""
        for _ in range(count):
            self._store({int(CKA_LABEL): label}, role="create")

    def _effect_role(self, attrs: dict[int, Any], base: str) -> str:
        """The filing role for an effect object about to be stored (F5)."""
        label = self._label_of(attrs)
        if label is not None and b"control" in label:
            return f"{base}-control"
        return base

    @staticmethod
    def _decoded_value(attr: int, raw: bytes) -> Any:
        if attr in _BOOL_ATTRS:
            return _decode_bool(raw)
        if attr in _ULONG_ATTRS:
            return _decode_ulong(raw)
        if attr in _ARRAY_ATTRS:
            return _decode_array(raw)
        return raw

    def _template_attrs(self, raw_attrs: dict[int, bytes]) -> dict[int, Any]:
        return {attr: self._decoded_value(attr, blob) for attr, blob in raw_attrs.items()}

    def _label_of(self, attrs: dict[int, Any]) -> bytes | None:
        label = attrs.get(int(CKA_LABEL))
        if isinstance(label, str):
            return label.encode("utf-8")
        return label

    def _maybe_leak(self, attrs: dict[int, Any], *, role: str) -> None:
        if self._leak_labeled is not None and self._label_of(attrs) == self._leak_labeled:
            handle = self._store(dict(attrs), role=role)
            if role == "keypair-pub":
                self._rsa_handles.add(handle)

    def _maybe_leak_unlabeled(self, attrs: dict[int, Any], *, role: str) -> int | None:
        """Refused creation that still creates, but drops CKA_LABEL (PR64 P2)."""
        if self._leak_unlabeled is None or self._label_of(attrs) != self._leak_unlabeled:
            return None
        dropped = dict(attrs)
        dropped.pop(int(CKA_LABEL), None)
        return self._store(dropped, role=role)

    def _maybe_foreign_delta(self, attrs: dict[int, Any]) -> None:
        """Plant an unrelated token object during the refused attempt (R1)."""
        if self._foreign_delta_for_label is None or self._label_of(attrs) != (
            self._foreign_delta_for_label
        ):
            return
        foreign = {
            int(CKA_LABEL): "foreign-delta",
            int(CKA_TOKEN): True,
            int(CKA_CLASS): int(CKO_PRIVATE_KEY),
            int(CKA_KEY_TYPE): int(CKK_AES),
        }
        self.foreign_delta_handle = self._store(foreign, role="foreign")

    def _apply_extra(self, attrs: dict[int, Any]) -> None:
        if self._extra_for_label is not None and self._label_of(attrs) == self._extra_for_label:
            attrs.update(self._extra_attrs)

    def _pop(self, script: list[_T]) -> _T | None:
        return script.pop(0) if script else None

    # -- object management -----------------------------------------------------

    def C_CreateObject(self, _sh: int, tmpl: Any, count: int, out: Any) -> int:  # noqa: N802
        if tmpl is None and count == 0:
            return self._probe_rv
        raw_attrs = _decode_template(tmpl, count)
        self.create_templates.append(raw_attrs)
        attrs = self._template_attrs(raw_attrs)
        scripted = self._pop(self._create_script)
        if scripted is not None:
            self._maybe_leak(attrs, role="create")
            leaked = self._maybe_leak_unlabeled(attrs, role="create")
            self._maybe_foreign_delta(attrs)
            if leaked is not None:
                _fill_ulong(out, leaked)
            if self._refusal_out_handle is not None:
                _fill_ulong(out, self._refusal_out_handle)
            return scripted
        # Content-based capability gap (F7): refuse creates of a key type the
        # module does not support. Scripts take precedence when non-None.
        key_type: Any = attrs.get(int(CKA_KEY_TYPE))
        type_refusal = self._create_refuse_key_type.get(key_type, None)
        if type_refusal is not None and type_refusal != _OK:
            return type_refusal
        # Permission-dependent import refusal (N4): refuse any template
        # carrying the seeded usage attribute as CK_TRUE.
        for bool_attr, bool_rv in self._create_refuse_bool_attr.items():
            if raw_attrs.get(bool_attr) == b"\x01":
                return bool_rv
        self._apply_extra(attrs)
        handle = self._store(attrs, role="create")
        _fill_ulong(out, handle)
        return _OK

    def C_GenerateKeyPair(  # noqa: N802
        self,
        _sh: int,
        mech: Any,
        pub_tmpl: Any,
        pub_count: int,
        priv_tmpl: Any,
        priv_count: int,
        pub_out: Any,
        priv_out: Any,
    ) -> int:
        mech_id, _ = _decode_mech(mech)
        pub_raw = _decode_template(pub_tmpl, pub_count) if pub_count else {}
        priv_raw = _decode_template(priv_tmpl, priv_count) if priv_count else {}
        self.keypair_calls.append((pub_raw, priv_raw))
        scripted = self._pop(self._keypair_script)
        pub_attrs = self._template_attrs(pub_raw)
        priv_attrs = self._template_attrs(priv_raw)
        if scripted is not None:
            self._maybe_leak(pub_attrs, role="keypair-pub")
            self._maybe_leak(priv_attrs, role="keypair-priv")
            leaked_pub = self._maybe_leak_unlabeled(pub_attrs, role="keypair-pub")
            leaked_priv = self._maybe_leak_unlabeled(priv_attrs, role="keypair-priv")
            # Real key objects always expose CKA_CLASS/CKA_KEY_TYPE; the
            # raw leaked templates may omit them (priv halves especially).
            _type_by_gen = {
                int(CKM_RSA_PKCS_KEY_PAIR_GEN): int(CKK_RSA),
                int(CKM_EC_KEY_PAIR_GEN): int(CKK_EC),
                int(CKM_ML_DSA_KEY_PAIR_GEN): int(CKK_ML_DSA),
                int(CKM_SLH_DSA_KEY_PAIR_GEN): int(CKK_SLH_DSA),
                int(CKM_ML_KEM_KEY_PAIR_GEN): int(CKK_ML_KEM),
            }
            for leaked, obj_class in (
                (leaked_pub, int(CKO_PUBLIC_KEY)),
                (leaked_priv, int(CKO_PRIVATE_KEY)),
            ):
                if leaked is not None:
                    leaked_attrs = self.objects[leaked].attrs
                    leaked_attrs.setdefault(int(CKA_CLASS), obj_class)
                    if mech_id in _type_by_gen:
                        leaked_attrs.setdefault(int(CKA_KEY_TYPE), _type_by_gen[mech_id])
            self._maybe_foreign_delta(pub_attrs)
            if leaked_pub is not None:
                _fill_ulong(pub_out, leaked_pub)
            if leaked_priv is not None:
                _fill_ulong(priv_out, leaked_priv)
            return scripted
        rsa_gen = int(CKM_RSA_PKCS_KEY_PAIR_GEN)
        ec_gen = int(CKM_EC_KEY_PAIR_GEN)
        mldsa_gen = int(CKM_ML_DSA_KEY_PAIR_GEN)
        slhdsa_gen = int(CKM_SLH_DSA_KEY_PAIR_GEN)
        mlkem_gen = int(CKM_ML_KEM_KEY_PAIR_GEN)
        if mech_id == rsa_gen:
            modulus, exponent = self.rsa_numbers()
            pub_attrs.update(
                {
                    int(CKA_CLASS): int(CKO_PUBLIC_KEY),
                    int(CKA_KEY_TYPE): int(CKK_RSA),
                    int(CKA_MODULUS): modulus,
                    int(CKA_PUBLIC_EXPONENT): exponent,
                }
            )
            priv_attrs.update(
                {
                    int(CKA_CLASS): int(CKO_PRIVATE_KEY),
                    int(CKA_KEY_TYPE): int(CKK_RSA),
                    int(CKA_MODULUS): modulus,
                    int(CKA_PUBLIC_EXPONENT): exponent,
                }
            )
        elif mech_id == ec_gen:
            pub_attrs.update(
                {
                    int(CKA_CLASS): int(CKO_PUBLIC_KEY),
                    int(CKA_KEY_TYPE): int(CKK_EC),
                    int(CKA_EC_PARAMS): _P256_PARAMS,
                    int(CKA_EC_POINT): self.ec_point_der(),
                }
            )
            priv_attrs.update(
                {
                    int(CKA_CLASS): int(CKO_PRIVATE_KEY),
                    int(CKA_KEY_TYPE): int(CKK_EC),
                    int(CKA_EC_PARAMS): _P256_PARAMS,
                }
            )
        elif mech_id == mlkem_gen:
            pub_attrs.update(
                {
                    int(CKA_CLASS): int(CKO_PUBLIC_KEY),
                    int(CKA_KEY_TYPE): int(CKK_ML_KEM),
                    int(CKA_PARAMETER_SET): int(CKP_ML_KEM_768),
                }
            )
            priv_attrs.update(
                {
                    int(CKA_CLASS): int(CKO_PRIVATE_KEY),
                    int(CKA_KEY_TYPE): int(CKK_ML_KEM),
                    int(CKA_PARAMETER_SET): int(CKP_ML_KEM_768),
                }
            )
        elif mech_id in (mldsa_gen, slhdsa_gen):
            key_type = int(CKK_ML_DSA) if mech_id == mldsa_gen else int(CKK_SLH_DSA)
            pub_len = _ML_DSA_65_PUB_LEN if mech_id == mldsa_gen else _SLH_DSA_128S_PUB_LEN
            pub_attrs.update(
                {
                    int(CKA_CLASS): int(CKO_PUBLIC_KEY),
                    int(CKA_KEY_TYPE): key_type,
                    int(CKA_VALUE): bytes(
                        [(self._next_handle + i) % 251 + 1 for i in range(pub_len)]
                    ),
                }
            )
            priv_attrs.update(
                {
                    int(CKA_CLASS): int(CKO_PRIVATE_KEY),
                    int(CKA_KEY_TYPE): key_type,
                }
            )
        else:
            raise AssertionError(f"fake keygen cannot serve mechanism {mech_id:#x}")
        self._apply_extra(pub_attrs)
        self._apply_extra(priv_attrs)
        # Role-specific readback overrides (F10): generate legs run exactly
        # one keygen, so these apply unconditionally to the attempt halves.
        if self._keypair_pub_extra:
            pub_attrs.update(self._keypair_pub_extra)
        if self._keypair_priv_extra:
            priv_attrs.update(self._keypair_priv_extra)
        pub_handle = self._store(pub_attrs, role="keypair")
        priv_handle = self._store(priv_attrs, role="keypair")
        if mech_id == rsa_gen:
            self._rsa_handles.add(pub_handle)
            self._rsa_handles.add(priv_handle)
        elif mech_id == ec_gen:
            self._ec_handles.add(pub_handle)
            self._ec_handles.add(priv_handle)
        else:
            tag = "ml-dsa" if mech_id == mldsa_gen else "slh-dsa"
            self._pqc_handles[pub_handle] = tag
            self._pqc_handles[priv_handle] = tag
        _fill_ulong(pub_out, pub_handle)
        _fill_ulong(priv_out, priv_handle)
        return _OK

    def C_DestroyObject(self, _sh: int, handle: int) -> int:  # noqa: N802
        self.destroy_calls.append(int(handle))
        scripted = self._pop(self._destroy_script)
        if scripted is not None:
            raise scripted
        stored = self.objects.get(int(handle))
        if stored is not None:
            stored.destroyed = True
        self.destroyed.append(int(handle))
        return _OK

    def C_GetAttributeValue(self, _sh: int, handle: int, tmpl: Any, count: int) -> int:  # noqa: N802
        self.get_attr_calls += 1
        scripted = self._pop(self._get_attr_script)
        if scripted is not None:
            return scripted
        stored = self.objects.get(int(handle))
        assert stored is not None, f"read from unknown handle {handle}"
        row_rvs: list[int] = []
        for i in range(count):
            attr = int(tmpl[i].type)
            cap = int(tmpl[i].ulValueLen)
            addr = tmpl[i].pValue
            if (
                self._sentinel_ok_label is not None
                and self._label_of(stored.attrs) == self._sentinel_ok_label
                and attr == int(CKA_ALLOWED_MECHANISMS)
            ):
                # CKR_OK + CK_UNAVAILABLE_INFORMATION sentinel (N9):
                # success claimed, no value delivered.
                tmpl[i].ulValueLen = _U64
                row_rvs.append(_OK)
                continue
            contradiction = self._contradict_readback.get(
                (self._label_of(stored.attrs) or b"", attr)
            )
            if contradiction is not None:
                # Refusal-with-data (G0): the module answers a refusal CKR
                # but still writes real bytes with a real length (never the
                # CK_UNAVAILABLE_INFORMATION sentinel).
                leak_ckr, leak_blob = contradiction
                if addr:
                    ctypes.memmove(addr, leak_blob, min(len(leak_blob), cap))
                tmpl[i].ulValueLen = len(leak_blob)
                row_rvs.append(leak_ckr)
                continue
            blob = self._raw_readback.get((stored.role, attr))
            if blob is not None:
                if addr:
                    ctypes.memmove(addr, blob, min(len(blob), cap))
                tmpl[i].ulValueLen = len(blob)
                row_rvs.append(_OK)
                continue
            value = stored.attrs.get(attr)
            if attr in self._hide or attr in self._hide_for.get(stored.role, ()) or value is None:
                rv, length, fill = _TYPE_INVALID, _U64, None
            elif attr == int(CKA_VALUE) and (
                stored.attrs.get(int(CKA_SENSITIVE), False) is True
                or stored.attrs.get(int(CKA_EXTRACTABLE), True) is False
            ):
                rv, length, fill = _SENSITIVE_RV, _U64, None
            else:
                blob = _encode_value(attr, value)
                rv, length, fill = _OK, len(blob), blob
            if fill is not None and addr:
                ctypes.memmove(addr, fill, min(len(fill), cap))
            tmpl[i].ulValueLen = length
            row_rvs.append(rv)
        if _SENSITIVE_RV in row_rvs:
            return _SENSITIVE_RV
        if _TYPE_INVALID in row_rvs:
            return _TYPE_INVALID
        return _OK

    def C_FindObjectsInit(self, _sh: int, tmpl: Any, count: int) -> int:  # noqa: N802
        self._find_seq += 1
        fail = self._find_fail.get(self._find_seq)
        if fail is not None and fail[0] == "init":
            return fail[1]
        decoded = _decode_template(tmpl, count) if count else {}
        # An empty template matches every live object (full inventory, P2);
        # a non-empty template keeps the label-filtered semantics.
        self._find_all = count == 0
        self._find_search = decoded.get(int(CKA_LABEL))
        self._find_offset = 0
        return _OK

    def C_FindObjects(self, _sh: int, handles: Any, max_count: int, out_count: Any) -> int:  # noqa: N802
        fail = self._find_fail.get(self._find_seq)
        if fail is not None and fail[0] == "find":
            return fail[1]
        matched = [
            handle
            for handle, stored in self.objects.items()
            if not stored.destroyed
            and (self._find_all or self._label_of(stored.attrs) == self._find_search)
        ]
        # Paged cursor (F12): each call continues where the previous stopped.
        # An optional page cap (N6) models a provider returning fewer
        # handles than requested on intermediate pages (§5.7.8 maximum).
        limit = max_count if self._find_page_cap is None else min(max_count, self._find_page_cap)
        page = matched[self._find_offset : self._find_offset + limit]
        self.find_pages.append(len(page))
        self._find_offset += len(page)
        for i, handle in enumerate(page):
            handles[i] = handle
        _fill_ulong(out_count, len(page))
        return _OK

    def C_FindObjectsFinal(self, _sh: int) -> int:  # noqa: N802
        fail = self._find_fail.get(self._find_seq)
        if fail is not None and fail[0] == "final":
            return fail[1]
        self._find_search = None
        return _OK

    def C_SessionCancel(self, _sh: int, _flags: int) -> int:  # noqa: N802
        return _OK

    # -- key management --------------------------------------------------------

    def C_DeriveKey(  # noqa: N802
        self, _sh: int, mech: Any, base: int, tmpl: Any, count: int, out: Any
    ) -> int:
        _mech_id, param = _decode_string_data_param(mech)
        self.derive_calls.append((int(base), param))
        scripted = self._pop(self._derive_script)
        if scripted is not None:
            return scripted
        stored = self.objects.get(int(base))
        assert stored is not None, f"derive from unknown handle {base}"
        base_value = stored.attrs.get(int(CKA_VALUE))
        assert isinstance(base_value, bytes), base_value
        attrs = self._template_attrs(_decode_template(tmpl, count)) if count else {}
        role = self._effect_role(attrs, "derive")
        override = self._derive_value_for.get(role, self._derive_value)
        if override is not None:
            attrs[int(CKA_VALUE)] = override
        else:
            assert len(param) % 16 == 0 and param, param
            worker = Cipher(algorithms.AES(base_value), modes.ECB()).encryptor()  # nosec B305
            attrs[int(CKA_VALUE)] = worker.update(param) + worker.finalize()
        self._apply_extra(attrs)
        handle = self._store(attrs, role="derive")
        _fill_ulong(out, handle)
        return _OK

    def C_WrapKey(  # noqa: N802
        self, _sh: int, mech: Any, wrapping: int, target: int, out: Any, out_len: Any
    ) -> int:
        mech_id, _ = _decode_mech(mech)
        assert mech_id == _AES_KW, mech_id
        scripted = self._pop(self._wrap_script)
        if scripted is not None and out is None and scripted != _BUFFER_TOO_SMALL:
            return scripted
        # Per-op blob selection (F5): the size query opens each wrap op, so
        # the op-indexed override is resolved there and reused for the fetch.
        if out is None:
            self._wrap_blob_pending = self._wrap_blob_for.get(self._wrap_op_count)
            self._wrap_op_count += 1
        if self._wrap_blob_pending is not None:
            payload = self._wrap_blob_pending
        elif self._wrap_blob is not None:
            payload = self._wrap_blob
        else:
            kek = self.objects[int(wrapping)].attrs.get(int(CKA_VALUE))
            key = self.objects[int(target)].attrs.get(int(CKA_VALUE))
            assert isinstance(kek, bytes), kek
            if not isinstance(key, bytes):
                # Sourceless private object (genpair halves carry components,
                # not CKA_VALUE): wrap deterministic per-handle bytes so the
                # blob mechanics stay genuine; unwrap recovers the same bytes.
                key = bytes([(int(target) * 31 + i) % 251 + 1 for i in range(16)])
            payload = aes_key_wrap(kek, key)
        _register_minted_blob(payload)
        if out is None:
            _fill_ulong(out_len, len(payload))
            return _OK
        if scripted is not None:
            return scripted
        ctypes.memmove(out, payload, len(payload))
        _fill_ulong(out_len, len(payload))
        return _OK

    def C_UnwrapKey(  # noqa: N802
        self,
        _sh: int,
        mech: Any,
        unwrapping: int,
        in_buf: Any,
        in_len: int,
        tmpl: Any,
        count: int,
        out: Any,
    ) -> int:
        mech_id, _ = _decode_mech(mech)
        assert mech_id == _AES_KW, mech_id
        raw_attrs = _decode_template(tmpl, count) if count else {}
        self.unwrap_calls.append(raw_attrs)
        attrs = self._template_attrs(raw_attrs)
        scripted = self._pop(self._unwrap_script)
        if scripted is not None:
            self._maybe_leak(attrs, role="unwrap")
            leaked = self._maybe_leak_unlabeled(attrs, role="unwrap")
            self._maybe_foreign_delta(attrs)
            if leaked is not None:
                _fill_ulong(out, leaked)
            return scripted
        # False-UNWRAP-default provider (F6): an unwrapping key without an
        # explicit CKA_UNWRAP=True is refused, like a strict module.
        stored_kek = self.objects.get(int(unwrapping))
        if stored_kek is not None and stored_kek.attrs.get(int(CKA_UNWRAP), False) is not True:
            return _KEY_NOT_PERMITTED
        blob = bytes(in_buf[:in_len])
        role = self._effect_role(attrs, "unwrap")
        override = self._unwrap_value_for.get(role, self._unwrap_value)
        if override is not None:
            attrs[int(CKA_VALUE)] = override
        else:
            kek = self.objects[int(unwrapping)].attrs.get(int(CKA_VALUE))
            assert isinstance(kek, bytes), kek
            attrs[int(CKA_VALUE)] = aes_key_unwrap(kek, blob)
        self._apply_extra(attrs)
        handle = self._store(attrs, role="unwrap")
        _fill_ulong(out, handle)
        return _OK

    def C_EncapsulateKey(  # noqa: N802
        self,
        _sh: int,
        mech: Any,
        pub: int,
        tmpl: Any,
        count: int,
        out: Any,
        out_len: Any,
        handle_out: Any,
    ) -> int:
        mech_id, _ = _decode_mech(mech)
        assert mech_id == _ML_KEM, mech_id
        assert int(pub) in self.objects, pub
        scripted = self._pop(self._encaps_script)
        if scripted is not None:
            return scripted
        attrs = self._template_attrs(_decode_template(tmpl, count)) if count else {}
        role = self._effect_role(attrs, "encaps")
        ct = self._encaps_ct_for.get(role, self._encaps_ct)
        if ct is None:
            ct = b"E" * _KEM_CT_LEN
        _register_minted_blob(ct)
        secret = self._encaps_secret_for.get(role, self._encaps_secret)
        if secret is None:
            secret = b"S" * _KEM_SECRET_LEN
        if out is None:
            _fill_ulong(out_len, len(ct))
            return _BUFFER_TOO_SMALL
        attrs[int(CKA_VALUE)] = secret
        self._apply_extra(attrs)
        handle = self._store(attrs, role="encaps")
        ctypes.memmove(out, ct, len(ct))
        _fill_ulong(out_len, len(ct))
        _fill_ulong(handle_out, handle)
        return _OK

    def C_DecapsulateKey(  # noqa: N802
        self,
        _sh: int,
        mech: Any,
        priv: int,
        tmpl: Any,
        count: int,
        in_buf: Any,
        in_len: int,
        out: Any,
    ) -> int:
        mech_id, _ = _decode_mech(mech)
        assert mech_id == _ML_KEM, mech_id
        assert int(priv) in self.objects, priv
        assert in_len > 0, "decapsulate of empty ciphertext"
        scripted = self._pop(self._decaps_script)
        if scripted is not None:
            return scripted
        attrs = self._template_attrs(_decode_template(tmpl, count)) if count else {}
        role = self._effect_role(attrs, "decaps")
        secret = self._decaps_secret_for.get(role, self._decaps_secret)
        if secret is None:
            secret = b"S" * _KEM_SECRET_LEN
        attrs[int(CKA_VALUE)] = secret
        self._apply_extra(attrs)
        handle = self._store(attrs, role="decaps")
        _fill_ulong(out, handle)
        return _OK

    # -- single-part crypto ------------------------------------------------------

    @staticmethod
    def _aes_ecb(key: bytes, data: bytes, *, encrypt: bool) -> bytes:
        worker = Cipher(algorithms.AES(key), modes.ECB())  # nosec B305
        op = worker.encryptor() if encrypt else worker.decryptor()
        return op.update(data) + op.finalize()

    def _aes_key(self, handle: int, *, op: str) -> tuple[bytes, str] | int:
        stored = self.objects.get(int(handle))
        assert stored is not None, f"crypto on unknown handle {handle}"
        value = stored.attrs.get(int(CKA_VALUE))
        if not isinstance(value, bytes) or len(value) not in (16, 24, 32):
            return _KEY_TYPE_INCONSISTENT
        flag = int(CKA_ENCRYPT) if op == "encrypt" else int(CKA_DECRYPT)
        if stored.attrs.get(flag, True) is False:
            return _KEY_NOT_PERMITTED
        return value, stored.role

    def C_EncryptInit(self, _sh: int, mech: Any, handle: int) -> int:  # noqa: N802
        mech_id, _ = _decode_mech(mech)
        stored = self.objects.get(int(handle))
        role = stored.role if stored is not None else "unknown"
        scripted = self._encrypt_rv.get((role, mech_id))
        if scripted is not None:
            return scripted
        if mech_id == _RSA_PKCS:
            # Optional strict premise (N5): an unrequested CKA_ENCRYPT
            # stays false in this fake, so EncryptInit is refused.
            if self._enforce_rsa_encrypt_permission:
                target = self.objects.get(int(handle))
                granted = target.attrs.get(int(CKA_ENCRYPT), False) if target else False
                if granted is not True:
                    return _KEY_NOT_PERMITTED
            self._enc_op = (mech_id, int(handle), b"", b"", role)
            return _OK
        assert mech_id == _AES_ECB, mech_id
        outcome = self._aes_key(int(handle), op="encrypt")
        if isinstance(outcome, int):
            return outcome
        key_bytes, role = outcome
        self._enc_op = (mech_id, int(handle), key_bytes, b"", role)
        return _OK

    def C_Encrypt(  # noqa: N802
        self, _sh: int, in_buf: Any, in_len: int, out: Any, out_len: Any
    ) -> int:
        assert self._enc_op is not None, "C_Encrypt without C_EncryptInit"
        mech_id, handle, key_bytes, _param, role = self._enc_op
        override = self._encrypt_output_for.get((role, mech_id))
        if override is not None:
            _register_minted_blob(override)
            payload = override
        elif mech_id == _AES_ECB and in_len % 16 != 0:
            return _DATA_LEN_RANGE
        elif mech_id == _RSA_PKCS:
            stored = self.objects[int(handle)]
            modulus = stored.attrs.get(int(CKA_MODULUS))
            if not isinstance(modulus, bytes):
                return _KEY_TYPE_INCONSISTENT
            exponent = stored.attrs.get(int(CKA_PUBLIC_EXPONENT), b"\x01\x00\x01")
            assert isinstance(exponent, bytes), exponent
            pub = rsa.RSAPublicNumbers(
                int.from_bytes(exponent, "big"), int.from_bytes(modulus, "big")
            ).public_key()
            payload = pub.encrypt(bytes(in_buf[:in_len]), padding.PKCS1v15())
        else:
            payload = self._aes_ecb(key_bytes, bytes(in_buf[:in_len]), encrypt=True)
        if out is None:
            _fill_ulong(out_len, len(payload))
            return _OK
        self._enc_op = None
        ctypes.memmove(out, payload, len(payload))
        _fill_ulong(out_len, len(payload))
        return _OK

    def C_DecryptInit(self, _sh: int, mech: Any, handle: int) -> int:  # noqa: N802
        mech_id, _ = _decode_mech(mech)
        assert mech_id == _AES_ECB, mech_id
        stored = self.objects.get(int(handle))
        role = stored.role if stored is not None else "unknown"
        scripted = self._decrypt_rv.get((role, mech_id))
        if scripted is not None:
            return scripted
        outcome = self._aes_key(int(handle), op="decrypt")
        if isinstance(outcome, int):
            return outcome
        key_bytes, role = outcome
        self._dec_op = (mech_id, int(handle), key_bytes, b"", role)
        return _OK

    def C_Decrypt(  # noqa: N802
        self, _sh: int, in_buf: Any, in_len: int, out: Any, out_len: Any
    ) -> int:
        assert self._dec_op is not None, "C_Decrypt without C_DecryptInit"
        mech_id, _handle, key_bytes, _param, role = self._dec_op
        override = self._decrypt_output_for.get((role, mech_id))
        if override is not None:
            payload = override
        elif in_len % 16 != 0:
            return _ENC_DATA_LEN_RANGE
        else:
            payload = self._aes_ecb(key_bytes, bytes(in_buf[:in_len]), encrypt=False)
            if self._decrypt_corrupt:
                payload = bytes(b ^ 0xFF for b in payload)
        if out is None:
            _fill_ulong(out_len, len(payload))
            return _OK
        self._dec_op = None
        ctypes.memmove(out, payload, len(payload))
        _fill_ulong(out_len, len(payload))
        return _OK

    # -- message crypto ----------------------------------------------------------

    def C_MessageEncryptInit(self, _sh: int, mech: Any, handle: int) -> int:  # noqa: N802
        if not self._message_supported:
            return _NOT_SUPPORTED
        mech_id, _ = _decode_mech(mech)
        assert mech_id == _AES_ECB, mech_id
        stored = self.objects.get(int(handle))
        role = stored.role if stored is not None else "unknown"
        scripted = self._message_encrypt_rv.get((role, mech_id))
        if scripted is not None:
            return scripted
        outcome = self._aes_key(int(handle), op="encrypt")
        if isinstance(outcome, int):
            return outcome
        key_bytes, role = outcome
        self._msg_enc_op = (mech_id, int(handle), key_bytes, role)
        return _OK

    def C_EncryptMessage(  # noqa: N802
        self,
        _sh: int,
        _msg: Any,
        _msg_len: int,
        _aad: Any,
        _aad_len: int,
        in_buf: Any,
        in_len: int,
        out: Any,
        out_len: Any,
    ) -> int:
        assert self._msg_enc_op is not None, "C_EncryptMessage without init"
        mech_id, _handle, key_bytes, role = self._msg_enc_op
        override = self._message_encrypt_output_for.get((role, mech_id))
        if override is not None:
            _register_minted_blob(override)
        if override is None and in_len % 16 != 0:
            return _DATA_LEN_RANGE
        payload = (
            override
            if override is not None
            else self._aes_ecb(key_bytes, bytes(in_buf[:in_len]), encrypt=True)
        )
        if out is None:
            _fill_ulong(out_len, len(payload))
            return _OK
        ctypes.memmove(out, payload, len(payload))
        _fill_ulong(out_len, len(payload))
        return _OK

    def C_MessageEncryptFinal(self, _sh: int) -> int:  # noqa: N802
        self._msg_enc_op = None
        return _OK

    def C_MessageDecryptInit(self, _sh: int, mech: Any, handle: int) -> int:  # noqa: N802
        if not self._message_supported:
            return _NOT_SUPPORTED
        mech_id, _ = _decode_mech(mech)
        assert mech_id == _AES_ECB, mech_id
        stored = self.objects.get(int(handle))
        role = stored.role if stored is not None else "unknown"
        scripted = self._message_decrypt_rv.get((role, mech_id))
        if scripted is not None:
            return scripted
        outcome = self._aes_key(int(handle), op="decrypt")
        if isinstance(outcome, int):
            return outcome
        key_bytes, role = outcome
        self._msg_dec_op = (mech_id, int(handle), key_bytes, role)
        return _OK

    def C_DecryptMessage(  # noqa: N802
        self,
        _sh: int,
        _msg: Any,
        _msg_len: int,
        _aad: Any,
        _aad_len: int,
        in_buf: Any,
        in_len: int,
        out: Any,
        out_len: Any,
    ) -> int:
        assert self._msg_dec_op is not None, "C_DecryptMessage without init"
        mech_id, _handle, key_bytes, role = self._msg_dec_op
        override = self._message_decrypt_output_for.get((role, mech_id))
        if override is not None:
            payload = override
        elif in_len % 16 != 0:
            return _ENC_DATA_LEN_RANGE
        else:
            payload = self._aes_ecb(key_bytes, bytes(in_buf[:in_len]), encrypt=False)
            if self._decrypt_corrupt:
                payload = bytes(b ^ 0xFF for b in payload)
        if out is None:
            _fill_ulong(out_len, len(payload))
            return _OK
        ctypes.memmove(out, payload, len(payload))
        _fill_ulong(out_len, len(payload))
        return _OK

    def C_MessageDecryptFinal(self, _sh: int) -> int:  # noqa: N802
        self._msg_dec_op = None
        return _OK

    # -- signatures ----------------------------------------------------------------

    def C_SignInit(self, _sh: int, mech: Any, handle: int) -> int:  # noqa: N802
        if self._sign_raise is not None:
            raise self._sign_raise
        mech_id, _ = _decode_mech(mech)
        scripted = self._pop(self._sign_init_script)
        if scripted is not None:
            if scripted == _OK:
                self._sign_op = (mech_id, int(handle))
            return scripted
        self._sign_op = (mech_id, int(handle))
        return _OK

    def C_Sign(  # noqa: N802
        self, _sh: int, in_buf: Any, in_len: int, out: Any, out_len: Any
    ) -> int:
        if self._sign_raise is not None:
            raise self._sign_raise
        assert self._sign_op is not None, "C_Sign without C_SignInit"
        mech_id, handle = self._sign_op
        scripted = self._pop(self._sign_script)
        if scripted is not None and scripted != _OK:
            return scripted
        data = bytes(in_buf[:in_len])
        pqc_issue: tuple[int, bytes, bytes] | None = None
        if self._sign_output is not None:
            _register_minted_blob(self._sign_output)
            payload = self._sign_output
        elif handle in self._rsa_handles or self._sign_key == "rsa":
            assert mech_id == _RSA_PKCS_SIGN, mech_id
            payload = self._ensure_rsa().sign(data, padding.PKCS1v15(), hashes.SHA256())
        elif handle in self._ec_handles or self._sign_key == "ec":
            assert mech_id == _ECDSA, mech_id
            # Faithful raw ECDSA (F2): CKM_ECDSA signs the supplied digest
            # without hashing (PKCS#11 v3.2 §6.3.12: input length "any"),
            # never Hash(data). The Prehashed algorithm follows the digest
            # length, so any supplied digest is signed exactly as given.
            prehash = {20: hashes.SHA1(), 32: hashes.SHA256()}.get(len(data))  # nosec B303
            assert prehash is not None, len(data)
            der = self._ensure_ec().sign(data, ec.ECDSA(utils.Prehashed(prehash)))
            r, s = utils.decode_dss_signature(der)
            payload = int(r).to_bytes(32, "big") + int(s).to_bytes(32, "big")
        elif handle in self._pqc_handles:
            tag = self._pqc_handles[handle]
            payload = b"G" * (_ML_DSA_65_SIG_LEN if tag == "ml-dsa" else 7856)
            # Honest issuance (F11): only delivered module-produced PQC
            # signatures verify; overrides are never issued.
            pqc_issue = (mech_id, data, payload)
        else:
            return _KEY_TYPE_INCONSISTENT
        if out is None:
            _fill_ulong(out_len, len(payload))
            return _OK
        if pqc_issue is not None:
            self._pqc_issued.add(pqc_issue)
        self._sign_op = None
        ctypes.memmove(out, payload, len(payload))
        _fill_ulong(out_len, len(payload))
        return _OK

    def C_VerifyInit(self, _sh: int, mech: Any, handle: int) -> int:  # noqa: N802
        mech_id, _ = _decode_mech(mech)
        self._verify_op = (mech_id, int(handle))
        return _OK

    def C_Verify(  # noqa: N802
        self, _sh: int, _data: Any, _data_len: int, _sig: Any, _sig_len: int
    ) -> int:
        assert self._verify_op is not None, "C_Verify without C_VerifyInit"
        mech_id, _ = self._verify_op
        self._verify_op = None
        scripted = self._pop(self._verify_script)
        if scripted is not None:
            return scripted
        # Honest module (F11): a PQC signature verifies only if this module
        # issued it for these bytes; anything else is invalid, never assumed.
        if mech_id in (_ML_DSA, _SLH_DSA):
            data = bytes(_data[:_data_len])
            sig = bytes(_sig[:_sig_len])
            if (mech_id, data, sig) in self._pqc_issued:
                return _OK
            return _SIGNATURE_INVALID
        return _OK


_ALL_MECHS = {
    "AES_ECB",
    "AES_ECB_ENCRYPT_DATA",
    "AES_KEY_WRAP",
    "RSA_PKCS",
    "RSA_PKCS_KEY_PAIR_GEN",
    "SHA256_RSA_PKCS",
    "EC_KEY_PAIR_GEN",
    "ECDSA",
    "ML_KEM",
    "ML_KEM_KEY_PAIR_GEN",
    "ML_DSA",
    "ML_DSA_KEY_PAIR_GEN",
    "SLH_DSA",
    "SLH_DSA_KEY_PAIR_GEN",
}


def _rs(fake: _PolicyFake, *, mechs: set[str] | None = None) -> SimpleNamespace:
    advertised = _ALL_MECHS if mechs is None else mechs
    return SimpleNamespace(raw=fake, sh=1, has_mechanism=lambda name: name in advertised)


def _qc4a_derive(rs: SimpleNamespace, leg: str, use: str) -> None:
    cls = getattr(tobj, "TestAllowedMechanismsDerive")
    cls().test_derive_policy_leg(rs, leg, use)


def _qc4a_wrap(rs: SimpleNamespace, leg: str, use: str) -> None:
    cls = getattr(tobj, "TestAllowedMechanismsWrap")
    cls().test_wrap_policy_leg(rs, leg, use)


def _qc4a_unwrap(rs: SimpleNamespace, leg: str, use: str) -> None:
    cls = getattr(tobj, "TestAllowedMechanismsUnwrap")
    cls().test_unwrap_policy_leg(rs, leg, use)


def _qc4a_encaps(rs: SimpleNamespace, leg: str) -> None:
    cls = getattr(tkem, "TestAllowedMechanismsEncapsulate")
    cls().test_encapsulate_policy_leg(rs, leg)


def _qc4a_decaps(rs: SimpleNamespace, leg: str) -> None:
    cls = getattr(tkem, "TestAllowedMechanismsDecapsulate")
    cls().test_decapsulate_policy_leg(rs, leg)


def _qc4b_create(rs: SimpleNamespace, family: str, malformation: str) -> None:
    cls = getattr(tobj, "TestMalformedObjectCreate")
    cls().test_create_malformed_template(rs, family, malformation)


def _qc4b_unwrap(rs: SimpleNamespace, family: str, malformation: str) -> None:
    cls = getattr(tobj, "TestMalformedObjectUnwrap")
    cls().test_unwrap_malformed_template(rs, family, malformation)


def _qc4b_generate(rs: SimpleNamespace, family: str, malformation: str) -> None:
    cls = getattr(tobj, "TestMalformedObjectGenerate")
    cls().test_generate_malformed_template(rs, family, malformation)


def _qc4c(rs: SimpleNamespace, malformation: str) -> None:
    cls = getattr(twrong, "TestMalformedRsaSignDownstream")
    cls().test_rsa_sign_downstream(rs, malformation)


def _policy_module() -> Any:
    """Import the QC4 table module (absent on BASE)."""
    from pkcs11_check.testcases.ckr import _object_policy as policy_mod

    return policy_mod


def _run_must_fail(fn: Callable[..., Any], *args: Any, **kwargs: Any) -> None:
    """Run ``fn`` requiring ``pytest.fail``; an xfail or skip here is a false pass."""
    try:
        with pytest.raises(Failed) as exc_info:
            fn(*args, **kwargs)
    except Skipped as exc:
        pytest.fail(f"expected fail, got skip instead: {exc}")
    assert not isinstance(exc_info.value, XFailed), f"expected fail, got xfail: {exc_info.value}"


def _terminal_record() -> Any:
    records = C.get_records()
    assert records, "expected at least one classification record"
    return records[-1]


def _assert_fail_record(reason: str, kind: str | None) -> Any:
    record = _terminal_record()
    assert record.reason == reason, record.summary
    assert record.kind == kind, record.summary
    assert record.outcome == "fail", record.summary
    return record


def _reported_outcome(*, initial: str = "passed") -> str:
    """Replay the record stream through the REAL report hook.

    Uses the production ``pytest_runtest_makereport`` helper (not a
    reimplementation): any fail record fails, else any xfail record xfails,
    else the initial phase outcome stands. Task 15's I14 fix established
    asserting the complete stream; F1 requires it for every pass claim.
    """
    report = SimpleNamespace(outcome=initial)
    _apply_recorded_outcome(report, C.get_records())
    if report.outcome == "failed":
        return "fail"
    if getattr(report, "wasxfail", None) is not None:
        return "xfail"
    return "pass"


def _assert_xfail_record(reason: str) -> Any:
    record = _terminal_record()
    assert record.reason == reason, record.summary
    assert record.outcome == "xfail", record.summary
    fails = [rec for rec in C.get_records() if rec.outcome == "fail"]
    assert not fails, [rec.summary for rec in fails]
    return record


def _assert_terminal_pass() -> Any:
    """COMPLETE reported outcome passes through the REAL report hook.

    An earlier xfail "observation" record flips the reported outcome to xfail
    even when the terminal record passes (F1): a pass claim must replay the
    whole stream, never inspect only the last record.
    """
    records = C.get_records()
    assert records, "expected pass evidence records"
    assert _reported_outcome() == "pass", [(rec.reason, rec.outcome) for rec in records]
    terminal = records[-1]
    assert terminal.reason == "sanctioned_refusal", terminal.summary
    assert terminal.outcome == "pass", terminal.summary
    return terminal


def _assert_peer_note() -> None:
    """A peer observation left neutral evidence on the compliance channel."""
    notes = [note for note in get_notes() if "peer claim" in note.description]
    assert notes, [note.description for note in get_notes()]


def _assert_cleaned_up(fake: _PolicyFake) -> None:
    assert fake.created, "fake created no objects at all"
    assert set(fake.destroyed) >= set(fake.created), (fake.created, fake.destroyed)


def _assert_nothing_leaked(fake: _PolicyFake) -> None:
    """Subset cleanup check for setup voids (creation itself may be refused)."""
    assert set(fake.destroyed) >= set(fake.created), (fake.created, fake.destroyed)


def _assert_no_secret_bytes() -> None:
    """No record may carry key/secret bytes (lengths, names, RVs only).

    F16: every encoding the records could carry is gated — single- and
    double-quoted byte-string literals (printable or not, empty or not) via
    generic markers, plus the decoded text and hex of every blob the fake
    minted or handled this test.  Short blobs (< 8 bytes) skip the text/hex
    arms since their encodings collide with legitimate prose (a ``b"short"``
    blob vs "blob too short"); their repr forms still trip the markers.
    """
    for record in C.get_records():
        for field in (record.label, record.summary, repr(record.detail)):
            assert "b'" not in field and 'b"' not in field, field
            for blob in _MINTED_BLOBS:
                if len(blob) < 8:
                    continue
                assert blob.hex() not in field, field
                try:
                    text = blob.decode("ascii")
                except UnicodeDecodeError:
                    continue
                assert text not in field, field


def _plant_record(detail: dict[str, Any]) -> None:
    """Plant a single crypto-fail record carrying *detail* (F16 gate probes)."""
    C.record_as(
        "wrong_result",
        kind="crypto",
        label="f16-hygiene-probe",
        operation="C_Sign",
        summary="f16 hygiene probe",
        detail=detail,
    )


def test_no_secret_bytes_catches_printable_single_quoted_repr() -> None:
    """F16: a printable single-quoted byte string must trip the hygiene gate."""
    _plant_record({"blob": repr(b"PRINTABLE-PLANTED-CANARY-0123")})
    with pytest.raises(AssertionError):
        _assert_no_secret_bytes()


def test_no_secret_bytes_catches_double_quoted_repr() -> None:
    """F16: a double-quoted byte string must trip the hygiene gate."""
    _plant_record({"blob": repr(b"printable with 'quote' inside ok")})
    with pytest.raises(AssertionError):
        _assert_no_secret_bytes()


def test_no_secret_bytes_catches_empty_bytes_literal() -> None:
    """F16: an empty byte-string literal must trip the hygiene gate."""
    _plant_record({"blob": repr(b"")})
    with pytest.raises(AssertionError):
        _assert_no_secret_bytes()


def test_no_secret_bytes_catches_hex_of_minted_blob() -> None:
    """F16: hex of a fake-minted blob must trip the hygiene gate."""
    blob = b"\xde\xad\xbe\xef\x00\x11\x22\x33minted-canary"
    _register_minted_blob(blob)
    _plant_record({"blob": blob.hex()})
    with pytest.raises(AssertionError):
        _assert_no_secret_bytes()


def test_no_secret_bytes_catches_decoded_text_of_minted_blob() -> None:
    """F16: decoded text of a fake-minted blob must trip the hygiene gate."""
    blob = b"DECODED-MINTED-CANARY-4567"
    _register_minted_blob(blob)
    _plant_record({"blob": blob.decode("ascii")})
    with pytest.raises(AssertionError):
        _assert_no_secret_bytes()


def test_no_secret_bytes_accepts_lengths_names_and_rvs() -> None:
    """F16: the strengthened gate still accepts legitimate record content."""
    _plant_record(
        {
            "expected_len": 64,
            "actual_len": 63,
            "operation": "C_Sign",
            "rv": "CKR_OK",
            "label": "qc4a-wrap-included-t",
        }
    )
    _assert_no_secret_bytes()


# -- QC4a table -----------------------------------------------------------------


def test_table_pins_constrained_key_per_function_with_citations() -> None:
    """Each of the five functions names its PRIMARY constrained key + citation."""
    mod = _policy_module()
    rows = {row.key: row for row in mod.POLICY_FUNCTION_TABLE}
    assert set(rows) == {"derive", "wrap", "unwrap", "encapsulate", "decapsulate"}
    assert rows["derive"].operation == "C_DeriveKey"
    assert rows["derive"].constrained_role == "base key"
    assert rows["wrap"].operation == "C_WrapKey"
    assert rows["wrap"].constrained_role == "wrapping key"
    assert rows["unwrap"].operation == "C_UnwrapKey"
    assert rows["unwrap"].constrained_role == "unwrapping key"
    assert rows["encapsulate"].operation == "C_EncapsulateKey"
    assert rows["encapsulate"].constrained_role == "public key"
    assert rows["decapsulate"].operation == "C_DecapsulateKey"
    assert rows["decapsulate"].constrained_role == "private key"
    for key, row in rows.items():
        assert row.citation, key
        assert "ALLOWED_MECHANISMS" in row.citation, key
        assert "KEY_FUNCTION_NOT_PERMITTED" in row.citation, key
    assert "5.18.5" in rows["derive"].citation
    assert "5.18.3" in rows["wrap"].citation
    assert "5.18.4" in rows["unwrap"].citation
    assert "5.18.8" in rows["encapsulate"].citation
    assert "5.18.9" in rows["decapsulate"].citation
    for key, row in rows.items():
        assert "4.1.3" not in row.citation, key
        assert "adjudicat" in row.citation, key
        # N10: CKA_ALLOWED_MECHANISMS is a key attribute (Table 26),
        # not a common object attribute (Table 14).
        assert "Table 26" in row.citation, (key, row.citation)
        assert "Table 14" not in row.citation, (key, row.citation)


def test_table_row_lookup_rejects_unknown_keys() -> None:
    mod = _policy_module()
    assert mod.row_by_key("derive").operation == "C_DeriveKey"
    with pytest.raises(KeyError):
        mod.row_by_key("no_such_function")


def test_malformed_cell_inventory_is_pinned() -> None:
    """The QC4b matrix enumerates Create/Unwrap/Generate x family x malformation."""
    mod = _policy_module()
    assert set(mod.CREATE_CELLS) == {
        ("rsa", "swap_secret_class_asym_type"),
        ("rsa", "swap_asym_class_secret_type"),
        ("rsa", "missing_modulus"),
        ("rsa", "missing_exponent"),
        ("ec", "swap_secret_class_asym_type"),
        ("ec", "swap_asym_class_secret_type"),
        ("ec", "missing_params"),
        ("ec", "missing_point"),
        ("pqc", "swap_secret_class_asym_type"),
        ("pqc", "swap_asym_class_secret_type"),
        ("pqc", "missing_params"),
    }
    assert set(mod.UNWRAP_CELLS) == {
        ("rsa", "swap_secret_class_asym_type"),
        ("rsa", "swap_asym_class_secret_type"),
        ("ec", "swap_secret_class_asym_type"),
        ("ec", "swap_asym_class_secret_type"),
        ("pqc", "swap_secret_class_asym_type"),
        ("pqc", "swap_asym_class_secret_type"),
    }
    assert set(mod.GENERATE_CELLS) == {
        ("rsa", "swap_secret_class_asym_type"),
        ("rsa", "swap_asym_class_secret_type"),
        ("rsa", "missing_modulus_bits"),
        ("ec", "swap_secret_class_asym_type"),
        ("ec", "swap_asym_class_secret_type"),
        ("ec", "missing_params"),
        ("pqc", "swap_secret_class_asym_type"),
        ("pqc", "swap_asym_class_secret_type"),
        ("pqc", "missing_params"),
    }
    assert mod.RSA_DOWNSTREAM_MALFORMATIONS == (
        "swap_secret_class_asym_type",
        "swap_asym_class_secret_type",
        "missing_modulus",
        "missing_exponent",
    )
    assert mod.ML_KEM_768_CT_LEN == 1088
    assert mod.ML_KEM_768_SECRET_LEN == 32


def test_malformed_labels_are_deterministic_and_unique() -> None:
    mod = _policy_module()
    labels = set()
    for cells, operation in (
        (mod.CREATE_CELLS, "create"),
        (mod.UNWRAP_CELLS, "unwrap"),
        (mod.GENERATE_CELLS, "generate"),
    ):
        for family, malformation in cells:
            attempt = mod.malformed_label(operation, family, malformation)
            control = mod.control_label(operation, family, malformation)
            assert attempt and control and attempt != control
            assert attempt not in labels and control not in labels, (attempt, control)
            labels.add(attempt)
            labels.add(control)
    downstream = {mod.downstream_label(mal) for mal in mod.RSA_DOWNSTREAM_MALFORMATIONS}
    assert len(downstream) == 4
    assert not (downstream & labels)


def test_malformed_labels_unique_across_calls_by_default(monkeypatch: pytest.MonkeyPatch) -> None:
    """F12: attempt labels are unique per call unless a factory is injected."""
    mod = _policy_module()
    assert _SAVED_NONCE_FACTORY is not None, "F12 nonce factory missing"
    monkeypatch.setattr(mod, "_LABEL_NONCE_FACTORY", _SAVED_NONCE_FACTORY)
    first = mod.malformed_label("create", "rsa", "swap_secret_class_asym_type")
    second = mod.malformed_label("create", "rsa", "swap_secret_class_asym_type")
    assert first != second


def test_malformed_label_uses_injected_factory() -> None:
    """F12: contracts pin determinism via the injected factory (autouse 't')."""
    mod = _policy_module()
    assert getattr(mod, "_LABEL_NONCE_FACTORY", None) is not None, "F12 nonce factory missing"
    label = mod.malformed_label("create", "rsa", "swap_secret_class_asym_type")
    assert label == "qc4b-create-rsa-swap_secret_class_asym_type-t"


# -- QC4a derive ------------------------------------------------------------------


@pytest.mark.parametrize("use", ["classic", "message"])
def test_qc4a_derive_included_success_passes(use: str) -> None:
    """Included derive completes; the derived key is oracle-verified + round-trips."""
    fake = _PolicyFake()
    _qc4a_derive(_rs(fake), "included", use)
    _assert_terminal_pass()
    record = _terminal_record()
    assert record.reason == "sanctioned_refusal", record.summary
    assert record.actual_ckr == ckr_name(_OK), record.summary
    assert (record.detail or {}).get("oracle_match") is True, record.detail
    assert (record.detail or {}).get("round_trip") is True, record.detail
    _assert_cleaned_up(fake)
    _assert_no_secret_bytes()


def test_qc4a_derive_included_control_refused_voids() -> None:
    """A refused control derive voids the included leg as setup, never passes it."""
    fake = _PolicyFake(derive_script=[_FUNCTION_FAILED])
    assert_xfails(_qc4a_derive, _rs(fake), "included", "classic")
    record = _assert_xfail_record("not_operational")
    assert record.actual_ckr == ckr_name(_FUNCTION_FAILED), record.summary
    _assert_cleaned_up(fake)


@pytest.mark.parametrize("rv", [_FUNCTION_FAILED, _KEY_NOT_PERMITTED, _MECHANISM_INVALID])
def test_qc4a_derive_included_refusal_is_deviation_xfail(rv: int) -> None:
    """Refusing an included mechanism where supported is a deviation, never a pass."""
    fake = _PolicyFake(derive_script=[None, rv])
    assert_xfails(_qc4a_derive, _rs(fake), "included", "classic")
    record = _assert_xfail_record("honest_deviation")
    assert record.actual_ckr == ckr_name(rv), record.summary
    _assert_cleaned_up(fake)


def test_qc4a_derive_included_oracle_mismatch_fails() -> None:
    """A derived value outside the local ECB oracle fails crypto wrong_result."""
    fake = _PolicyFake(derive_value=b"W" * 16)
    _run_must_fail(_qc4a_derive, _rs(fake), "included", "classic")
    record = _assert_fail_record("wrong_result", "crypto")
    assert "oracle" in (record.summary or "").lower(), record.summary
    _assert_cleaned_up(fake)


def test_qc4a_derive_included_wrong_length_value_fails() -> None:
    """A derived value ignoring the requested VALUE_LEN fails crypto wrong_result."""
    fake = _PolicyFake(derive_value=b"W" * 20)
    _run_must_fail(_qc4a_derive, _rs(fake), "included", "classic")
    _assert_fail_record("wrong_result", "crypto")
    _assert_cleaned_up(fake)


def test_qc4a_derive_included_malformed_use_output_fails() -> None:
    """A successful ECB use with a malformed-length output fails wrong_result."""
    fake = _PolicyFake(encrypt_output_for={("derive", _AES_ECB): b"W" * 20})
    _run_must_fail(_qc4a_derive, _rs(fake), "included", "classic")
    _assert_fail_record("wrong_result", "crypto")
    _assert_cleaned_up(fake)


def test_qc4a_derive_included_wrong_use_output_fails() -> None:
    """A successful ECB use outside the local oracle fails wrong_result."""
    fake = _PolicyFake(encrypt_output_for={("derive", _AES_ECB): b"W" * 16})
    _run_must_fail(_qc4a_derive, _rs(fake), "included", "classic")
    _assert_fail_record("wrong_result", "crypto")
    _assert_cleaned_up(fake)


def test_qc4a_derive_included_round_trip_break_fails() -> None:
    """Encrypt/decrypt incoherence on the derived key fails wrong_result."""
    fake = _PolicyFake(decrypt_corrupt=True)
    _run_must_fail(_qc4a_derive, _rs(fake), "included", "classic")
    _assert_fail_record("wrong_result", "crypto")
    _assert_cleaned_up(fake)


def test_qc4a_derive_included_use_refused_is_unproved() -> None:
    """Accepted derive with refused use leaves the effect unproved, never passed."""
    fake = _PolicyFake(encrypt_rv={("derive", _AES_ECB): _FUNCTION_FAILED})
    assert_xfails(_qc4a_derive, _rs(fake), "included", "classic")
    record = _assert_xfail_record("honest_deviation")
    assert record.actual_ckr == ckr_name(_OK), record.summary
    assert (record.detail or {}).get("disposition") == "unproved-effect", record.detail
    _assert_cleaned_up(fake)


def test_qc4a_derive_included_decrypt_refused_is_unproved() -> None:
    """F16: accepted derive with refused decrypt is unproved, with its RV kept."""
    fake = _PolicyFake(decrypt_rv={("derive", _AES_ECB): _FUNCTION_FAILED})
    assert_xfails(_qc4a_derive, _rs(fake), "included", "classic")
    record = _assert_xfail_record("honest_deviation")
    assert record.actual_ckr == ckr_name(_OK), record.summary
    assert (record.detail or {}).get("disposition") == "unproved-effect", record.detail
    assert (record.detail or {}).get("use_rv") == ckr_name(_FUNCTION_FAILED), record.detail
    _assert_cleaned_up(fake)
    _assert_no_secret_bytes()


def test_qc4a_derive_included_message_decrypt_refused_is_unproved() -> None:
    """F16: message-decrypt refusal is unproved with its RV, like the classic arm."""
    fake = _PolicyFake(message_decrypt_rv={("derive", _AES_ECB): _FUNCTION_FAILED})
    assert_xfails(_qc4a_derive, _rs(fake), "included", "message")
    record = _assert_xfail_record("honest_deviation")
    assert record.actual_ckr == ckr_name(_OK), record.summary
    assert (record.detail or {}).get("disposition") == "unproved-effect", record.detail
    assert (record.detail or {}).get("use_rv") == ckr_name(_FUNCTION_FAILED), record.detail
    _assert_cleaned_up(fake)
    _assert_no_secret_bytes()


def test_qc4a_derive_included_claim_mismatch_voids() -> None:
    """An included seed reading back excluded voids the premise, never passes."""
    blob = _encode_value(int(CKA_ALLOWED_MECHANISMS), [_AES_ECB])
    fake = _PolicyFake(raw_readback={("create", int(CKA_ALLOWED_MECHANISMS)): blob})
    assert_xfails(_qc4a_derive, _rs(fake), "included", "classic")
    record = _assert_xfail_record("not_operational")
    assert "claim" in (record.summary or "").lower(), record.summary
    _assert_cleaned_up(fake)


def test_qc4a_derive_claim_readback_refused_voids() -> None:
    """A refused claim-first readback voids the leg with the RV preserved."""
    fake = _PolicyFake(get_attr_script=[_DEVICE_ERROR])
    assert_xfails(_qc4a_derive, _rs(fake), "included", "classic")
    record = _assert_xfail_record("not_operational")
    assert record.actual_ckr == ckr_name(_DEVICE_ERROR), record.summary
    _assert_cleaned_up(fake)


def test_qc4a_derive_excluded_policy_refusal_passes() -> None:
    """The singleton policy refusal of an excluded mechanism passes as effective."""
    fake = _PolicyFake(derive_script=[None, _KEY_NOT_PERMITTED])
    _qc4a_derive(_rs(fake), "excluded", "classic")
    _assert_terminal_pass()
    record = _terminal_record()
    assert record.reason == "sanctioned_refusal", record.summary
    assert record.actual_ckr == ckr_name(_KEY_NOT_PERMITTED), record.summary
    _assert_cleaned_up(fake)


@pytest.mark.parametrize("rv", [_FUNCTION_FAILED, _ACTION_PROHIBITED, _MECHANISM_INVALID])
def test_qc4a_derive_excluded_alternate_refusal_xfails(rv: int) -> None:
    """A non-policy clean refusal never proves the restriction effective."""
    fake = _PolicyFake(derive_script=[None, rv])
    assert_xfails(_qc4a_derive, _rs(fake), "excluded", "classic")
    record = _assert_xfail_record("nonspec_reject")
    assert record.actual_ckr == ckr_name(rv), record.summary
    _assert_cleaned_up(fake)


def test_qc4a_derive_excluded_vendor_refusal_xfails() -> None:
    fake = _PolicyFake(derive_script=[None, _VENDOR_RV])
    assert_xfails(_qc4a_derive, _rs(fake), "excluded", "classic")
    record = _assert_xfail_record("nonspec_reject")
    assert record.actual_ckr == ckr_name(_VENDOR_RV), record.summary
    _assert_cleaned_up(fake)


def test_qc4a_derive_excluded_undefined_rv_fails_metadata() -> None:
    fake = _PolicyFake(derive_script=[None, _UNDEFINED_RV])
    _run_must_fail(_qc4a_derive, _rs(fake), "excluded", "classic")
    _assert_fail_record("self_contradiction", "metadata")
    _assert_cleaned_up(fake)


def test_qc4a_derive_excluded_control_refused_voids() -> None:
    """Without an operational including-list control the excluded leg is void."""
    fake = _PolicyFake(derive_script=[_FUNCTION_FAILED])
    assert_xfails(_qc4a_derive, _rs(fake), "excluded", "classic")
    record = _assert_xfail_record("not_operational")
    assert record.actual_ckr == ckr_name(_FUNCTION_FAILED), record.summary
    _assert_cleaned_up(fake)


def test_qc4a_derive_excluded_control_claim_mismatch_voids() -> None:
    """A control key not actually including the mechanism voids the excluded leg."""
    blob = _encode_value(int(CKA_ALLOWED_MECHANISMS), [_AES_ECB])
    fake = _PolicyFake(raw_readback={("create", int(CKA_ALLOWED_MECHANISMS)): blob})
    assert_xfails(_qc4a_derive, _rs(fake), "excluded", "classic")
    _assert_xfail_record("not_operational")
    _assert_cleaned_up(fake)


def test_qc4a_derive_control_decrypt_refused_voids() -> None:
    """F16: a control with refused decrypt voids the leg as setup, never passes."""
    fake = _PolicyFake(decrypt_rv={("derive-control", _AES_ECB): _FUNCTION_FAILED})
    assert_xfails(_qc4a_derive, _rs(fake), "excluded", "classic")
    record = _assert_xfail_record("not_operational")
    assert record.actual_ckr == ckr_name(_FUNCTION_FAILED), record.summary
    _assert_cleaned_up(fake)
    _assert_no_secret_bytes()


def test_qc4a_derive_control_wrong_value_fails() -> None:
    """F5: an incorrect control derived value fails; never PASS + shaped refusal."""
    fake = _PolicyFake(
        derive_script=[None, _KEY_NOT_PERMITTED],
        derive_value_for={"derive-control": b"W" * 16},
    )
    _run_must_fail(_qc4a_derive, _rs(fake), "excluded", "classic")
    record = _assert_fail_record("wrong_result", "crypto")
    assert "control" in (record.summary or "").lower(), record.summary
    _assert_cleaned_up(fake)


def test_qc4a_derive_control_wrong_use_output_fails() -> None:
    """F5: the control runs the same ECB effect check as the main leg."""
    fake = _PolicyFake(
        derive_script=[None, _KEY_NOT_PERMITTED],
        encrypt_output_for={("derive-control", _AES_ECB): b"W" * 16},
    )
    _run_must_fail(_qc4a_derive, _rs(fake), "excluded", "classic")
    _assert_fail_record("wrong_result", "crypto")
    _assert_cleaned_up(fake)


@pytest.mark.parametrize("use", ["classic", "message"])
def test_qc4a_derive_excluded_completion_is_bypass_fail(use: str) -> None:
    """Completing an excluded derive with a verified effect fails policy bypass."""
    fake = _PolicyFake()
    _run_must_fail(_qc4a_derive, _rs(fake), "excluded", use)
    record = _assert_fail_record("self_contradiction", "policy")
    assert "bypass" in (record.summary or "").lower(), record.summary
    assert record.actual_ckr == ckr_name(_OK), record.summary
    _assert_cleaned_up(fake)
    _assert_no_secret_bytes()


def test_qc4a_derive_excluded_completion_unusable_is_unproved() -> None:
    """An excluded completion whose effect is unusable never fails unproved."""
    fake = _PolicyFake(encrypt_rv={("derive", _AES_ECB): _FUNCTION_FAILED})
    assert_xfails(_qc4a_derive, _rs(fake), "excluded", "classic")
    record = _assert_xfail_record("honest_deviation")
    assert (record.detail or {}).get("disposition") == "unproved-effect", record.detail
    _assert_cleaned_up(fake)


def test_qc4a_derive_excluded_completion_incoherent_fails_crypto() -> None:
    """Crypto incoherence on an excluded completion fails wrong_result, not bypass."""
    fake = _PolicyFake(decrypt_corrupt=True)
    _run_must_fail(_qc4a_derive, _rs(fake), "excluded", "classic")
    _assert_fail_record("wrong_result", "crypto")
    _assert_cleaned_up(fake)


def test_qc4a_derive_setup_import_refused_voids() -> None:
    fake = _PolicyFake(create_script=[_FUNCTION_FAILED])
    assert_xfails(_qc4a_derive, _rs(fake), "included", "classic")
    record = _assert_xfail_record("not_operational")
    assert record.actual_ckr == ckr_name(_FUNCTION_FAILED), record.summary
    _assert_nothing_leaked(fake)


def test_qc4a_derive_control_import_refused_voids() -> None:
    fake = _PolicyFake(create_script=[None, _FUNCTION_FAILED])
    assert_xfails(_qc4a_derive, _rs(fake), "included", "classic")
    _assert_xfail_record("not_operational")
    _assert_cleaned_up(fake)


def test_qc4a_derive_missing_mechanism_skips() -> None:
    fake = _PolicyFake()
    mechs = set(_ALL_MECHS) - {"AES_ECB_ENCRYPT_DATA"}
    assert_skips(_qc4a_derive, _rs(fake, mechs=mechs), "included", "classic")


def test_qc4a_derive_message_unsupported_skips() -> None:
    """A message-use leg without message entry points skips as incapable."""
    fake = _PolicyFake(message_supported=False)
    assert_skips(_qc4a_derive, _rs(fake), "included", "message")
    _assert_cleaned_up(fake)


def test_qc4a_derive_message_unsupported_binding_skips(monkeypatch: pytest.MonkeyPatch) -> None:
    """A missing C_MessageEncryptInit binding skips the message leg too."""
    monkeypatch.delattr(_PolicyFake, "C_MessageEncryptInit")
    fake = _PolicyFake()
    assert_skips(_qc4a_derive, _rs(fake), "included", "message")
    _assert_cleaned_up(fake)


def test_qc4a_derive_message_round_trip_break_fails() -> None:
    fake = _PolicyFake(decrypt_corrupt=True)
    _run_must_fail(_qc4a_derive, _rs(fake), "included", "message")
    _assert_fail_record("wrong_result", "crypto")
    _assert_cleaned_up(fake)


def test_qc4a_derive_message_use_refused_is_unproved() -> None:
    fake = _PolicyFake(message_encrypt_rv={("derive", _AES_ECB): _FUNCTION_FAILED})
    assert_xfails(_qc4a_derive, _rs(fake), "included", "message")
    record = _assert_xfail_record("honest_deviation")
    assert (record.detail or {}).get("disposition") == "unproved-effect", record.detail
    _assert_cleaned_up(fake)


# -- QC4a wrap --------------------------------------------------------------------


@pytest.mark.parametrize("use", ["classic", "message"])
def test_qc4a_wrap_included_success_passes(use: str) -> None:
    """Included wrap completes; the blob re-unwraps and the key round-trips."""
    fake = _PolicyFake()
    _qc4a_wrap(_rs(fake), "included", use)
    _assert_terminal_pass()
    record = _terminal_record()
    assert record.reason == "sanctioned_refusal", record.summary
    assert (record.detail or {}).get("oracle_match") is True, record.detail
    assert (record.detail or {}).get("round_trip") is True, record.detail
    assert "peer_allowed_mechanisms" in (record.detail or {}), record.detail
    _assert_cleaned_up(fake)
    _assert_no_secret_bytes()


def test_qc4a_wrap_peer_list_is_observed_not_failed_on() -> None:
    """A peer target list is recorded in evidence and never carries an oracle."""
    blob = _encode_value(int(CKA_ALLOWED_MECHANISMS), [_AES_KW])
    fake = _PolicyFake(raw_readback={("create", int(CKA_ALLOWED_MECHANISMS)): blob})
    _qc4a_wrap(_rs(fake), "included", "classic")
    _assert_terminal_pass()
    record = _terminal_record()
    assert (record.detail or {}).get("peer_allowed_mechanisms") == ["CKM_AES_KEY_WRAP"]


def test_qc4a_wrap_absent_peer_list_reports_terminal_pass() -> None:
    """F1: healthy wrap + absent peer list → terminal PASS via the real hook."""
    fake = _PolicyFake()
    _qc4a_wrap(_rs(fake), "included", "classic")
    _assert_terminal_pass()
    record = _terminal_record()
    assert (record.detail or {}).get("peer_allowed_mechanisms") is None, record.detail
    _assert_peer_note()


def test_qc4a_wrap_refused_peer_read_is_neutral() -> None:
    """F1/F13: a standard peer-read refusal stays a neutral note, never a record."""
    fake = _PolicyFake(get_attr_script=[None, None, _FUNCTION_FAILED])
    _qc4a_wrap(_rs(fake), "included", "classic")
    _assert_terminal_pass()
    _assert_peer_note()


def test_qc4a_wrap_vendor_peer_read_xfails() -> None:
    """F13 + N9: vendor peer refusal xfails with full terminal evidence."""
    fake = _PolicyFake(get_attr_script=[None, None, _VENDOR_RV])
    assert_xfails(_qc4a_wrap, _rs(fake), "included", "classic")
    record = _assert_xfail_record("nonspec_reject")
    assert record.kind == "policy", record.summary
    assert record.label == "C_WrapKey ALLOWED_MECHANISMS included (classic use): peer claim", (
        record.label
    )
    assert record.operation == "C_GetAttributeValue", record.operation
    assert record.actual_ckr == ckr_name(_VENDOR_RV), record.summary
    assert _reported_outcome() == "xfail", [rec.reason for rec in C.get_records()]
    _assert_cleaned_up(fake)
    _assert_no_secret_bytes()


def test_qc4a_wrap_undefined_peer_read_fails_metadata() -> None:
    """F13 + N9: undefined peer RV fails metadata with full terminal evidence."""
    fake = _PolicyFake(get_attr_script=[None, None, _UNDEFINED_RV])
    _run_must_fail(_qc4a_wrap, _rs(fake), "included", "classic")
    record = _assert_fail_record("self_contradiction", "metadata")
    assert record.label == "C_WrapKey ALLOWED_MECHANISMS included (classic use): peer claim", (
        record.label
    )
    assert record.operation == "C_GetAttributeValue", record.operation
    assert record.actual_ckr == ckr_name(_UNDEFINED_RV), record.summary
    assert _reported_outcome() == "fail", [rec.reason for rec in C.get_records()]
    _assert_cleaned_up(fake)
    _assert_no_secret_bytes()


def test_qc4a_unwrap_absent_peer_list_reports_terminal_pass() -> None:
    """F1: healthy unwrap + absent peer list → terminal PASS via the real hook."""
    fake = _PolicyFake()
    _qc4a_unwrap(_rs(fake), "included", "classic")
    _assert_terminal_pass()
    _assert_peer_note()


def test_qc4a_encaps_absent_peer_list_reports_terminal_pass() -> None:
    """F1: healthy encapsulate + absent peer list → terminal PASS via the real hook."""
    fake = _PolicyFake()
    _qc4a_encaps(_rs(fake), "included")
    _assert_terminal_pass()
    _assert_peer_note()


def test_qc4a_decaps_absent_peer_list_reports_terminal_pass() -> None:
    """F1: healthy decapsulate + absent peer list → terminal PASS via the real hook."""
    fake = _PolicyFake()
    _qc4a_decaps(_rs(fake), "included")
    _assert_terminal_pass()
    _assert_peer_note()


def test_read_peer_claim_absence_leaves_no_record(monkeypatch: pytest.MonkeyPatch) -> None:
    """F1: peer absence leaves NO classification record (neutral note only)."""
    mod = _policy_module()
    monkeypatch.setattr(mod, "read_attributes", lambda *args: {})
    assert mod.read_peer_claim(SimpleNamespace(raw=object(), sh=1), 1, label="probe") is None
    assert C.get_records() == [], "absence must not record"
    assert _reported_outcome() == "pass"
    _assert_peer_note()


def test_read_peer_claim_malformed_shape_is_neutral(monkeypatch: pytest.MonkeyPatch) -> None:
    """F1: a malformed peer claim leaves NO classification record (note only)."""
    mod = _policy_module()
    monkeypatch.setattr(
        mod, "read_attributes", lambda *args: {int(CKA_ALLOWED_MECHANISMS): b"not-a-list"}
    )
    assert mod.read_peer_claim(SimpleNamespace(raw=object(), sh=1), 1, label="probe") is None
    assert C.get_records() == [], "malformed shape must not record"
    assert _reported_outcome() == "pass"
    _assert_peer_note()


def test_read_peer_claim_malformed_entries_are_neutral(monkeypatch: pytest.MonkeyPatch) -> None:
    """F16: a peer list with non-mechanism entries leaves NO record (note only)."""
    mod = _policy_module()
    monkeypatch.setattr(
        mod,
        "read_attributes",
        lambda *args: {int(CKA_ALLOWED_MECHANISMS): [int(_AES_ECB), "CKM_BOGUS"]},
    )
    assert mod.read_peer_claim(SimpleNamespace(raw=object(), sh=1), 1, label="probe") is None
    assert C.get_records() == [], "malformed entries must not record"
    assert _reported_outcome() == "pass"
    _assert_peer_note()


def test_qc4a_wrap_peer_contradiction_fails_self_contradiction() -> None:
    """R1: peer refusal-with-data takes the hatch contradiction arm: FAIL, not a note.

    A proved module self-contradiction fails loud per framework doctrine
    (F9 fail-fast); it is never noted-and-passed. The recorded finding
    carries the refusal CKR + leaked length, replacing G0's neutral note.
    """
    target_label = b"qc4a-wrap-included-classic-target"
    leak = int(_AES_KW).to_bytes(8, sys.byteorder)
    fake = _PolicyFake(
        contradict_readback={(target_label, int(CKA_ALLOWED_MECHANISMS)): (_TYPE_INVALID, leak)}
    )
    _run_must_fail(_qc4a_wrap, _rs(fake), "included", "classic")
    record = _assert_fail_record("self_contradiction", "policy")
    assert record.actual_ckr == ckr_name(_TYPE_INVALID), record.summary
    assert (record.detail or {}).get("leaked_len") == len(leak), record.detail
    assert _reported_outcome() == "fail", [rec.reason for rec in C.get_records()]
    assert not [note for note in get_notes() if "peer claim" in note.description], [
        note.description for note in get_notes()
    ]
    _assert_cleaned_up(fake)
    _assert_no_secret_bytes()


def test_qc4a_wrap_included_control_refused_voids() -> None:
    fake = _PolicyFake(wrap_script=[_FUNCTION_FAILED])
    assert_xfails(_qc4a_wrap, _rs(fake), "included", "classic")
    record = _assert_xfail_record("not_operational")
    assert record.actual_ckr == ckr_name(_FUNCTION_FAILED), record.summary
    _assert_cleaned_up(fake)


@pytest.mark.parametrize("rv", [_FUNCTION_FAILED, _KEY_NOT_PERMITTED])
def test_qc4a_wrap_included_refusal_is_deviation_xfail(rv: int) -> None:
    fake = _PolicyFake(wrap_script=[None, None, rv])
    assert_xfails(_qc4a_wrap, _rs(fake), "included", "classic")
    record = _assert_xfail_record("honest_deviation")
    assert record.actual_ckr == ckr_name(rv), record.summary
    _assert_cleaned_up(fake)


def test_qc4a_wrap_included_malformed_blob_is_unproved() -> None:
    """A non-KW-shaped blob has no normative shape: unproved, never a crypto fail."""
    fake = _PolicyFake(wrap_blob_for={1: b"short"})
    assert_xfails(_qc4a_wrap, _rs(fake), "included", "classic")
    record = _assert_xfail_record("honest_deviation")
    assert (record.detail or {}).get("disposition") == "unproved-effect", record.detail
    _assert_cleaned_up(fake)


def test_qc4a_wrap_included_empty_blob_is_unproved() -> None:
    fake = _PolicyFake(wrap_blob_for={1: b""})
    assert_xfails(_qc4a_wrap, _rs(fake), "included", "classic")
    _assert_xfail_record("honest_deviation")
    _assert_cleaned_up(fake)


def test_qc4a_wrap_included_foreign_blob_is_unproved() -> None:
    """A blob failing the local KW oracle never fails; it is unvalidated."""
    mod = _policy_module()
    blob = aes_key_wrap(mod.QC4_AES_BASE, b"Z" * 16)
    fake = _PolicyFake(wrap_blob_for={1: blob})
    assert_xfails(_qc4a_wrap, _rs(fake), "included", "classic")
    record = _assert_xfail_record("honest_deviation")
    assert (record.detail or {}).get("key_match") is False, record.detail
    _assert_cleaned_up(fake)


def test_qc4a_wrap_included_reunwrap_refused_is_unproved() -> None:
    fake = _PolicyFake(unwrap_script=[None, _FUNCTION_FAILED])
    assert_xfails(_qc4a_wrap, _rs(fake), "included", "classic")
    record = _assert_xfail_record("honest_deviation")
    assert (record.detail or {}).get("disposition") == "unproved-effect", record.detail
    _assert_cleaned_up(fake)


def test_qc4a_wrap_included_wrong_use_output_fails() -> None:
    fake = _PolicyFake(encrypt_output_for={("unwrap", _AES_ECB): b"W" * 16})
    _run_must_fail(_qc4a_wrap, _rs(fake), "included", "classic")
    _assert_fail_record("wrong_result", "crypto")
    _assert_cleaned_up(fake)


def test_qc4a_wrap_included_round_trip_break_fails() -> None:
    fake = _PolicyFake(decrypt_corrupt=True)
    _run_must_fail(_qc4a_wrap, _rs(fake), "included", "classic")
    _assert_fail_record("wrong_result", "crypto")
    _assert_cleaned_up(fake)


def test_qc4a_wrap_excluded_policy_refusal_passes() -> None:
    fake = _PolicyFake(wrap_script=[None, None, _KEY_NOT_PERMITTED])
    _qc4a_wrap(_rs(fake), "excluded", "classic")
    _assert_terminal_pass()
    record = _terminal_record()
    assert record.reason == "sanctioned_refusal", record.summary
    assert record.actual_ckr == ckr_name(_KEY_NOT_PERMITTED), record.summary
    _assert_cleaned_up(fake)


@pytest.mark.parametrize("rv", [_FUNCTION_FAILED, _ACTION_PROHIBITED])
def test_qc4a_wrap_excluded_alternate_refusal_xfails(rv: int) -> None:
    fake = _PolicyFake(wrap_script=[None, None, rv])
    assert_xfails(_qc4a_wrap, _rs(fake), "excluded", "classic")
    record = _assert_xfail_record("nonspec_reject")
    assert record.actual_ckr == ckr_name(rv), record.summary
    _assert_cleaned_up(fake)


def test_qc4a_wrap_excluded_undefined_rv_fails_metadata() -> None:
    fake = _PolicyFake(wrap_script=[None, None, _UNDEFINED_RV])
    _run_must_fail(_qc4a_wrap, _rs(fake), "excluded", "classic")
    _assert_fail_record("self_contradiction", "metadata")
    _assert_cleaned_up(fake)


def test_qc4a_wrap_excluded_control_refused_voids() -> None:
    fake = _PolicyFake(wrap_script=[_FUNCTION_FAILED])
    assert_xfails(_qc4a_wrap, _rs(fake), "excluded", "classic")
    _assert_xfail_record("not_operational")
    _assert_cleaned_up(fake)


def test_qc4a_wrap_control_malformed_blob_voids() -> None:
    """F5: an unvalidated control blob voids; never PASS + shaped refusal."""
    fake = _PolicyFake(
        wrap_script=[None, None, _KEY_NOT_PERMITTED],
        wrap_blob_for={0: b"short"},
    )
    assert_xfails(_qc4a_wrap, _rs(fake), "excluded", "classic")
    record = _assert_xfail_record("not_operational")
    assert "control" in (record.summary or "").lower(), record.summary
    _assert_cleaned_up(fake)


def test_qc4a_wrap_control_incoherent_use_fails() -> None:
    """F5: the control runs the same re-unwrap/round-trip effect check."""
    fake = _PolicyFake(
        wrap_script=[None, None, _KEY_NOT_PERMITTED],
        decrypt_output_for={("unwrap-control", _AES_ECB): b"W" * 16},
    )
    _run_must_fail(_qc4a_wrap, _rs(fake), "excluded", "classic")
    _assert_fail_record("wrong_result", "crypto")
    _assert_cleaned_up(fake)


@pytest.mark.parametrize("use", ["classic", "message"])
def test_qc4a_wrap_excluded_completion_is_bypass_fail(use: str) -> None:
    fake = _PolicyFake()
    _run_must_fail(_qc4a_wrap, _rs(fake), "excluded", use)
    record = _assert_fail_record("self_contradiction", "policy")
    assert "bypass" in (record.summary or "").lower(), record.summary
    _assert_cleaned_up(fake)
    _assert_no_secret_bytes()


def test_qc4a_wrap_excluded_completion_locally_proved_still_fails() -> None:
    """F9: a locally proved bypass FAILs before a later re-unwrap refusal can unprove it."""
    fake = _PolicyFake(unwrap_script=[None, _FUNCTION_FAILED])
    _run_must_fail(_qc4a_wrap, _rs(fake), "excluded", "classic")
    record = _assert_fail_record("self_contradiction", "policy")
    assert "bypass" in (record.summary or "").lower(), record.summary
    assert (record.detail or {}).get("key_match") is True, record.detail
    _assert_cleaned_up(fake)


def test_qc4a_wrap_setup_import_refused_voids() -> None:
    fake = _PolicyFake(create_script=[_FUNCTION_FAILED])
    assert_xfails(_qc4a_wrap, _rs(fake), "included", "classic")
    _assert_xfail_record("not_operational")
    _assert_nothing_leaked(fake)


def test_qc4a_wrap_missing_mechanism_skips() -> None:
    fake = _PolicyFake()
    mechs = set(_ALL_MECHS) - {"AES_KEY_WRAP"}
    assert_skips(_qc4a_wrap, _rs(fake, mechs=mechs), "included", "classic")


def test_qc4a_wrap_message_unsupported_skips() -> None:
    fake = _PolicyFake(message_supported=False)
    assert_skips(_qc4a_wrap, _rs(fake), "included", "message")
    _assert_cleaned_up(fake)


# -- QC4a unwrap --------------------------------------------------------------------


@pytest.mark.parametrize("use", ["classic", "message"])
def test_qc4a_unwrap_included_success_passes(use: str) -> None:
    """Included unwrap completes; the unwrapped key is oracle-verified + round-trips."""
    fake = _PolicyFake()
    _qc4a_unwrap(_rs(fake), "included", use)
    _assert_terminal_pass()
    record = _terminal_record()
    assert record.reason == "sanctioned_refusal", record.summary
    assert (record.detail or {}).get("oracle_match") is True, record.detail
    assert (record.detail or {}).get("round_trip") is True, record.detail
    assert "peer_allowed_mechanisms" in (record.detail or {}), record.detail
    _assert_cleaned_up(fake)
    _assert_no_secret_bytes()


def test_qc4a_unwrap_blob_premise_refused_voids() -> None:
    """Without a wrappable blob premise the unwrap leg voids as setup."""
    fake = _PolicyFake(wrap_script=[_FUNCTION_FAILED])
    assert_xfails(_qc4a_unwrap, _rs(fake), "included", "classic")
    record = _assert_xfail_record("not_operational")
    assert record.actual_ckr == ckr_name(_FUNCTION_FAILED), record.summary
    _assert_cleaned_up(fake)


def test_qc4a_unwrap_included_control_refused_voids() -> None:
    fake = _PolicyFake(unwrap_script=[_FUNCTION_FAILED])
    assert_xfails(_qc4a_unwrap, _rs(fake), "included", "classic")
    record = _assert_xfail_record("not_operational")
    assert record.actual_ckr == ckr_name(_FUNCTION_FAILED), record.summary
    _assert_cleaned_up(fake)


@pytest.mark.parametrize("rv", [_FUNCTION_FAILED, _KEY_NOT_PERMITTED])
def test_qc4a_unwrap_included_refusal_is_deviation_xfail(rv: int) -> None:
    fake = _PolicyFake(unwrap_script=[None, rv])
    assert_xfails(_qc4a_unwrap, _rs(fake), "included", "classic")
    record = _assert_xfail_record("honest_deviation")
    assert record.actual_ckr == ckr_name(rv), record.summary
    _assert_cleaned_up(fake)


def test_qc4a_unwrap_included_wrong_material_fails() -> None:
    """An unwrapped key outside the known-target oracle fails wrong_result."""
    fake = _PolicyFake(unwrap_value=b"Z" * 16)
    _run_must_fail(_qc4a_unwrap, _rs(fake), "included", "classic")
    _assert_fail_record("wrong_result", "crypto")
    _assert_cleaned_up(fake)


def test_qc4a_unwrap_included_round_trip_break_fails() -> None:
    fake = _PolicyFake(decrypt_corrupt=True)
    _run_must_fail(_qc4a_unwrap, _rs(fake), "included", "classic")
    _assert_fail_record("wrong_result", "crypto")
    _assert_cleaned_up(fake)


def test_qc4a_unwrap_included_use_refused_is_unproved() -> None:
    fake = _PolicyFake(encrypt_rv={("unwrap", _AES_ECB): _FUNCTION_FAILED})
    assert_xfails(_qc4a_unwrap, _rs(fake), "included", "classic")
    record = _assert_xfail_record("honest_deviation")
    assert (record.detail or {}).get("disposition") == "unproved-effect", record.detail
    _assert_cleaned_up(fake)


def test_qc4a_unwrap_excluded_policy_refusal_passes() -> None:
    fake = _PolicyFake(unwrap_script=[None, _KEY_NOT_PERMITTED])
    _qc4a_unwrap(_rs(fake), "excluded", "classic")
    _assert_terminal_pass()
    record = _terminal_record()
    assert record.reason == "sanctioned_refusal", record.summary
    assert record.actual_ckr == ckr_name(_KEY_NOT_PERMITTED), record.summary
    _assert_cleaned_up(fake)


@pytest.mark.parametrize("rv", [_FUNCTION_FAILED, _ACTION_PROHIBITED])
def test_qc4a_unwrap_excluded_alternate_refusal_xfails(rv: int) -> None:
    fake = _PolicyFake(unwrap_script=[None, rv])
    assert_xfails(_qc4a_unwrap, _rs(fake), "excluded", "classic")
    record = _assert_xfail_record("nonspec_reject")
    assert record.actual_ckr == ckr_name(rv), record.summary
    _assert_cleaned_up(fake)


def test_qc4a_unwrap_excluded_vendor_refusal_xfails() -> None:
    fake = _PolicyFake(unwrap_script=[None, _VENDOR_RV])
    assert_xfails(_qc4a_unwrap, _rs(fake), "excluded", "classic")
    _assert_xfail_record("nonspec_reject")
    _assert_cleaned_up(fake)


def test_qc4a_unwrap_excluded_undefined_rv_fails_metadata() -> None:
    fake = _PolicyFake(unwrap_script=[None, _UNDEFINED_RV])
    _run_must_fail(_qc4a_unwrap, _rs(fake), "excluded", "classic")
    _assert_fail_record("self_contradiction", "metadata")
    _assert_cleaned_up(fake)


def test_qc4a_unwrap_excluded_control_refused_voids() -> None:
    fake = _PolicyFake(unwrap_script=[_FUNCTION_FAILED])
    assert_xfails(_qc4a_unwrap, _rs(fake), "excluded", "classic")
    _assert_xfail_record("not_operational")
    _assert_cleaned_up(fake)


def test_qc4a_unwrap_control_wrong_material_fails() -> None:
    """F5: an incorrect control unwrapped key fails; never PASS + shaped refusal."""
    fake = _PolicyFake(
        unwrap_script=[None, _KEY_NOT_PERMITTED],
        unwrap_value_for={"unwrap-control": b"W" * 16},
    )
    _run_must_fail(_qc4a_unwrap, _rs(fake), "excluded", "classic")
    record = _assert_fail_record("wrong_result", "crypto")
    assert "control" in (record.summary or "").lower(), record.summary
    _assert_cleaned_up(fake)


@pytest.mark.parametrize("use", ["classic", "message"])
def test_qc4a_unwrap_excluded_completion_is_bypass_fail(use: str) -> None:
    fake = _PolicyFake()
    _run_must_fail(_qc4a_unwrap, _rs(fake), "excluded", use)
    record = _assert_fail_record("self_contradiction", "policy")
    assert "bypass" in (record.summary or "").lower(), record.summary
    _assert_cleaned_up(fake)
    _assert_no_secret_bytes()


def test_qc4a_unwrap_excluded_completion_unusable_is_unproved() -> None:
    fake = _PolicyFake(encrypt_rv={("unwrap", _AES_ECB): _FUNCTION_FAILED})
    assert_xfails(_qc4a_unwrap, _rs(fake), "excluded", "classic")
    record = _assert_xfail_record("honest_deviation")
    assert (record.detail or {}).get("disposition") == "unproved-effect", record.detail
    _assert_cleaned_up(fake)


def test_qc4a_unwrap_setup_import_refused_voids() -> None:
    fake = _PolicyFake(create_script=[_FUNCTION_FAILED])
    assert_xfails(_qc4a_unwrap, _rs(fake), "included", "classic")
    _assert_xfail_record("not_operational")
    _assert_nothing_leaked(fake)


def test_qc4a_unwrap_claim_readback_refused_voids() -> None:
    fake = _PolicyFake(get_attr_script=[_DEVICE_ERROR])
    assert_xfails(_qc4a_unwrap, _rs(fake), "excluded", "classic")
    record = _assert_xfail_record("not_operational")
    assert record.actual_ckr == ckr_name(_DEVICE_ERROR), record.summary
    _assert_cleaned_up(fake)


def test_qc4a_unwrap_missing_mechanism_skips() -> None:
    fake = _PolicyFake()
    mechs = set(_ALL_MECHS) - {"AES_KEY_WRAP"}
    assert_skips(_qc4a_unwrap, _rs(fake, mechs=mechs), "included", "classic")


def test_qc4a_unwrap_message_unsupported_skips() -> None:
    fake = _PolicyFake(message_supported=False)
    assert_skips(_qc4a_unwrap, _rs(fake), "included", "message")
    _assert_cleaned_up(fake)


def test_qc4a_unwrap_message_round_trip_break_fails() -> None:
    fake = _PolicyFake(decrypt_corrupt=True)
    _run_must_fail(_qc4a_unwrap, _rs(fake), "included", "message")
    _assert_fail_record("wrong_result", "crypto")
    _assert_cleaned_up(fake)


# -- QC4a encapsulate -----------------------------------------------------------------


def test_qc4a_encaps_included_success_passes() -> None:
    """Included encaps completes; both sides yield the identical 32-byte secret."""
    fake = _PolicyFake()
    _qc4a_encaps(_rs(fake), "included")
    _assert_terminal_pass()
    record = _terminal_record()
    assert record.reason == "sanctioned_refusal", record.summary
    assert (record.detail or {}).get("secrets_match") is True, record.detail
    assert (record.detail or {}).get("secret_len") == 32, record.detail
    assert "peer_allowed_mechanisms" in (record.detail or {}), record.detail
    _assert_cleaned_up(fake)
    _assert_no_secret_bytes()


def test_qc4a_encaps_keygen_refused_voids() -> None:
    fake = _PolicyFake(keypair_script=[_FUNCTION_FAILED])
    assert_xfails(_qc4a_encaps, _rs(fake), "included")
    record = _assert_xfail_record("not_operational")
    assert record.actual_ckr == ckr_name(_FUNCTION_FAILED), record.summary
    _assert_nothing_leaked(fake)


def test_qc4a_encaps_claim_mismatch_voids() -> None:
    blob = _encode_value(int(CKA_ALLOWED_MECHANISMS), [_AES_ECB])
    fake = _PolicyFake(raw_readback={("keypair", int(CKA_ALLOWED_MECHANISMS)): blob})
    assert_xfails(_qc4a_encaps, _rs(fake), "included")
    _assert_xfail_record("not_operational")
    _assert_cleaned_up(fake)


def test_qc4a_encaps_included_control_refused_voids() -> None:
    fake = _PolicyFake(encaps_script=[_FUNCTION_FAILED])
    assert_xfails(_qc4a_encaps, _rs(fake), "included")
    record = _assert_xfail_record("not_operational")
    assert record.actual_ckr == ckr_name(_FUNCTION_FAILED), record.summary
    _assert_cleaned_up(fake)


@pytest.mark.parametrize("rv", [_FUNCTION_FAILED, _KEY_NOT_PERMITTED])
def test_qc4a_encaps_included_refusal_is_deviation_xfail(rv: int) -> None:
    fake = _PolicyFake(encaps_script=[None, None, rv])
    assert_xfails(_qc4a_encaps, _rs(fake), "included")
    record = _assert_xfail_record("honest_deviation")
    assert record.actual_ckr == ckr_name(rv), record.summary
    _assert_cleaned_up(fake)


def test_qc4a_encaps_included_short_ct_fails() -> None:
    """A non-1088-byte ML-KEM-768 ciphertext fails crypto wrong_result."""
    fake = _PolicyFake(encaps_ct=b"E" * 100)
    _run_must_fail(_qc4a_encaps, _rs(fake), "included")
    _assert_fail_record("wrong_result", "crypto")
    _assert_cleaned_up(fake)


def test_qc4a_encaps_included_empty_ct_fails() -> None:
    fake = _PolicyFake(encaps_ct=b"")
    _run_must_fail(_qc4a_encaps, _rs(fake), "included")
    _assert_fail_record("wrong_result", "crypto")
    _assert_cleaned_up(fake)


def test_qc4a_encaps_included_decaps_refused_is_unproved() -> None:
    fake = _PolicyFake(decaps_script=[None, _FUNCTION_FAILED])
    assert_xfails(_qc4a_encaps, _rs(fake), "included")
    record = _assert_xfail_record("honest_deviation")
    assert (record.detail or {}).get("disposition") == "unproved-effect", record.detail
    _assert_cleaned_up(fake)


def test_qc4a_encaps_included_secret_mismatch_fails() -> None:
    fake = _PolicyFake(decaps_secret=b"D" * 32)
    _run_must_fail(_qc4a_encaps, _rs(fake), "included")
    record = _assert_fail_record("wrong_result", "crypto")
    assert "kem sides disagree" in (record.summary or "").lower(), record.summary
    _assert_cleaned_up(fake)


def test_qc4a_encaps_included_short_secret_fails() -> None:
    fake = _PolicyFake(decaps_secret=b"D" * 16)
    _run_must_fail(_qc4a_encaps, _rs(fake), "included")
    _assert_fail_record("wrong_result", "crypto")
    _assert_cleaned_up(fake)


def test_qc4a_encaps_included_empty_secret_fails() -> None:
    fake = _PolicyFake(decaps_secret=b"")
    _run_must_fail(_qc4a_encaps, _rs(fake), "included")
    _assert_fail_record("wrong_result", "crypto")
    _assert_cleaned_up(fake)


def test_qc4a_encaps_included_secret_unreadable_is_unproved() -> None:
    fake = _PolicyFake(hide_for={"encaps": {int(CKA_VALUE)}, "decaps": {int(CKA_VALUE)}})
    assert_xfails(_qc4a_encaps, _rs(fake), "included")
    record = _assert_xfail_record("honest_deviation")
    assert (record.detail or {}).get("disposition") == "unproved-effect", record.detail
    _assert_cleaned_up(fake)


def test_qc4a_encaps_excluded_policy_refusal_passes() -> None:
    fake = _PolicyFake(encaps_script=[None, None, _KEY_NOT_PERMITTED])
    _qc4a_encaps(_rs(fake), "excluded")
    _assert_terminal_pass()
    record = _terminal_record()
    assert record.reason == "sanctioned_refusal", record.summary
    assert record.actual_ckr == ckr_name(_KEY_NOT_PERMITTED), record.summary
    _assert_cleaned_up(fake)


@pytest.mark.parametrize("rv", [_FUNCTION_FAILED, _ACTION_PROHIBITED, _MECHANISM_INVALID])
def test_qc4a_encaps_excluded_alternate_refusal_xfails(rv: int) -> None:
    fake = _PolicyFake(encaps_script=[None, None, rv])
    assert_xfails(_qc4a_encaps, _rs(fake), "excluded")
    record = _assert_xfail_record("nonspec_reject")
    assert record.actual_ckr == ckr_name(rv), record.summary
    _assert_cleaned_up(fake)


def test_qc4a_encaps_excluded_vendor_refusal_xfails() -> None:
    fake = _PolicyFake(encaps_script=[None, None, _VENDOR_RV])
    assert_xfails(_qc4a_encaps, _rs(fake), "excluded")
    _assert_xfail_record("nonspec_reject")
    _assert_cleaned_up(fake)


def test_qc4a_encaps_excluded_undefined_rv_fails_metadata() -> None:
    fake = _PolicyFake(encaps_script=[None, None, _UNDEFINED_RV])
    _run_must_fail(_qc4a_encaps, _rs(fake), "excluded")
    _assert_fail_record("self_contradiction", "metadata")
    _assert_cleaned_up(fake)


def test_qc4a_encaps_excluded_control_refused_voids() -> None:
    fake = _PolicyFake(encaps_script=[_FUNCTION_FAILED])
    assert_xfails(_qc4a_encaps, _rs(fake), "excluded")
    _assert_xfail_record("not_operational")
    _assert_cleaned_up(fake)


def test_qc4a_encaps_control_secret_mismatch_fails() -> None:
    """F5: a disagreeing control KEM pair fails; never PASS + shaped refusal."""
    fake = _PolicyFake(
        encaps_script=[None, None, _KEY_NOT_PERMITTED],
        encaps_secret_for={"encaps-control": b"W" * 32},
    )
    _run_must_fail(_qc4a_encaps, _rs(fake), "excluded")
    record = _assert_fail_record("wrong_result", "crypto")
    assert "control" in (record.summary or "").lower(), record.summary
    _assert_cleaned_up(fake)


def test_qc4a_encaps_excluded_completion_is_bypass_fail() -> None:
    fake = _PolicyFake()
    _run_must_fail(_qc4a_encaps, _rs(fake), "excluded")
    record = _assert_fail_record("self_contradiction", "policy")
    assert "bypass" in (record.summary or "").lower(), record.summary
    _assert_cleaned_up(fake)
    _assert_no_secret_bytes()


def test_qc4a_encaps_excluded_completion_unusable_is_unproved() -> None:
    fake = _PolicyFake(decaps_script=[None, _FUNCTION_FAILED])
    assert_xfails(_qc4a_encaps, _rs(fake), "excluded")
    record = _assert_xfail_record("honest_deviation")
    assert (record.detail or {}).get("disposition") == "unproved-effect", record.detail
    _assert_cleaned_up(fake)


def test_qc4a_encaps_excluded_completion_mismatch_fails_crypto() -> None:
    fake = _PolicyFake(decaps_secret=b"D" * 32)
    _run_must_fail(_qc4a_encaps, _rs(fake), "excluded")
    _assert_fail_record("wrong_result", "crypto")
    _assert_cleaned_up(fake)


def test_qc4a_encaps_missing_mechanism_skips() -> None:
    fake = _PolicyFake()
    mechs = set(_ALL_MECHS) - {"ML_KEM"}
    assert_skips(_qc4a_encaps, _rs(fake, mechs=mechs), "included")


def test_qc4a_encaps_missing_keygen_skips() -> None:
    fake = _PolicyFake()
    mechs = set(_ALL_MECHS) - {"ML_KEM_KEY_PAIR_GEN"}
    assert_skips(_qc4a_encaps, _rs(fake, mechs=mechs), "included")


# -- QC4a decapsulate -----------------------------------------------------------------


def test_qc4a_decaps_included_success_passes() -> None:
    """Included decaps completes; the secret equals the encaps side byte-wise."""
    fake = _PolicyFake()
    _qc4a_decaps(_rs(fake), "included")
    _assert_terminal_pass()
    record = _terminal_record()
    assert record.reason == "sanctioned_refusal", record.summary
    assert (record.detail or {}).get("secrets_match") is True, record.detail
    assert (record.detail or {}).get("secret_len") == 32, record.detail
    assert "peer_allowed_mechanisms" in (record.detail or {}), record.detail
    _assert_cleaned_up(fake)
    _assert_no_secret_bytes()


def test_qc4a_decaps_premise_encaps_refused_voids() -> None:
    """Without a premise ciphertext the decaps leg voids as setup."""
    fake = _PolicyFake(encaps_script=[_FUNCTION_FAILED])
    assert_xfails(_qc4a_decaps, _rs(fake), "included")
    record = _assert_xfail_record("not_operational")
    assert record.actual_ckr == ckr_name(_FUNCTION_FAILED), record.summary
    _assert_cleaned_up(fake)


def test_qc4a_decaps_included_control_refused_voids() -> None:
    fake = _PolicyFake(decaps_script=[_FUNCTION_FAILED])
    assert_xfails(_qc4a_decaps, _rs(fake), "included")
    record = _assert_xfail_record("not_operational")
    assert record.actual_ckr == ckr_name(_FUNCTION_FAILED), record.summary
    _assert_cleaned_up(fake)


@pytest.mark.parametrize("rv", [_FUNCTION_FAILED, _KEY_NOT_PERMITTED])
def test_qc4a_decaps_included_refusal_is_deviation_xfail(rv: int) -> None:
    fake = _PolicyFake(decaps_script=[None, rv])
    assert_xfails(_qc4a_decaps, _rs(fake), "included")
    record = _assert_xfail_record("honest_deviation")
    assert record.actual_ckr == ckr_name(rv), record.summary
    _assert_cleaned_up(fake)


def test_qc4a_decaps_included_secret_mismatch_fails() -> None:
    fake = _PolicyFake(decaps_secret=b"D" * 32)
    _run_must_fail(_qc4a_decaps, _rs(fake), "included")
    _assert_fail_record("wrong_result", "crypto")
    _assert_cleaned_up(fake)


def test_qc4a_decaps_included_short_secret_fails() -> None:
    fake = _PolicyFake(decaps_secret=b"D" * 31)
    _run_must_fail(_qc4a_decaps, _rs(fake), "included")
    _assert_fail_record("wrong_result", "crypto")
    _assert_cleaned_up(fake)


def test_qc4a_decaps_included_secret_unreadable_is_unproved() -> None:
    fake = _PolicyFake(hide_for={"encaps": {int(CKA_VALUE)}, "decaps": {int(CKA_VALUE)}})
    assert_xfails(_qc4a_decaps, _rs(fake), "included")
    record = _assert_xfail_record("honest_deviation")
    assert (record.detail or {}).get("disposition") == "unproved-effect", record.detail
    _assert_cleaned_up(fake)


def test_qc4a_decaps_excluded_policy_refusal_passes() -> None:
    fake = _PolicyFake(decaps_script=[None, _KEY_NOT_PERMITTED])
    _qc4a_decaps(_rs(fake), "excluded")
    _assert_terminal_pass()
    record = _terminal_record()
    assert record.reason == "sanctioned_refusal", record.summary
    assert record.actual_ckr == ckr_name(_KEY_NOT_PERMITTED), record.summary
    _assert_cleaned_up(fake)


@pytest.mark.parametrize("rv", [_FUNCTION_FAILED, _ACTION_PROHIBITED])
def test_qc4a_decaps_excluded_alternate_refusal_xfails(rv: int) -> None:
    fake = _PolicyFake(decaps_script=[None, rv])
    assert_xfails(_qc4a_decaps, _rs(fake), "excluded")
    record = _assert_xfail_record("nonspec_reject")
    assert record.actual_ckr == ckr_name(rv), record.summary
    _assert_cleaned_up(fake)


def test_qc4a_decaps_excluded_undefined_rv_fails_metadata() -> None:
    fake = _PolicyFake(decaps_script=[None, _UNDEFINED_RV])
    _run_must_fail(_qc4a_decaps, _rs(fake), "excluded")
    _assert_fail_record("self_contradiction", "metadata")
    _assert_cleaned_up(fake)


def test_qc4a_decaps_excluded_control_refused_voids() -> None:
    fake = _PolicyFake(decaps_script=[_FUNCTION_FAILED])
    assert_xfails(_qc4a_decaps, _rs(fake), "excluded")
    _assert_xfail_record("not_operational")
    _assert_cleaned_up(fake)


def test_qc4a_decaps_control_secret_mismatch_fails() -> None:
    """F5: a disagreeing control decaps pair fails; never PASS + shaped refusal."""
    fake = _PolicyFake(
        encaps_script=[None, None, None, None],
        decaps_script=[None, _KEY_NOT_PERMITTED],
        decaps_secret_for={"decaps-control": b"W" * 32},
    )
    _run_must_fail(_qc4a_decaps, _rs(fake), "excluded")
    record = _assert_fail_record("wrong_result", "crypto")
    assert "control" in (record.summary or "").lower(), record.summary
    _assert_cleaned_up(fake)


def test_qc4a_encaps_cleanup_failure_attempts_all_handles() -> None:
    """F14: a raising destroy does not skip the remaining owned handles."""
    # Destroy order on success: control secrets, main secrets, then the four
    # keys; the boom hits the first key destroy with three still pending.
    fake = _PolicyFake(destroy_script=[None, None, None, None, RuntimeError("boom")])
    with pytest.raises(RuntimeError, match="boom"):
        _qc4a_encaps(_rs(fake), "included")
    assert set(fake.destroy_calls) >= set(fake.created), (fake.created, fake.destroy_calls)


def test_qc4a_wrap_bypass_fail_survives_cleanup_failure() -> None:
    """F14: a cleanup exception never replaces the primary contradiction."""
    # Control cleanup healthy; the boom lands in the FAIL unwind's finally.
    fake = _PolicyFake(destroy_script=[None, RuntimeError("boom")])
    _run_must_fail(_qc4a_wrap, _rs(fake), "excluded", "classic")
    _assert_fail_record("self_contradiction", "policy")
    assert set(fake.destroy_calls) >= set(fake.created), (fake.created, fake.destroy_calls)


def test_qc4b_create_leak_evidence_survives_cleanup_failure() -> None:
    """F14: leak evidence is recorded before cleanup runs; a destroy failure keeps it."""
    label = _attempt_label("create", "rsa", "missing_modulus")
    fake = _PolicyFake(
        create_script=[None, _TEMPLATE_INCONSISTENT],
        leak_labeled=label,
        # Control destroy healthy; the leaked handle's destroy raises.
        destroy_script=[None, RuntimeError("boom")],
    )
    _run_must_fail(_qc4b_create, _rs(fake), "rsa", "missing_modulus")
    record = _assert_fail_record("self_contradiction", "lifecycle")
    assert (record.detail or {}).get("leaked_count") == 1, record.detail


def test_cleanup_owned_multiple_failures_group_without_primary(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """F16: several QC4 cleanup failures with no primary raise grouped, labeled."""
    mod = _policy_module()
    calls: list[int] = []

    def _boom(_raw: Any, _sh: Any, handle: int) -> None:
        calls.append(handle)
        raise OSError(f"cleanup failed for {handle}")

    monkeypatch.setattr(mod, "destroy_quietly", _boom)
    rs = SimpleNamespace(raw=object(), sh=1)
    with pytest.raises(BaseExceptionGroup, match="QC4 owned-handle cleanup failures") as exc_info:
        mod._cleanup_owned(rs, [1, 2])
    assert [str(exc) for exc in exc_info.value.exceptions] == [
        "cleanup failed for 1",
        "cleanup failed for 2",
    ]
    assert calls == [1, 2]
    notes = getattr(exc_info.value.exceptions[0], "__notes__", [])
    assert any("owned handle 1" in note for note in notes), notes


def test_rsa_priv_from_components_inconsistent_is_none() -> None:
    """F16: inconsistent RSA components rebuild to None (unwitnessable, never loud)."""
    mod = _policy_module()
    _, _, key = mod.rsa2048_material()
    numbers = key.private_numbers()

    def _be(value: int) -> bytes:
        return int(value).to_bytes((int(value).bit_length() + 7) // 8 or 1, "big")

    rebuild = mod._rsa_priv_from_components(
        _be(numbers.public_numbers.n),
        _be(numbers.public_numbers.e),
        _be(numbers.d),
        _be(numbers.p),
        _be(numbers.q),
        _be(numbers.dmp1),
        _be(numbers.dmq1),
        _be(numbers.iqmp),
    )
    assert rebuild is not None
    assert (
        mod._rsa_priv_from_components(
            _be(numbers.public_numbers.n),
            _be(numbers.public_numbers.e),
            _be(numbers.d),
            _be(numbers.p),
            _be(numbers.q),
            _be(numbers.dmp1),
            _be(numbers.dmq1),
            b"\x00",
        )
        is None
    )


def test_ec_priv_from_scalar_invalid_is_none() -> None:
    """F16: an invalid P-256 scalar rebuilds to None (unwitnessable, never loud)."""
    mod = _policy_module()
    assert mod._ec_priv_from_scalar(b"\x00" * 32) is None
    assert mod._ec_priv_from_scalar(b"") is None


def test_find_by_label_without_finalize_still_propagates() -> None:
    """F16: a failing inventory without C_FindObjectsFinal keeps its own error."""
    from pkcs11_check.raw.rv import CkrAssertionError

    mod = _policy_module()

    def _init(_sh: int, _tmpl: Any, _count: int) -> int:
        return _OK

    def _find(_sh: int, _handles: Any, _size: int, _found: Any) -> int:
        return _DEVICE_ERROR

    rs = SimpleNamespace(raw=SimpleNamespace(C_FindObjectsInit=_init, C_FindObjects=_find), sh=1)
    with pytest.raises(CkrAssertionError) as exc_info:
        mod._find_by_label(rs, "qc4a-wrap-included-t")
    assert exc_info.value.rv == _DEVICE_ERROR, exc_info.value


def test_qc4a_decaps_excluded_completion_is_bypass_fail() -> None:
    fake = _PolicyFake()
    _run_must_fail(_qc4a_decaps, _rs(fake), "excluded")
    record = _assert_fail_record("self_contradiction", "policy")
    assert "bypass" in (record.summary or "").lower(), record.summary
    _assert_cleaned_up(fake)
    _assert_no_secret_bytes()


def test_qc4a_decaps_excluded_completion_unusable_is_unproved() -> None:
    fake = _PolicyFake(hide_for={"encaps": {int(CKA_VALUE)}, "decaps": {int(CKA_VALUE)}})
    assert_xfails(_qc4a_decaps, _rs(fake), "excluded")
    record = _assert_xfail_record("honest_deviation")
    assert (record.detail or {}).get("disposition") == "unproved-effect", record.detail
    _assert_cleaned_up(fake)


def test_qc4a_decaps_claim_readback_refused_voids() -> None:
    fake = _PolicyFake(get_attr_script=[_DEVICE_ERROR])
    assert_xfails(_qc4a_decaps, _rs(fake), "excluded")
    _assert_xfail_record("not_operational")
    _assert_cleaned_up(fake)


def test_qc4a_decaps_keygen_refused_voids() -> None:
    fake = _PolicyFake(keypair_script=[_FUNCTION_FAILED])
    assert_xfails(_qc4a_decaps, _rs(fake), "included")
    _assert_xfail_record("not_operational")
    _assert_nothing_leaked(fake)


def test_qc4a_decaps_missing_mechanism_skips() -> None:
    fake = _PolicyFake()
    mechs = set(_ALL_MECHS) - {"ML_KEM"}
    assert_skips(_qc4a_decaps, _rs(fake, mechs=mechs), "included")


# -- QC4b matrix ----------------------------------------------------------------------

# Hardcoded at collection time (the provider module is absent on BASE); pinned
# against the provider constants by test_malformed_cell_inventory_is_pinned.
_CREATE_CELLS = [
    ("rsa", "swap_secret_class_asym_type"),
    ("rsa", "swap_asym_class_secret_type"),
    ("rsa", "missing_modulus"),
    ("rsa", "missing_exponent"),
    ("ec", "swap_secret_class_asym_type"),
    ("ec", "swap_asym_class_secret_type"),
    ("ec", "missing_params"),
    ("ec", "missing_point"),
    ("pqc", "swap_secret_class_asym_type"),
    ("pqc", "swap_asym_class_secret_type"),
    ("pqc", "missing_params"),
]
_UNWRAP_CELLS = [
    ("rsa", "swap_secret_class_asym_type"),
    ("rsa", "swap_asym_class_secret_type"),
    ("ec", "swap_secret_class_asym_type"),
    ("ec", "swap_asym_class_secret_type"),
    ("pqc", "swap_secret_class_asym_type"),
    ("pqc", "swap_asym_class_secret_type"),
]
_GENERATE_CELLS = [
    ("rsa", "swap_secret_class_asym_type"),
    ("rsa", "swap_asym_class_secret_type"),
    ("rsa", "missing_modulus_bits"),
    ("ec", "swap_secret_class_asym_type"),
    ("ec", "swap_asym_class_secret_type"),
    ("ec", "missing_params"),
    ("pqc", "swap_secret_class_asym_type"),
    ("pqc", "swap_asym_class_secret_type"),
    ("pqc", "missing_params"),
]
_QC4C_MALS = [
    "swap_secret_class_asym_type",
    "swap_asym_class_secret_type",
    "missing_modulus",
    "missing_exponent",
]


def _attempt_label(operation: str, family: str, malformation: str) -> bytes:
    mod = _policy_module()
    label: str = mod.malformed_label(operation, family, malformation)
    return label.encode("utf-8")


def _create_unusable_kwargs(family: str, malformation: str) -> dict[str, Any]:
    """Scripts forcing the accepted-create use leg to find no usable material."""
    if family == "pqc":
        kwargs: dict[str, Any] = {"verify_script": [_FUNCTION_FAILED]}
        if malformation == "swap_asym_class_secret_type":
            kwargs["encrypt_rv"] = {("create", _AES_ECB): _KEY_TYPE_INCONSISTENT}
        return kwargs
    if malformation in ("swap_secret_class_asym_type", "swap_asym_class_secret_type"):
        return {"encrypt_rv": {("create", _AES_ECB): _KEY_TYPE_INCONSISTENT}}
    if malformation == "missing_exponent":
        return {"encrypt_rv": {("create", _RSA_PKCS): _KEY_TYPE_INCONSISTENT}}
    return {}


@pytest.mark.parametrize(
    ("family", "malformation"),
    [
        ("rsa", "swap_secret_class_asym_type"),
        ("rsa", "swap_asym_class_secret_type"),
        ("ec", "swap_secret_class_asym_type"),
        ("ec", "swap_asym_class_secret_type"),
        ("pqc", "swap_asym_class_secret_type"),
    ],
)
def test_qc4b_create_aes_cell_control_is_aes_shaped(family: str, malformation: str) -> None:
    """F7: an AES-material cell gets an AES control, never an RSA/EC one."""
    fake = _PolicyFake(create_script=[None, _TEMPLATE_INCONSISTENT])
    _qc4b_create(_rs(fake), family, malformation)
    _assert_terminal_pass()
    assert len(fake.create_templates) == 2, "legal control must run before the attempt"
    control = fake.create_templates[0]
    assert _decode_ulong(control[int(CKA_CLASS)]) == int(CKO_SECRET_KEY), control
    assert _decode_ulong(control[int(CKA_KEY_TYPE)]) == int(CKK_AES), control


@pytest.mark.parametrize(
    ("family", "malformation"),
    [
        ("rsa", "swap_secret_class_asym_type"),
        ("rsa", "swap_asym_class_secret_type"),
        ("ec", "swap_secret_class_asym_type"),
        ("ec", "swap_asym_class_secret_type"),
        ("pqc", "swap_asym_class_secret_type"),
    ],
)
def test_qc4b_create_aes_incapable_module_voids_aes_cell(family: str, malformation: str) -> None:
    """F7: RSA-capable/AES-incapable + malformed AES cell must NOT pass."""
    fake = _PolicyFake(create_refuse_key_type={int(CKK_AES): _TEMPLATE_INCONSISTENT})
    assert_xfails(_qc4b_create, _rs(fake), family, malformation)
    record = _assert_xfail_record("not_operational")
    assert record.actual_ckr == ckr_name(_TEMPLATE_INCONSISTENT), record.summary
    assert len(fake.create_templates) == 1, "void must precede the malformed attempt"


@pytest.mark.parametrize(("family", "malformation"), _CREATE_CELLS)
def test_qc4b_create_control_refused_voids(family: str, malformation: str) -> None:
    """A refused well-formed control voids the whole cell, never passes it."""
    fake = _PolicyFake(create_script=[_TEMPLATE_INCONSISTENT])
    assert_xfails(_qc4b_create, _rs(fake), family, malformation)
    record = _assert_xfail_record("not_operational")
    assert record.actual_ckr == ckr_name(_TEMPLATE_INCONSISTENT), record.summary
    assert len(fake.create_templates) == 1, "void must precede the malformed attempt"
    _assert_nothing_leaked(fake)


@pytest.mark.parametrize(("family", "malformation"), _CREATE_CELLS)
def test_qc4b_create_refuse_zero_delta_passes(family: str, malformation: str) -> None:
    """Clean refusal + zero inventory delta passes with the RV preserved."""
    fake = _PolicyFake(create_script=[None, _TEMPLATE_INCONSISTENT])
    _qc4b_create(_rs(fake), family, malformation)
    _assert_terminal_pass()
    record = _terminal_record()
    assert record.reason == "sanctioned_refusal", record.summary
    assert record.actual_ckr == ckr_name(_TEMPLATE_INCONSISTENT), record.summary
    assert (record.detail or {}).get("inventory_delta") == 0, record.detail
    assert len(fake.create_templates) == 2, "legal control must run before the attempt"
    _assert_cleaned_up(fake)
    _assert_no_secret_bytes()


@pytest.mark.parametrize("litter", [0, 10, 300])
def test_qc4b_create_refusal_with_litter_baseline_passes(litter: int) -> None:
    """F12: pre-existing inventory is subtracted (multi-page included); no leak passes."""
    label = _attempt_label("create", "rsa", "swap_secret_class_asym_type")
    fake = _PolicyFake(create_script=[None, _TEMPLATE_INCONSISTENT])
    fake.plant_litter(label, litter)
    _qc4b_create(_rs(fake), "rsa", "swap_secret_class_asym_type")
    _assert_terminal_pass()
    record = _terminal_record()
    assert (record.detail or {}).get("inventory_delta") == 0, record.detail


def test_qc4b_create_refusal_past_256_litter_still_catches_leak() -> None:
    """F12: 256 pre-existing + 1 leaked object must FAIL (no 256 cap)."""
    label = _attempt_label("create", "rsa", "swap_secret_class_asym_type")
    fake = _PolicyFake(create_script=[None, _TEMPLATE_INCONSISTENT], leak_labeled=label)
    fake.plant_litter(label, 256)
    preexisting = set(fake.created)
    _run_must_fail(_qc4b_create, _rs(fake), "rsa", "swap_secret_class_asym_type")
    record = _assert_fail_record("self_contradiction", "lifecycle")
    assert (record.detail or {}).get("leaked_count") == 1, record.detail
    assert set(fake.destroyed) >= (set(fake.created) - preexisting)


@pytest.mark.parametrize(("family", "malformation"), _CREATE_CELLS)
def test_qc4b_create_refuse_leak_fails(family: str, malformation: str) -> None:
    """A refusal that still creates the labeled object fails as a leaked object."""
    label = _attempt_label("create", family, malformation)
    fake = _PolicyFake(create_script=[None, _TEMPLATE_INCONSISTENT], leak_labeled=label)
    _run_must_fail(_qc4b_create, _rs(fake), family, malformation)
    record = _assert_fail_record("self_contradiction", "lifecycle")
    assert "leak" in (record.summary or "").lower(), record.summary
    _assert_cleaned_up(fake)


@pytest.mark.parametrize(("family", "malformation"), _CREATE_CELLS)
def test_qc4b_create_accept_unusable_xfails(family: str, malformation: str) -> None:
    """Accepted-but-unusable material is a visible deviation, never a quiet pass."""
    label = _attempt_label("create", family, malformation)
    kwargs = _create_unusable_kwargs(family, malformation)
    if family == "ec":
        # F8: the role-appropriate Verify op must be attempted (and refused)
        # before "unusable" is honest; seed the known point so it is.
        _, known_point, _ = _policy_module().ec_p256_material()
        fake = _PolicyFake(**{**kwargs, "verify_script": [_FUNCTION_FAILED]})
        fake._extra_for_label = label
        fake._extra_attrs = {int(CKA_EC_POINT): known_point}
    else:
        fake = _PolicyFake(**kwargs)
    assert_xfails(_qc4b_create, _rs(fake), family, malformation)
    record = _assert_xfail_record("honest_deviation")
    assert record.actual_ckr == ckr_name(_OK), record.summary
    assert (record.detail or {}).get("disposition") == "inspected-unusable", record.detail
    assert (record.detail or {}).get("use_attempted") is True, record.detail
    _assert_cleaned_up(fake)
    _assert_no_secret_bytes()


def test_qc4b_create_ec_valid_public_verifies_refuses_sign() -> None:
    """F8: a valid pubkey that verifies but refuses Sign is usable, never unusable."""
    fake = _PolicyFake()
    assert_xfails(_qc4b_create, _rs(fake), "ec", "missing_params")
    record = _assert_xfail_record("honest_deviation")
    assert (record.detail or {}).get("disposition") == "accepted-coherent", record.detail
    assert (record.detail or {}).get("coherent_uses") == ["ec_verify"], record.detail
    _assert_cleaned_up(fake)


def test_qc4b_create_ec_verify_invalid_fails_crypto() -> None:
    """F16: a module rejecting a locally valid signature contradicts itself."""
    fake = _PolicyFake(verify_script=[_SIGNATURE_INVALID])
    _run_must_fail(_qc4b_create, _rs(fake), "ec", "missing_params")
    record = _assert_fail_record("wrong_result", "crypto")
    assert "locally valid signature" in (record.summary or ""), record.summary
    _assert_cleaned_up(fake)
    _assert_no_secret_bytes()


def test_qc4b_create_ec_unwitnessed_verify_is_unproved_not_unusable() -> None:
    """F8: an unwitnessable role op yields unproved, never 'inspected-unusable'."""
    fake = _PolicyFake(encrypt_rv={("create", _AES_ECB): _FUNCTION_FAILED})
    assert_xfails(_qc4b_create, _rs(fake), "ec", "swap_secret_class_asym_type")
    record = _assert_xfail_record("honest_deviation")
    assert (record.detail or {}).get("disposition") == "unproved-effect", record.detail
    _assert_cleaned_up(fake)


def test_qc4b_create_ec_sign_unverifiable_without_point_is_unproved() -> None:
    """F16: a successful but uninterpretable sign is unproved, never unusable."""
    fake = _PolicyFake(
        encrypt_rv={("create", _AES_ECB): _FUNCTION_FAILED},
        sign_output=b"G" * 64,
    )
    assert_xfails(_qc4b_create, _rs(fake), "ec", "swap_secret_class_asym_type")
    record = _assert_xfail_record("honest_deviation")
    assert (record.detail or {}).get("disposition") == "unproved-effect", record.detail
    assert _reported_outcome() == "xfail", [rec.reason for rec in C.get_records()]
    _assert_cleaned_up(fake)
    _assert_no_secret_bytes()


def test_qc4b_create_witnessed_aes_use_survives_halves_refusal() -> None:
    """F9: a witnessed type confusion FAILs even if a later component read refuses."""
    fake = _PolicyFake(get_attr_script=[None, None, _DEVICE_ERROR])
    _run_must_fail(_qc4b_create, _rs(fake), "ec", "swap_secret_class_asym_type")
    record = _assert_fail_record("self_contradiction", "policy")
    assert "aes" in (record.summary or "").lower(), record.summary
    _assert_cleaned_up(fake)


@pytest.mark.parametrize(("family", "malformation"), _CREATE_CELLS)
def test_qc4b_create_attempt_requests_role_usage(family: str, malformation: str) -> None:
    """F8: create attempts request the usage attribute their exercise role needs."""
    expected = {"rsa": CKA_ENCRYPT, "ec": CKA_VERIFY, "pqc": CKA_VERIFY}[family]
    fake = _PolicyFake(create_script=[None, _TEMPLATE_INCONSISTENT])
    _qc4b_create(_rs(fake), family, malformation)
    _assert_terminal_pass()
    attempt = fake.create_templates[1]
    assert _decode_bool(attempt[int(expected)]) is True, attempt


@pytest.mark.parametrize(("family", "malformation"), _UNWRAP_CELLS)
def test_qc4b_unwrap_attempt_requests_sign_usage(family: str, malformation: str) -> None:
    """F8: unwrap attempts exercise Sign, so they request CKA_SIGN (as does control)."""
    fake = _PolicyFake(unwrap_script=[None, _TEMPLATE_INCONSISTENT])
    _qc4b_unwrap(_rs(fake), family, malformation)
    _assert_terminal_pass()
    assert len(fake.unwrap_calls) == 2
    for call in fake.unwrap_calls:
        assert _decode_bool(call[int(CKA_SIGN)]) is True, call


@pytest.mark.parametrize(("family", "malformation"), _CREATE_CELLS)
def test_qc4b_create_accept_readback_refused_is_unproved(family: str, malformation: str) -> None:
    """Accepted creation with refused identity inspection never fails unproved."""
    script: list[int | None] = [None, None, _DEVICE_ERROR] if family == "pqc" else [_DEVICE_ERROR]
    fake = _PolicyFake(get_attr_script=script)
    assert_xfails(_qc4b_create, _rs(fake), family, malformation)
    record = _assert_xfail_record("honest_deviation")
    assert record.actual_ckr == ckr_name(_OK), record.summary
    assert (record.detail or {}).get("disposition") == "unproved-effect", record.detail
    _assert_cleaned_up(fake)


def test_qc4b_create_missing_identity_is_unproved(monkeypatch: pytest.MonkeyPatch) -> None:
    """F16: an accepted object omitting class/type never fails; effect unproved."""
    mod = _policy_module()
    monkeypatch.setattr(mod, "read_qc3_attributes", lambda *args, **kwargs: {})
    fake = _PolicyFake()
    assert_xfails(_qc4b_create, _rs(fake), "rsa", "swap_secret_class_asym_type")
    record = _assert_xfail_record("honest_deviation")
    assert record.actual_ckr == ckr_name(_OK), record.summary
    assert (record.detail or {}).get("disposition") == "unproved-effect", record.detail
    assert "unreadable" in (record.summary or ""), record.summary
    assert _reported_outcome() == "xfail", [rec.reason for rec in C.get_records()]
    _assert_cleaned_up(fake)
    _assert_no_secret_bytes()


def test_qc4b_create_alternate_standard_refusal_passes() -> None:
    """Any standard refusal of a malformed template passes (RV preserved)."""
    fake = _PolicyFake(create_script=[None, _FUNCTION_FAILED])
    _qc4b_create(_rs(fake), "rsa", "missing_modulus")
    _assert_terminal_pass()
    record = _terminal_record()
    assert record.actual_ckr == ckr_name(_FUNCTION_FAILED), record.summary
    _assert_cleaned_up(fake)


def test_qc4b_create_vendor_refusal_xfails() -> None:
    fake = _PolicyFake(create_script=[None, _VENDOR_RV])
    assert_xfails(_qc4b_create, _rs(fake), "rsa", "missing_modulus")
    record = _assert_xfail_record("nonspec_reject")
    assert record.label == "C_CreateObject malformed rsa/missing_modulus", record.label
    assert record.operation == "C_CreateObject", record.operation
    assert record.actual_ckr == ckr_name(_VENDOR_RV), record.summary
    detail = record.detail or {}
    assert detail.get("refusal_rv") == ckr_name(_VENDOR_RV), detail
    assert detail.get("inventory_delta") == 0, detail
    assert _reported_outcome() == "xfail", [rec.reason for rec in C.get_records()]
    assert fake._find_seq == 2, "post-refusal inventory must run (N7)"
    _assert_cleaned_up(fake)


def test_qc4b_create_undefined_rv_fails_metadata() -> None:
    fake = _PolicyFake(create_script=[None, _UNDEFINED_RV])
    _run_must_fail(_qc4b_create, _rs(fake), "rsa", "missing_modulus")
    _assert_fail_record("self_contradiction", "metadata")
    _assert_cleaned_up(fake)


@pytest.mark.parametrize(
    ("family", "malformation"),
    [
        ("rsa", "swap_secret_class_asym_type"),
        ("rsa", "swap_asym_class_secret_type"),
        ("ec", "swap_secret_class_asym_type"),
        ("ec", "swap_asym_class_secret_type"),
    ],
)
def test_qc4b_create_swap_aes_use_fails(family: str, malformation: str) -> None:
    """AES-coherent use of a kept-malformed swap identity fails as contradiction."""
    fake = _PolicyFake()
    _run_must_fail(_qc4b_create, _rs(fake), family, malformation)
    record = _assert_fail_record("self_contradiction", "policy")
    assert "malformed" in (record.summary or "").lower(), record.summary
    _assert_cleaned_up(fake)
    _assert_no_secret_bytes()


def test_qc4b_create_swap_normalized_coherent_xfails() -> None:
    """Coherent use under a normalized well-formed identity is deviation, not fail."""
    label = _attempt_label("create", "rsa", "swap_secret_class_asym_type")
    fake = _PolicyFake(
        extra_for_label=label,
        extra_attrs={int(CKA_CLASS): int(CKO_SECRET_KEY), int(CKA_KEY_TYPE): int(CKK_AES)},
    )
    assert_xfails(_qc4b_create, _rs(fake), "rsa", "swap_secret_class_asym_type")
    record = _assert_xfail_record("honest_deviation")
    assert (record.detail or {}).get("disposition") == "accepted-coherent", record.detail
    assert (record.detail or {}).get("identity_kept") is False, record.detail
    _assert_cleaned_up(fake)


def test_qc4b_create_aes_oracle_mismatch_fails_crypto() -> None:
    """F16: admitted AES use missing the known-key oracle fails wrong_result."""
    fake = _PolicyFake(encrypt_output_for={("create", _AES_ECB): b"W" * 16})
    _run_must_fail(_qc4b_create, _rs(fake), "rsa", "swap_secret_class_asym_type")
    record = _assert_fail_record("wrong_result", "crypto")
    assert "oracle" in (record.summary or ""), record.summary
    _assert_cleaned_up(fake)
    _assert_no_secret_bytes()


def test_qc4b_create_aes_malformed_output_fails_crypto() -> None:
    """F16: malformed successful AES output fails wrong_result before the oracle."""
    fake = _PolicyFake(encrypt_output_for={("create", _AES_ECB): b"W" * 20})
    _run_must_fail(_qc4b_create, _rs(fake), "rsa", "swap_secret_class_asym_type")
    record = _assert_fail_record("wrong_result", "crypto")
    assert "observed_len" in (record.summary or ""), record.summary
    _assert_cleaned_up(fake)
    _assert_no_secret_bytes()


def test_qc4b_create_aes_encrypt_refused_carries_use_rv() -> None:
    """F16: a refused AES acceptance use keeps its RV in the unusable evidence."""
    fake = _PolicyFake(encrypt_rv={("create", _AES_ECB): _FUNCTION_FAILED})
    assert_xfails(_qc4b_create, _rs(fake), "rsa", "swap_secret_class_asym_type")
    record = _assert_xfail_record("honest_deviation")
    assert (record.detail or {}).get("disposition") == "inspected-unusable", record.detail
    use_rvs = (record.detail or {}).get("use_rvs")
    assert isinstance(use_rvs, list), record.detail
    assert ckr_name(_FUNCTION_FAILED) in use_rvs, record.detail
    _assert_cleaned_up(fake)
    _assert_no_secret_bytes()


def test_qc4b_create_missing_exponent_unreadable_oracle_is_unproved() -> None:
    """F3: an unreadable admitted exponent cannot be interpreted; never wrong_result."""
    fake = _PolicyFake()
    assert_xfails(_qc4b_create, _rs(fake), "rsa", "missing_exponent")
    record = _assert_xfail_record("honest_deviation")
    assert (record.detail or {}).get("disposition") == "unproved-effect", record.detail
    # R2: the absent component read records not_operational (key components
    # are required, hence hatch-free); the complete reported outcome through
    # the real hook stays the leg's own xfail -- record + xfail consistent.
    component = [
        rec
        for rec in C.get_records()
        if rec.reason == "not_operational" and rec.operation == "C_GetAttributeValue"
    ]
    assert len(component) == 1, [(rec.reason, rec.operation) for rec in C.get_records()]
    assert component[0].actual_ckr == ckr_name(_TYPE_INVALID), component[0].summary
    assert _reported_outcome() == "xfail", [rec.reason for rec in C.get_records()]
    _assert_cleaned_up(fake)


def test_qc4b_create_component_contradiction_fails_self_contradiction() -> None:
    """R2: component refusal-with-data fails loud (fail-fast), never noted-and-xfailed.

    Plain attr_or_record records the proved self-contradiction; the read
    raises for it immediately so a None return always means xfail downstream.
    """
    label = _attempt_label("create", "rsa", "missing_exponent")
    leak = b"\x01\x00\x01"
    fake = _PolicyFake(
        contradict_readback={(label, int(CKA_PUBLIC_EXPONENT)): (_TYPE_INVALID, leak)}
    )
    _run_must_fail(_qc4b_create, _rs(fake), "rsa", "missing_exponent")
    record = _assert_fail_record("self_contradiction", "policy")
    assert record.actual_ckr == ckr_name(_TYPE_INVALID), record.summary
    assert (record.detail or {}).get("leaked_len") == len(leak), record.detail
    assert _reported_outcome() == "fail", [rec.reason for rec in C.get_records()]
    _assert_cleaned_up(fake)
    _assert_no_secret_bytes()


def _alternate_valid_exponent() -> tuple[bytes, bytes]:
    """A valid admitted (modulus, exponent) differing from the seeded exponent."""
    from math import gcd

    mod = _policy_module()
    modulus, _, priv = mod.rsa2048_material()
    numbers = priv.private_numbers()
    lam = (numbers.p - 1) * (numbers.q - 1) // gcd(numbers.p - 1, numbers.q - 1)
    for candidate in (3, 5, 17, 257, 19, 7, 11):
        if candidate != numbers.public_numbers.e and gcd(candidate, lam) == 1:
            entry = candidate.to_bytes((candidate.bit_length() + 7) // 8, "big")
            return modulus, entry
    raise AssertionError("no alternate valid exponent found")


def test_qc4b_create_missing_exponent_admitted_exponent_coherent() -> None:
    """F3: correct encryption under a different valid exponent is not wrong_result."""
    label = _attempt_label("create", "rsa", "missing_exponent")
    modulus, exponent = _alternate_valid_exponent()
    fake = _PolicyFake()
    fake._extra_for_label = label
    fake._extra_attrs = {int(CKA_MODULUS): modulus, int(CKA_PUBLIC_EXPONENT): exponent}
    assert_xfails(_qc4b_create, _rs(fake), "rsa", "missing_exponent")
    record = _assert_xfail_record("honest_deviation")
    assert (record.detail or {}).get("disposition") == "accepted-coherent", record.detail
    _assert_cleaned_up(fake)


def test_qc4b_create_missing_exponent_broken_module_fails_crypto() -> None:
    """F3: genuine breakage under the admitted oracle still fails wrong_result."""
    label = _attempt_label("create", "rsa", "missing_exponent")
    modulus, exponent = _alternate_valid_exponent()
    fake = _PolicyFake(encrypt_output_for={("create", _RSA_PKCS): b"Z" * 256})
    fake._extra_for_label = label
    fake._extra_attrs = {int(CKA_MODULUS): modulus, int(CKA_PUBLIC_EXPONENT): exponent}
    _run_must_fail(_qc4b_create, _rs(fake), "rsa", "missing_exponent")
    _assert_fail_record("wrong_result", "crypto")
    _assert_cleaned_up(fake)


def test_qc4b_create_rsa_wrong_plaintext_fails_crypto() -> None:
    """F16: admitted encrypt decrypting to the wrong plaintext fails wrong_result."""
    modulus, exponent, priv = _policy_module().rsa2048_material()
    label = _attempt_label("create", "rsa", "missing_exponent")
    wrong = priv.public_key().encrypt(b"wrong-plaintext!!", padding.PKCS1v15())
    fake = _PolicyFake(
        encrypt_output_for={("create", _RSA_PKCS): wrong},
        extra_for_label=label,
        extra_attrs={int(CKA_MODULUS): modulus, int(CKA_PUBLIC_EXPONENT): exponent},
    )
    _run_must_fail(_qc4b_create, _rs(fake), "rsa", "missing_exponent")
    record = _assert_fail_record("wrong_result", "crypto")
    assert "wrong plaintext" in (record.summary or ""), record.summary
    _assert_cleaned_up(fake)
    _assert_no_secret_bytes()


def test_qc4b_create_missing_exponent_foreign_modulus_is_unproved() -> None:
    """F16: an admitted key on a foreign modulus cannot be interpreted; unproved."""
    foreign = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    foreign_n = int(foreign.public_key().public_numbers().n).to_bytes(256, "big")
    label = _attempt_label("create", "rsa", "missing_exponent")
    fake = _PolicyFake(
        extra_for_label=label,
        extra_attrs={int(CKA_MODULUS): foreign_n, int(CKA_PUBLIC_EXPONENT): b"\x01\x00\x01"},
    )
    assert_xfails(_qc4b_create, _rs(fake), "rsa", "missing_exponent")
    record = _assert_xfail_record("honest_deviation")
    assert (record.detail or {}).get("disposition") == "unproved-effect", record.detail
    assert _reported_outcome() == "xfail", [rec.reason for rec in C.get_records()]
    _assert_cleaned_up(fake)
    _assert_no_secret_bytes()


def test_rsa_oracle_for_admitted_uninvertible_exponent_is_none() -> None:
    """F16: an admitted exponent with no inverse yields no oracle (unproved).

    Pinned directly: through a leg the fake needs an odd encryptable
    exponent, whose invertibility is key-dependent; e=lambda(n) has no
    inverse for every key, deterministically. The leg treats None as
    unproved (foreign-modulus contract above).
    """
    from math import gcd

    mod = _policy_module()
    modulus, _, key = mod.rsa2048_material()
    numbers = key.private_numbers()
    p, q = int(numbers.p), int(numbers.q)
    lam = (p - 1) * (q - 1) // gcd(p - 1, q - 1)
    assert mod._rsa_oracle_for_admitted(key, (modulus, lam.to_bytes(256, "big"))) is None


def test_use_rsa_encrypt_decrypt_failure_fails_crypto(monkeypatch: pytest.MonkeyPatch) -> None:
    """F16: a decrypt-failing oracle fails wrong_result (classic-platform arm).

    OpenSSL >= 4 implicit rejection returns bytes instead of raising, so this
    ValueError arm is platform-conditional; the stub simulates classic padding
    validation to pin its terminal shape.
    """
    mod = _policy_module()
    modulus, _, _ = mod.rsa2048_material()

    class _RaisingOracle:
        @staticmethod
        def decrypt(_ciphertext: bytes, _padding: Any) -> bytes:
            raise ValueError("decryption failed")

    monkeypatch.setattr(mod, "_rsa_oracle_for_admitted", lambda *args, **kwargs: _RaisingOracle())
    fake = _PolicyFake()
    handle = fake._store({int(CKA_MODULUS): modulus}, role="create")
    with pytest.raises(Failed):
        mod._use_rsa_encrypt(
            _rs(fake),
            handle,
            private_key=object(),
            admitted=(modulus, b"\x01\x00\x01"),
            label="probe",
            operation="C_CreateObject",
            spec_ref="test",
        )
    record = _assert_fail_record("wrong_result", "crypto")
    assert "does not decrypt" in (record.summary or ""), record.summary


def test_qc4b_create_rsa_encrypt_refused_carries_use_rv() -> None:
    """F16: a refused RSA acceptance use keeps its RV in the unusable evidence."""
    fake = _PolicyFake(encrypt_rv={("create", _RSA_PKCS): _KEY_TYPE_INCONSISTENT})
    assert_xfails(_qc4b_create, _rs(fake), "rsa", "missing_exponent")
    record = _assert_xfail_record("honest_deviation")
    assert (record.detail or {}).get("disposition") == "inspected-unusable", record.detail
    assert (record.detail or {}).get("use_rvs") == [ckr_name(_KEY_TYPE_INCONSISTENT)], record.detail
    _assert_cleaned_up(fake)
    _assert_no_secret_bytes()


def test_qc4b_create_missing_exponent_filled_exponent_coherent() -> None:
    """A module-filled standard exponent verifies under the admitted oracle."""
    label = _attempt_label("create", "rsa", "missing_exponent")
    fake = _PolicyFake()
    _material_modulus, _material_exponent, _ = _policy_module().rsa2048_material()
    assert _material_exponent == b"\x01\x00\x01", _material_exponent
    fake._extra_for_label = label
    fake._extra_attrs = {
        int(CKA_MODULUS): _material_modulus,
        int(CKA_PUBLIC_EXPONENT): _material_exponent,
    }
    assert_xfails(_qc4b_create, _rs(fake), "rsa", "missing_exponent")
    record = _assert_xfail_record("honest_deviation")
    assert (record.detail or {}).get("disposition") == "accepted-coherent", record.detail
    _assert_cleaned_up(fake)


def test_qc4b_create_missing_modulus_success_is_unproved() -> None:
    """Encrypt success without verifiable halves never fails unproved."""
    label = _attempt_label("create", "rsa", "missing_modulus")
    fake = _PolicyFake()
    modulus, _ = fake.rsa_numbers()
    fake._extra_for_label = label
    fake._extra_attrs = {int(CKA_MODULUS): modulus}
    assert_xfails(_qc4b_create, _rs(fake), "rsa", "missing_modulus")
    record = _assert_xfail_record("honest_deviation")
    assert (record.detail or {}).get("disposition") == "unproved-effect", record.detail
    _assert_cleaned_up(fake)


def test_qc4b_create_ec_missing_params_sign_valid_fails() -> None:
    """A verifiable signature from a malformed EC identity fails cross-type use."""
    label = _attempt_label("create", "ec", "missing_params")
    fake = _PolicyFake(sign_key="ec")
    fake._extra_for_label = label
    fake._extra_attrs = {int(CKA_EC_POINT): fake.ec_point_der()}
    _run_must_fail(_qc4b_create, _rs(fake), "ec", "missing_params")
    record = _assert_fail_record("self_contradiction", "policy")
    assert (
        "cross-type" in (record.summary or "").lower()
        or "malformed" in (record.summary or "").lower()
    ), record.summary
    _assert_cleaned_up(fake)


def test_qc4b_create_ec_missing_params_sign_invalid_is_unproved() -> None:
    """With unknown params an invalid EC signature proves nothing (curve uncertain)."""
    label = _attempt_label("create", "ec", "missing_params")
    fake = _PolicyFake(sign_output=b"B" * 64)
    fake._extra_for_label = label
    fake._extra_attrs = {int(CKA_EC_POINT): fake.ec_point_der()}
    assert_xfails(_qc4b_create, _rs(fake), "ec", "missing_params")
    record = _assert_xfail_record("honest_deviation")
    assert (record.detail or {}).get("disposition") == "unproved-effect", record.detail
    _assert_cleaned_up(fake)


def test_qc4b_create_ec_missing_point_sign_valid_fails() -> None:
    """Known-curve sign success under a fabricated point fails cross-type use."""
    label = _attempt_label("create", "ec", "missing_point")
    fake = _PolicyFake(sign_key="ec")
    fake._extra_for_label = label
    fake._extra_attrs = {int(CKA_EC_POINT): fake.ec_point_der()}
    _run_must_fail(_qc4b_create, _rs(fake), "ec", "missing_point")
    _assert_fail_record("self_contradiction", "policy")
    _assert_cleaned_up(fake)


def test_qc4b_create_ec_missing_point_sign_invalid_fails_crypto() -> None:
    """Known curve + known point + invalid signature fails crypto wrong_result."""
    label = _attempt_label("create", "ec", "missing_point")
    fake = _PolicyFake(sign_output=b"B" * 64)
    fake._extra_for_label = label
    fake._extra_attrs = {int(CKA_EC_POINT): fake.ec_point_der()}
    _run_must_fail(_qc4b_create, _rs(fake), "ec", "missing_point")
    _assert_fail_record("wrong_result", "crypto")
    _assert_cleaned_up(fake)


def test_qc4b_create_ec_raw_signature_coherent_not_wrong_result() -> None:
    """F2: a correct raw ECDSA signer verifies; never false wrong_result."""
    label = _attempt_label("create", "ec", "missing_point")
    fake = _PolicyFake()
    fake._sign_output = fake.raw_ecdsa_over(_policy_module().QC4_ECDSA_DIGEST)
    fake._extra_for_label = label
    fake._extra_attrs = {int(CKA_EC_POINT): fake.ec_point_der()}
    _run_must_fail(_qc4b_create, _rs(fake), "ec", "missing_point")
    record = _assert_fail_record("self_contradiction", "policy")
    assert "cross-type" in (record.summary or "").lower(), record.summary
    _assert_cleaned_up(fake)


def test_qc4b_create_ec_tampered_raw_signature_fails_crypto() -> None:
    """F2: a tampered raw ECDSA signature fails crypto wrong_result."""
    label = _attempt_label("create", "ec", "missing_point")
    fake = _PolicyFake()
    good = fake.raw_ecdsa_over(_policy_module().QC4_ECDSA_DIGEST)
    bad = bytes([good[0] ^ 0xFF]) + good[1:]
    assert len(bad) == 64
    fake._sign_output = bad
    fake._extra_for_label = label
    fake._extra_attrs = {int(CKA_EC_POINT): fake.ec_point_der()}
    _run_must_fail(_qc4b_create, _rs(fake), "ec", "missing_point")
    _assert_fail_record("wrong_result", "crypto")
    _assert_cleaned_up(fake)


def test_qc4b_create_ec_short_signature_fails_crypto() -> None:
    """F4: a 63-byte P-256 ECDSA output fails crypto wrong_result, never unproved."""
    label = _attempt_label("create", "ec", "missing_point")
    fake = _PolicyFake(sign_output=b"B" * 63)
    fake._extra_for_label = label
    fake._extra_attrs = {int(CKA_EC_POINT): fake.ec_point_der()}
    _run_must_fail(_qc4b_create, _rs(fake), "ec", "missing_point")
    record = _assert_fail_record("wrong_result", "crypto")
    assert (record.detail or {}).get("sig_len") == 63, record.detail
    assert (record.detail or {}).get("expected_sig_len") == 64, record.detail
    _assert_cleaned_up(fake)


def test_qc4b_create_pqc_empty_signature_fails_crypto() -> None:
    """F4: an empty PQC signature fails crypto wrong_result before adjudication."""
    fake = _PolicyFake(sign_output=b"")
    _run_must_fail(_qc4b_create, _rs(fake), "pqc", "swap_secret_class_asym_type")
    record = _assert_fail_record("wrong_result", "crypto")
    assert (record.detail or {}).get("sig_len") == 0, record.detail
    _assert_cleaned_up(fake)


def test_qc4b_create_pqc_wrong_length_signature_fails_crypto() -> None:
    """F4: a wrong-length PQC signature fails crypto wrong_result (ML-DSA-65: 3309)."""
    fake = _PolicyFake(sign_output=b"G" * 100)
    _run_must_fail(_qc4b_create, _rs(fake), "pqc", "swap_secret_class_asym_type")
    record = _assert_fail_record("wrong_result", "crypto")
    assert (record.detail or {}).get("sig_len") == 100, record.detail
    assert (record.detail or {}).get("expected_sig_len") == _ML_DSA_65_SIG_LEN, record.detail
    _assert_cleaned_up(fake)


def test_qc4b_unwrap_pqc_wrong_length_signature_fails_crypto() -> None:
    """F4: the admitted-sign PQC leg gates shape before module verification."""
    fake = _PolicyFake(sign_output=b"G" * 100, verify_script=[_OK])
    _run_must_fail(_qc4b_unwrap, _rs(fake), "pqc", "swap_secret_class_asym_type")
    _assert_fail_record("wrong_result", "crypto")
    _assert_cleaned_up(fake)


def test_qc4b_unwrap_pqc_slh_wrong_length_signature_fails_crypto() -> None:
    """F4: the SLH-DSA fallback set gates its own fixed length (7856)."""
    fake = _PolicyFake(sign_output=b"G" * 100, verify_script=[_OK])
    _run_must_fail(
        _qc4b_unwrap, _rs(fake, mechs=_slh_only_mechs()), "pqc", "swap_secret_class_asym_type"
    )
    record = _assert_fail_record("wrong_result", "crypto")
    assert (record.detail or {}).get("expected_sig_len") == 7856, record.detail
    _assert_cleaned_up(fake)


def test_qc4b_create_pqc_swap_secret_verify_true_is_accepted_coherent() -> None:
    """F11: PQC module self-agreement is an accepted-coherent ceiling, never FAIL."""
    fake = _PolicyFake(verify_script=[_OK])
    assert_xfails(_qc4b_create, _rs(fake), "pqc", "swap_secret_class_asym_type")
    record = _assert_xfail_record("honest_deviation")
    assert (record.detail or {}).get("disposition") == "accepted-coherent", record.detail
    _assert_cleaned_up(fake)


def test_qc4b_create_pqc_swap_pub_verify_true_is_accepted_coherent() -> None:
    """F11: PQC module self-agreement is an accepted-coherent ceiling, never FAIL."""
    fake = _PolicyFake(
        encrypt_rv={("create", _AES_ECB): _KEY_TYPE_INCONSISTENT}, verify_script=[_OK]
    )
    assert_xfails(_qc4b_create, _rs(fake), "pqc", "swap_asym_class_secret_type")
    record = _assert_xfail_record("honest_deviation")
    assert (record.detail or {}).get("disposition") == "accepted-coherent", record.detail
    _assert_cleaned_up(fake)


def test_qc4b_create_pqc_unissued_signature_does_not_verify() -> None:
    """F11: a PQC signature the module did not produce does not verify (honest fake)."""
    fake = _PolicyFake(sign_output=b"X" * _ML_DSA_65_SIG_LEN)
    assert_xfails(_qc4b_create, _rs(fake), "pqc", "swap_secret_class_asym_type")
    record = _assert_xfail_record("honest_deviation")
    assert (record.detail or {}).get("disposition") == "inspected-unusable", record.detail
    _assert_cleaned_up(fake)


def test_qc4b_create_pqc_verify_false_xfails() -> None:
    """Invalid PQC verification on a malformed key is lenient, not wrong_result."""
    fake = _PolicyFake(verify_script=[_SIGNATURE_INVALID])
    assert_xfails(_qc4b_create, _rs(fake), "pqc", "swap_secret_class_asym_type")
    record = _assert_xfail_record("honest_deviation")
    assert (record.detail or {}).get("disposition") == "inspected-unusable", record.detail
    _assert_cleaned_up(fake)


def test_qc4b_create_pqc_verify_refused_carries_use_rv() -> None:
    """F16: a refused PQC module-verify keeps its RV in the unusable evidence."""
    fake = _PolicyFake(verify_script=[_FUNCTION_FAILED])
    assert_xfails(_qc4b_create, _rs(fake), "pqc", "swap_secret_class_asym_type")
    record = _assert_xfail_record("honest_deviation")
    assert (record.detail or {}).get("disposition") == "inspected-unusable", record.detail
    assert (record.detail or {}).get("use_rvs") == [ckr_name(_FUNCTION_FAILED)], record.detail
    _assert_cleaned_up(fake)
    _assert_no_secret_bytes()


def test_qc4b_create_pqc_sourcing_sign_refused_is_unproved() -> None:
    fake = _PolicyFake(sign_script=[_FUNCTION_FAILED])
    assert_xfails(_qc4b_create, _rs(fake), "pqc", "swap_secret_class_asym_type")
    record = _assert_xfail_record("honest_deviation")
    assert (record.detail or {}).get("disposition") == "unproved-effect", record.detail
    _assert_cleaned_up(fake)


def test_qc4b_create_pqc_sourcing_keygen_refused_voids() -> None:
    fake = _PolicyFake(keypair_script=[_FUNCTION_FAILED])
    assert_xfails(_qc4b_create, _rs(fake), "pqc", "missing_params")
    _assert_xfail_record("not_operational")
    _assert_nothing_leaked(fake)


def test_qc4b_create_pqc_sourcing_pub_unreadable_voids() -> None:
    fake = _PolicyFake(create_script=[None, _TEMPLATE_INCONSISTENT], hide={int(CKA_VALUE)})
    assert_xfails(_qc4b_create, _rs(fake), "pqc", "missing_params")
    _assert_xfail_record("not_operational")


@pytest.mark.parametrize(("family", "malformation"), _UNWRAP_CELLS)
def test_qc4b_unwrap_control_refused_voids(family: str, malformation: str) -> None:
    """A refused well-formed unwrap control voids the whole cell, never passes it."""
    fake = _PolicyFake(unwrap_script=[_TEMPLATE_INCONSISTENT])
    assert_xfails(_qc4b_unwrap, _rs(fake), family, malformation)
    record = _assert_xfail_record("not_operational")
    assert record.actual_ckr == ckr_name(_TEMPLATE_INCONSISTENT), record.summary
    assert len(fake.unwrap_calls) == 1, "void must precede the malformed attempt"
    _assert_cleaned_up(fake)


@pytest.mark.parametrize(("family", "malformation"), _UNWRAP_CELLS)
def test_qc4b_unwrap_refuse_zero_delta_passes(family: str, malformation: str) -> None:
    """Clean unwrap refusal + zero inventory delta passes with the RV preserved."""
    fake = _PolicyFake(unwrap_script=[None, _TEMPLATE_INCONSISTENT])
    _qc4b_unwrap(_rs(fake), family, malformation)
    _assert_terminal_pass()
    record = _terminal_record()
    assert record.reason == "sanctioned_refusal", record.summary
    assert record.actual_ckr == ckr_name(_TEMPLATE_INCONSISTENT), record.summary
    assert (record.detail or {}).get("inventory_delta") == 0, record.detail
    assert len(fake.unwrap_calls) == 2, "legal control must run before the attempt"
    assert len(fake.keypair_calls) == 1, "blob source pair must be generated"
    _assert_cleaned_up(fake)
    _assert_no_secret_bytes()


@pytest.mark.parametrize(("family", "malformation"), _UNWRAP_CELLS)
def test_qc4b_unwrap_refuse_leak_fails(family: str, malformation: str) -> None:
    """An unwrap refusal that still creates the labeled object fails as leaked."""
    label = _attempt_label("unwrap", family, malformation)
    fake = _PolicyFake(unwrap_script=[None, _TEMPLATE_INCONSISTENT], leak_labeled=label)
    _run_must_fail(_qc4b_unwrap, _rs(fake), family, malformation)
    record = _assert_fail_record("self_contradiction", "lifecycle")
    assert "leak" in (record.summary or "").lower(), record.summary
    _assert_cleaned_up(fake)


@pytest.mark.parametrize(("family", "malformation"), _UNWRAP_CELLS)
def test_qc4b_unwrap_accept_unusable_xfails(family: str, malformation: str) -> None:
    """Accepted-but-unusable unwrapped material is a visible deviation, not a pass."""
    kwargs: dict[str, Any] = {} if family == "pqc" else {"sign_script": [_FUNCTION_FAILED]}
    fake = _PolicyFake(**kwargs)
    assert_xfails(_qc4b_unwrap, _rs(fake), family, malformation)
    record = _assert_xfail_record("honest_deviation")
    assert record.actual_ckr == ckr_name(_OK), record.summary
    assert (record.detail or {}).get("disposition") == "inspected-unusable", record.detail
    assert (record.detail or {}).get("use_attempted") is True, record.detail
    _assert_cleaned_up(fake)
    _assert_no_secret_bytes()


@pytest.mark.parametrize(("family", "malformation"), _UNWRAP_CELLS)
def test_qc4b_unwrap_accept_readback_refused_is_unproved(family: str, malformation: str) -> None:
    """Accepted unwrap with refused identity inspection never fails unproved."""
    # Unwrap cells read no sourcing material: the inspection read is first.
    fake = _PolicyFake(get_attr_script=[_DEVICE_ERROR])
    assert_xfails(_qc4b_unwrap, _rs(fake), family, malformation)
    record = _assert_xfail_record("honest_deviation")
    assert record.actual_ckr == ckr_name(_OK), record.summary
    assert (record.detail or {}).get("disposition") == "unproved-effect", record.detail
    _assert_cleaned_up(fake)


def test_qc4b_unwrap_vendor_refusal_xfails() -> None:
    fake = _PolicyFake(unwrap_script=[None, _VENDOR_RV])
    assert_xfails(_qc4b_unwrap, _rs(fake), "ec", "swap_secret_class_asym_type")
    record = _assert_xfail_record("nonspec_reject")
    assert record.operation == "C_UnwrapKey", record.operation
    assert record.actual_ckr == ckr_name(_VENDOR_RV), record.summary
    detail = record.detail or {}
    assert detail.get("refusal_rv") == ckr_name(_VENDOR_RV), detail
    assert detail.get("inventory_delta") == 0, detail
    assert fake._find_seq == 2, "post-refusal inventory must run (N7)"
    _assert_cleaned_up(fake)


def test_qc4b_unwrap_undefined_rv_fails_metadata() -> None:
    fake = _PolicyFake(unwrap_script=[None, _UNDEFINED_RV])
    _run_must_fail(_qc4b_unwrap, _rs(fake), "ec", "swap_secret_class_asym_type")
    _assert_fail_record("self_contradiction", "metadata")
    _assert_cleaned_up(fake)


@pytest.mark.parametrize(
    "malformation", ["swap_secret_class_asym_type", "swap_asym_class_secret_type"]
)
def test_qc4b_unwrap_rsa_sign_valid_fails(malformation: str) -> None:
    """A valid RSA signature from a kept-malformed unwrap identity fails contradiction.

    N8 premise: the admitted object's own public halves read back (a real
    unwrapped private key carries them); verification runs under the
    admitted oracle, never substituted source components.
    """
    fake = _PolicyFake(sign_key="rsa")
    _modulus, _exponent = fake.rsa_numbers()
    fake._extra_for_label = _attempt_label("unwrap", "rsa", malformation)
    fake._extra_attrs = {int(CKA_MODULUS): _modulus, int(CKA_PUBLIC_EXPONENT): _exponent}
    _run_must_fail(_qc4b_unwrap, _rs(fake), "rsa", malformation)
    record = _assert_fail_record("self_contradiction", "policy")
    assert "malformed" in (record.summary or "").lower(), record.summary
    _assert_cleaned_up(fake)
    _assert_no_secret_bytes()


@pytest.mark.parametrize(
    "malformation", ["swap_secret_class_asym_type", "swap_asym_class_secret_type"]
)
def test_qc4b_unwrap_ec_sign_valid_fails(malformation: str) -> None:
    """N8 premise: admitted EC halves read back; no source substitution."""
    fake = _PolicyFake(sign_key="ec")
    fake._extra_for_label = _attempt_label("unwrap", "ec", malformation)
    fake._extra_attrs = {
        int(CKA_EC_PARAMS): _P256_PARAMS,
        int(CKA_EC_POINT): fake.ec_point_der(),
    }
    _run_must_fail(_qc4b_unwrap, _rs(fake), "ec", malformation)
    record = _assert_fail_record("self_contradiction", "policy")
    assert "malformed" in (record.summary or "").lower(), record.summary
    _assert_cleaned_up(fake)


def test_qc4b_unwrap_rsa_sign_invalid_fails_crypto() -> None:
    """N8 premise: invalidity is judged under the admitted (read-back) oracle."""
    fake = _PolicyFake(sign_output=b"B" * 256)
    _modulus, _exponent = fake.rsa_numbers()
    fake._extra_for_label = _attempt_label("unwrap", "rsa", "swap_secret_class_asym_type")
    fake._extra_attrs = {int(CKA_MODULUS): _modulus, int(CKA_PUBLIC_EXPONENT): _exponent}
    _run_must_fail(_qc4b_unwrap, _rs(fake), "rsa", "swap_secret_class_asym_type")
    _assert_fail_record("wrong_result", "crypto")
    _assert_cleaned_up(fake)


def test_qc4b_unwrap_ec_sign_invalid_fails_crypto() -> None:
    """N8 premise: invalidity is judged under the admitted (read-back) oracle."""
    fake = _PolicyFake(sign_output=b"B" * 64)
    fake._extra_for_label = _attempt_label("unwrap", "ec", "swap_secret_class_asym_type")
    fake._extra_attrs = {
        int(CKA_EC_PARAMS): _P256_PARAMS,
        int(CKA_EC_POINT): fake.ec_point_der(),
    }
    _run_must_fail(_qc4b_unwrap, _rs(fake), "ec", "swap_secret_class_asym_type")
    _assert_fail_record("wrong_result", "crypto")
    _assert_cleaned_up(fake)


def test_qc4b_unwrap_ec_malformed_signature_fails_crypto() -> None:
    """F4: a 63-byte P-256 ECDSA output fails crypto wrong_result, never unproved.

    N8 premise: the P-256 params grounding the gate read back from the
    admitted object itself.
    """
    fake = _PolicyFake(sign_output=b"B" * 63)
    fake._extra_for_label = _attempt_label("unwrap", "ec", "swap_secret_class_asym_type")
    fake._extra_attrs = {
        int(CKA_EC_PARAMS): _P256_PARAMS,
        int(CKA_EC_POINT): fake.ec_point_der(),
    }
    _run_must_fail(_qc4b_unwrap, _rs(fake), "ec", "swap_secret_class_asym_type")
    record = _assert_fail_record("wrong_result", "crypto")
    assert (record.detail or {}).get("sig_len") == 63, record.detail
    assert (record.detail or {}).get("expected_sig_len") == 64, record.detail
    _assert_cleaned_up(fake)


@pytest.mark.parametrize(
    "malformation", ["swap_secret_class_asym_type", "swap_asym_class_secret_type"]
)
def test_qc4b_unwrap_pqc_module_coherent_is_accepted_coherent(
    malformation: str,
) -> None:
    """F11: PQC module self-agreement is an accepted-coherent ceiling, never FAIL."""
    fake = _PolicyFake(sign_output=b"G" * _ML_DSA_65_SIG_LEN, verify_script=[_OK])
    assert_xfails(_qc4b_unwrap, _rs(fake), "pqc", malformation)
    record = _assert_xfail_record("honest_deviation")
    assert (record.detail or {}).get("disposition") == "accepted-coherent", record.detail
    _assert_cleaned_up(fake)


def test_qc4b_unwrap_pqc_verify_false_xfails() -> None:
    fake = _PolicyFake(sign_output=b"G" * _ML_DSA_65_SIG_LEN, verify_script=[_SIGNATURE_INVALID])
    assert_xfails(_qc4b_unwrap, _rs(fake), "pqc", "swap_secret_class_asym_type")
    record = _assert_xfail_record("honest_deviation")
    assert (record.detail or {}).get("disposition") == "inspected-unusable", record.detail
    _assert_cleaned_up(fake)


def test_qc4b_unwrap_pqc_trusted_verify_refused_is_unproved() -> None:
    """F16: refused trusted PQC verification leaves the unwrap effect unproved."""
    fake = _PolicyFake(sign_output=b"G" * _ML_DSA_65_SIG_LEN, verify_script=[_FUNCTION_FAILED])
    assert_xfails(_qc4b_unwrap, _rs(fake), "pqc", "swap_secret_class_asym_type")
    record = _assert_xfail_record("honest_deviation")
    assert (record.detail or {}).get("disposition") == "unproved-effect", record.detail
    assert (record.detail or {}).get("use_rvs") == [ckr_name(_FUNCTION_FAILED)], record.detail
    _assert_cleaned_up(fake)
    _assert_no_secret_bytes()


def test_qc4b_unwrap_source_keygen_refused_voids() -> None:
    fake = _PolicyFake(keypair_script=[_FUNCTION_FAILED])
    assert_xfails(_qc4b_unwrap, _rs(fake), "rsa", "swap_secret_class_asym_type")
    _assert_xfail_record("not_operational")
    _assert_nothing_leaked(fake)


def test_qc4b_unwrap_blob_wrap_refused_voids() -> None:
    fake = _PolicyFake(wrap_script=[_FUNCTION_FAILED])
    assert_xfails(_qc4b_unwrap, _rs(fake), "rsa", "swap_secret_class_asym_type")
    _assert_xfail_record("not_operational")
    _assert_cleaned_up(fake)


def test_qc4b_unwrap_setup_import_refused_voids() -> None:
    fake = _PolicyFake(create_script=[_FUNCTION_FAILED])
    assert_xfails(_qc4b_unwrap, _rs(fake), "rsa", "swap_secret_class_asym_type")
    _assert_xfail_record("not_operational")
    _assert_nothing_leaked(fake)


def test_qc4b_unwrap_kek_requests_unwrap_permission() -> None:
    """F6: the QC4b unwrap KEK template carries CKA_UNWRAP=True."""
    fake = _PolicyFake(unwrap_script=[None, _TEMPLATE_INCONSISTENT])
    try:
        _qc4b_unwrap(_rs(fake), "rsa", "swap_secret_class_asym_type")
    except XFailed:
        pass
    assert fake.create_templates, "KEK import must precede the unwrap control"
    kek_template = fake.create_templates[0]
    assert int(CKA_UNWRAP) in kek_template, kek_template
    assert _decode_bool(kek_template[int(CKA_UNWRAP)]) is True, kek_template


def test_qc4b_unwrap_false_unwrap_default_control_survives() -> None:
    """F6: with a correct template the legal control survives a strict provider."""
    fake = _PolicyFake(unwrap_script=[None, _TEMPLATE_INCONSISTENT])
    _qc4b_unwrap(_rs(fake), "rsa", "swap_secret_class_asym_type")
    _assert_terminal_pass()
    record = _terminal_record()
    assert record.actual_ckr == ckr_name(_TEMPLATE_INCONSISTENT), record.summary
    _assert_cleaned_up(fake)


@pytest.mark.parametrize(("family", "malformation"), _GENERATE_CELLS)
def test_qc4b_generate_control_refused_voids(family: str, malformation: str) -> None:
    """A refused well-formed generate control voids the whole cell, never passes it."""
    fake = _PolicyFake(keypair_script=[_FUNCTION_FAILED])
    assert_xfails(_qc4b_generate, _rs(fake), family, malformation)
    record = _assert_xfail_record("not_operational")
    assert record.actual_ckr == ckr_name(_FUNCTION_FAILED), record.summary
    assert len(fake.keypair_calls) == 1, "void must precede the malformed attempt"
    _assert_nothing_leaked(fake)


@pytest.mark.parametrize(("family", "malformation"), _GENERATE_CELLS)
def test_qc4b_generate_refuse_zero_delta_passes(family: str, malformation: str) -> None:
    """Clean generate refusal + zero inventory delta passes with the RV preserved."""
    fake = _PolicyFake(keypair_script=[None, _TEMPLATE_INCONSISTENT])
    _qc4b_generate(_rs(fake), family, malformation)
    _assert_terminal_pass()
    record = _terminal_record()
    assert record.reason == "sanctioned_refusal", record.summary
    assert record.actual_ckr == ckr_name(_TEMPLATE_INCONSISTENT), record.summary
    assert (record.detail or {}).get("inventory_delta") == 0, record.detail
    assert len(fake.keypair_calls) == 2, "legal control must run before the attempt"
    _assert_cleaned_up(fake)
    _assert_no_secret_bytes()


@pytest.mark.parametrize(("family", "malformation"), _GENERATE_CELLS)
def test_qc4b_generate_refuse_leak_fails(family: str, malformation: str) -> None:
    """A generate refusal that still creates labeled objects fails as leaked."""
    label = _attempt_label("generate", family, malformation)
    fake = _PolicyFake(keypair_script=[None, _TEMPLATE_INCONSISTENT], leak_labeled=label)
    _run_must_fail(_qc4b_generate, _rs(fake), family, malformation)
    record = _assert_fail_record("self_contradiction", "lifecycle")
    assert "leak" in (record.summary or "").lower(), record.summary
    _assert_cleaned_up(fake)


@pytest.mark.parametrize(("family", "malformation"), _GENERATE_CELLS)
def test_qc4b_generate_accept_unusable_xfails(family: str, malformation: str) -> None:
    """Accepted-but-unusable generated material is a visible deviation, not a pass."""
    label = _attempt_label("generate", family, malformation)
    if family == "rsa":
        # F10: both halves are exercised; refuse both (priv Sign + pub Encrypt).
        fake = _PolicyFake(
            sign_script=[_FUNCTION_FAILED],
            encrypt_rv={("keypair", _RSA_PKCS): _FUNCTION_FAILED},
        )
    elif family == "ec":
        # F10: seed the scalar so the pub Verify leg is attempted, refuse both.
        fake = _PolicyFake(sign_script=[_FUNCTION_FAILED], verify_script=[_FUNCTION_FAILED])
        fake._extra_for_label = label
        fake._extra_attrs = {
            int(CKA_EC_POINT): fake.ec_point_der(),
            int(CKA_VALUE): fake.ec_private_scalar(),
        }
    else:
        fake = _PolicyFake(sign_script=[_FUNCTION_FAILED])
    assert_xfails(_qc4b_generate, _rs(fake), family, malformation)
    record = _assert_xfail_record("honest_deviation")
    assert record.actual_ckr == ckr_name(_OK), record.summary
    assert (record.detail or {}).get("disposition") == "inspected-unusable", record.detail
    assert (record.detail or {}).get("use_attempted") is True, record.detail
    _assert_cleaned_up(fake)
    _assert_no_secret_bytes()


@pytest.mark.parametrize(("family", "malformation"), _GENERATE_CELLS)
def test_qc4b_generate_accept_readback_refused_is_unproved(family: str, malformation: str) -> None:
    """Accepted generate with refused identity inspection never fails unproved."""
    fake = _PolicyFake(get_attr_script=[_DEVICE_ERROR])
    assert_xfails(_qc4b_generate, _rs(fake), family, malformation)
    record = _assert_xfail_record("honest_deviation")
    assert record.actual_ckr == ckr_name(_OK), record.summary
    assert (record.detail or {}).get("disposition") == "unproved-effect", record.detail
    _assert_cleaned_up(fake)


def test_qc4b_generate_vendor_refusal_xfails() -> None:
    fake = _PolicyFake(keypair_script=[None, _VENDOR_RV])
    assert_xfails(_qc4b_generate, _rs(fake), "pqc", "missing_params")
    record = _assert_xfail_record("nonspec_reject")
    assert record.operation == "C_GenerateKeyPair", record.operation
    assert record.actual_ckr == ckr_name(_VENDOR_RV), record.summary
    detail = record.detail or {}
    assert detail.get("refusal_rv") == ckr_name(_VENDOR_RV), detail
    assert detail.get("inventory_delta") == 0, detail
    assert fake._find_seq == 2, "post-refusal inventory must run (N7)"
    _assert_cleaned_up(fake)


def test_qc4b_generate_undefined_rv_fails_metadata() -> None:
    fake = _PolicyFake(keypair_script=[None, _UNDEFINED_RV])
    _run_must_fail(_qc4b_generate, _rs(fake), "pqc", "missing_params")
    _assert_fail_record("self_contradiction", "metadata")
    _assert_cleaned_up(fake)


@pytest.mark.parametrize(
    ("family", "malformation"),
    [
        ("rsa", "swap_secret_class_asym_type"),
        ("rsa", "swap_asym_class_secret_type"),
        ("rsa", "missing_modulus_bits"),
        ("ec", "swap_secret_class_asym_type"),
        ("ec", "swap_asym_class_secret_type"),
        ("ec", "missing_params"),
    ],
)
def test_qc4b_generate_classic_coherent_xfails(family: str, malformation: str) -> None:
    """A coherent normalized generate result is deviation, never a quiet pass."""
    fake = _PolicyFake()
    assert_xfails(_qc4b_generate, _rs(fake), family, malformation)
    record = _assert_xfail_record("honest_deviation")
    assert (record.detail or {}).get("disposition") == "accepted-coherent", record.detail
    _assert_cleaned_up(fake)


def test_qc4b_generate_malformed_pub_proper_priv_no_cross_type() -> None:
    """F10: an unexercised malformed sibling must not indict a proper performer."""
    fake = _PolicyFake(keypair_pub_extra={int(CKA_CLASS): int(CKO_SECRET_KEY)})
    assert_xfails(_qc4b_generate, _rs(fake), "rsa", "swap_secret_class_asym_type")
    record = _assert_xfail_record("honest_deviation")
    assert (record.detail or {}).get("disposition") == "accepted-coherent", record.detail
    _assert_cleaned_up(fake)


def test_qc4b_generate_ec_malformed_pub_proper_priv_no_cross_type() -> None:
    """F10: EC twin — proper-priv signing is not cross-type via a malformed pub."""
    fake = _PolicyFake(keypair_pub_extra={int(CKA_CLASS): int(CKO_SECRET_KEY)})
    assert_xfails(_qc4b_generate, _rs(fake), "ec", "swap_secret_class_asym_type")
    record = _assert_xfail_record("honest_deviation")
    assert (record.detail or {}).get("disposition") == "accepted-coherent", record.detail
    _assert_cleaned_up(fake)


def test_qc4b_generate_ec_unreadable_scalar_pub_unverified_xfails() -> None:
    """F16: an unreadable priv scalar leaves the pub half unverified, not failed."""
    fake = _PolicyFake(
        keypair_pub_extra={int(CKA_CLASS): int(CKO_SECRET_KEY)},
        hide_for={"keypair": {int(CKA_VALUE)}},
    )
    assert_xfails(_qc4b_generate, _rs(fake), "ec", "swap_secret_class_asym_type")
    record = _assert_xfail_record("honest_deviation")
    assert (record.detail or {}).get("disposition") == "accepted-coherent", record.detail
    assert (record.detail or {}).get("coherent_uses") == ["ec_sign"], record.detail
    _assert_cleaned_up(fake)
    _assert_no_secret_bytes()


def test_qc4b_generate_rsa_malformed_pub_independently_usable_fails() -> None:
    """F10: the malformed half itself performing a witnessed use fails cross-type."""
    label = _attempt_label("generate", "rsa", "swap_secret_class_asym_type")
    fake = _PolicyFake(
        keypair_pub_extra={int(CKA_CLASS): int(CKO_SECRET_KEY)},
        sign_script=[_FUNCTION_FAILED],
    )
    fake._extra_for_label = label
    fake._extra_attrs = fake.rsa_private_components()
    _run_must_fail(_qc4b_generate, _rs(fake), "rsa", "swap_secret_class_asym_type")
    record = _assert_fail_record("self_contradiction", "policy")
    assert "cross-type" in (record.summary or "").lower(), record.summary
    _assert_cleaned_up(fake)


def test_qc4b_generate_ec_malformed_pub_independently_usable_fails() -> None:
    """F10: EC twin — a witnessed malformed-pub Verify fails, priv refused aside."""
    label = _attempt_label("generate", "ec", "swap_secret_class_asym_type")
    fake = _PolicyFake(
        keypair_pub_extra={int(CKA_CLASS): int(CKO_SECRET_KEY)},
        sign_script=[_FUNCTION_FAILED],
    )
    fake._extra_for_label = label
    fake._extra_attrs = {
        int(CKA_EC_POINT): fake.ec_point_der(),
        int(CKA_VALUE): fake.ec_private_scalar(),
    }
    _run_must_fail(_qc4b_generate, _rs(fake), "ec", "swap_secret_class_asym_type")
    record = _assert_fail_record("self_contradiction", "policy")
    assert "cross-type" in (record.summary or "").lower(), record.summary
    _assert_cleaned_up(fake)


def test_qc4b_generate_rsa_halves_mismatch_fails() -> None:
    """F10: generated halves disagreeing on (n, e) fail as module self-contradiction."""
    fake = _PolicyFake(keypair_priv_extra={int(CKA_MODULUS): b"\xff" * 256})
    _run_must_fail(_qc4b_generate, _rs(fake), "rsa", "swap_secret_class_asym_type")
    record = _assert_fail_record("self_contradiction", "policy")
    assert (record.detail or {}).get("halves") == "mismatched", record.detail
    _assert_cleaned_up(fake)


def test_qc4b_generate_ec_scalar_point_mismatch_fails() -> None:
    """F10: a scalar not matching the P-256 point fails as self-contradiction."""
    label = _attempt_label("generate", "ec", "swap_secret_class_asym_type")
    fake = _PolicyFake()
    fake._extra_for_label = label
    fake._extra_attrs = {int(CKA_VALUE): b"\x00" * 31 + b"\x01"}
    _run_must_fail(_qc4b_generate, _rs(fake), "ec", "swap_secret_class_asym_type")
    record = _assert_fail_record("self_contradiction", "policy")
    assert (record.detail or {}).get("halves") == "mismatched", record.detail
    _assert_cleaned_up(fake)


@pytest.mark.parametrize(
    ("family", "malformation"),
    [
        ("rsa", "swap_secret_class_asym_type"),
        ("rsa", "swap_asym_class_secret_type"),
        ("rsa", "missing_modulus_bits"),
        ("ec", "swap_secret_class_asym_type"),
        ("ec", "swap_asym_class_secret_type"),
        ("ec", "missing_params"),
    ],
)
def test_qc4b_generate_classic_incoherent_fails_crypto(family: str, malformation: str) -> None:
    """Incoherent generated material fails crypto wrong_result with full evidence."""
    sig_len = 256 if family == "rsa" else 64
    fake = _PolicyFake(sign_output=b"B" * sig_len)
    _run_must_fail(_qc4b_generate, _rs(fake), family, malformation)
    _assert_fail_record("wrong_result", "crypto")
    _assert_cleaned_up(fake)


@pytest.mark.parametrize(
    "malformation",
    ["swap_secret_class_asym_type", "swap_asym_class_secret_type", "missing_params"],
)
def test_qc4b_generate_pqc_coherent_xfails(malformation: str) -> None:
    """Module-only PQC coherence can never fail; it is recorded deviation."""
    fake = _PolicyFake()
    assert_xfails(_qc4b_generate, _rs(fake), "pqc", malformation)
    record = _assert_xfail_record("honest_deviation")
    assert (record.detail or {}).get("disposition") == "accepted-coherent", record.detail
    _assert_cleaned_up(fake)


def test_qc4b_generate_pqc_verify_false_xfails() -> None:
    fake = _PolicyFake(verify_script=[_SIGNATURE_INVALID])
    assert_xfails(_qc4b_generate, _rs(fake), "pqc", "missing_params")
    record = _assert_xfail_record("honest_deviation")
    assert (record.detail or {}).get("disposition") == "inspected-unusable", record.detail
    _assert_cleaned_up(fake)


def test_qc4b_generate_kept_malformed_coherent_fails() -> None:
    """A kept SECRET-class identity with verified use fails as contradiction."""
    label = _attempt_label("generate", "rsa", "swap_secret_class_asym_type")
    fake = _PolicyFake(
        extra_for_label=label,
        extra_attrs={int(CKA_CLASS): int(CKO_SECRET_KEY), int(CKA_KEY_TYPE): int(CKK_RSA)},
    )
    _run_must_fail(_qc4b_generate, _rs(fake), "rsa", "swap_secret_class_asym_type")
    _assert_fail_record("self_contradiction", "policy")
    _assert_cleaned_up(fake)


def test_qc4b_create_unsupported_skips() -> None:
    """A module without C_CreateObject skips the Create cell as incapable."""
    fake = _PolicyFake(probe_rv=_NOT_SUPPORTED)
    assert_skips(_qc4b_create, _rs(fake), "rsa", "missing_modulus")


def test_qc4b_create_before_inventory_failed_voids() -> None:
    fake = _PolicyFake(
        create_script=[None, _TEMPLATE_INCONSISTENT],
        find_fail={1: ("init", _FUNCTION_FAILED)},
    )
    assert_xfails(_qc4b_create, _rs(fake), "rsa", "missing_modulus")
    _assert_xfail_record("not_operational")
    _assert_cleaned_up(fake)


def test_qc4b_create_after_inventory_failed_is_unproved() -> None:
    """A refusal with unprovable inventory never passes; it stays unproved."""
    fake = _PolicyFake(
        create_script=[None, _TEMPLATE_INCONSISTENT],
        find_fail={2: ("find", _FUNCTION_FAILED)},
    )
    assert_xfails(_qc4b_create, _rs(fake), "rsa", "missing_modulus")
    record = _assert_xfail_record("honest_deviation")
    assert (record.detail or {}).get("disposition") == "unproved-effect", record.detail
    _assert_cleaned_up(fake)


def test_qc4b_create_undefined_refusal_beats_failed_inventory() -> None:
    """F13/F9 + N7: undefined defect recorded first, retained past inventory failure.

    Inventory must actually run (Find sequence 2) and its RV rides in the
    retained record's detail; the shortcut of terminating on validity
    before inventory cannot re-enter.
    """
    fake = _PolicyFake(
        create_script=[None, _UNDEFINED_RV],
        find_fail={2: ("find", _FUNCTION_FAILED)},
    )
    _run_must_fail(_qc4b_create, _rs(fake), "rsa", "missing_modulus")
    record = _assert_fail_record("self_contradiction", "metadata")
    assert record.label == "C_CreateObject malformed rsa/missing_modulus", record.label
    assert record.operation == "C_CreateObject", record.operation
    assert record.actual_ckr == ckr_name(_UNDEFINED_RV), record.summary
    detail = record.detail or {}
    assert detail.get("refusal_rv") == ckr_name(_UNDEFINED_RV), detail
    assert detail.get("inventory_rv") == ckr_name(_FUNCTION_FAILED), detail
    assert _reported_outcome() == "fail", [rec.reason for rec in C.get_records()]
    assert fake._find_seq == 2, "post-refusal inventory must run"
    _assert_cleaned_up(fake)


def test_qc4b_create_vendor_refusal_beats_failed_inventory() -> None:
    """F13/F9 + N7: vendor alternate recorded first; inventory still runs.

    The Find sequence must reach the post-refusal inventory (sequence 2)
    and the inventory RV rides in the retained record's detail.
    """
    fake = _PolicyFake(
        create_script=[None, _VENDOR_RV],
        find_fail={2: ("find", _FUNCTION_FAILED)},
    )
    assert_xfails(_qc4b_create, _rs(fake), "rsa", "missing_modulus")
    record = _assert_xfail_record("nonspec_reject")
    assert record.label == "C_CreateObject malformed rsa/missing_modulus", record.label
    assert record.operation == "C_CreateObject", record.operation
    assert record.actual_ckr == ckr_name(_VENDOR_RV), record.summary
    detail = record.detail or {}
    assert detail.get("refusal_rv") == ckr_name(_VENDOR_RV), detail
    assert detail.get("inventory_rv") == ckr_name(_FUNCTION_FAILED), detail
    assert _reported_outcome() == "xfail", [rec.reason for rec in C.get_records()]
    assert fake._find_seq == 2, "post-refusal inventory must run"
    _assert_cleaned_up(fake)


def test_qc4b_create_rsa_use_mech_missing_xfails_not_skips() -> None:
    """Admission without the family use mechanism stays a visible xfail, not a skip."""
    fake = _PolicyFake()
    mechs = set(_ALL_MECHS) - {"RSA_PKCS"}
    assert_xfails(_qc4b_create, _rs(fake, mechs=mechs), "rsa", "missing_modulus")
    record = _assert_xfail_record("honest_deviation")
    assert "unavailable" in (record.summary or "").lower(), record.summary
    _assert_cleaned_up(fake)


def test_qc4b_create_ec_use_mech_missing_xfails_not_skips() -> None:
    fake = _PolicyFake()
    mechs = set(_ALL_MECHS) - {"ECDSA"}
    assert_xfails(_qc4b_create, _rs(fake, mechs=mechs), "ec", "missing_params")
    record = _assert_xfail_record("honest_deviation")
    assert "unavailable" in (record.summary or "").lower(), record.summary
    _assert_cleaned_up(fake)


def test_qc4b_create_pqc_use_mech_missing_xfails_not_skips() -> None:
    fake = _PolicyFake()
    mechs = set(_ALL_MECHS) - {"ML_DSA"}
    assert_xfails(_qc4b_create, _rs(fake, mechs=mechs), "pqc", "missing_params")
    record = _assert_xfail_record("honest_deviation")
    assert "unavailable" in (record.summary or "").lower(), record.summary
    _assert_cleaned_up(fake)


def test_qc4b_create_pqc_unoffered_skips() -> None:
    """No offered PQC family skips the PQC cell visibly, never passes it."""
    fake = _PolicyFake()
    mechs = set(_ALL_MECHS) - {"ML_DSA_KEY_PAIR_GEN", "SLH_DSA_KEY_PAIR_GEN"}
    assert_skips(_qc4b_create, _rs(fake, mechs=mechs), "pqc", "missing_params")


def test_qc4b_unwrap_pqc_unoffered_skips() -> None:
    fake = _PolicyFake()
    mechs = set(_ALL_MECHS) - {"ML_DSA_KEY_PAIR_GEN", "SLH_DSA_KEY_PAIR_GEN"}
    assert_skips(_qc4b_unwrap, _rs(fake, mechs=mechs), "pqc", "swap_secret_class_asym_type")


def test_qc4b_generate_pqc_unoffered_skips() -> None:
    fake = _PolicyFake()
    mechs = set(_ALL_MECHS) - {"ML_DSA_KEY_PAIR_GEN", "SLH_DSA_KEY_PAIR_GEN"}
    assert_skips(_qc4b_generate, _rs(fake, mechs=mechs), "pqc", "missing_params")


def _slh_only_mechs() -> set[str]:
    return (set(_ALL_MECHS) - {"ML_DSA_KEY_PAIR_GEN", "ML_DSA"}) | {
        "SLH_DSA_KEY_PAIR_GEN",
        "SLH_DSA",
    }


def test_qc4b_create_pqc_slh_fallback_passes() -> None:
    """SLH-DSA serves as the offered PQC family when ML-DSA is absent."""
    fake = _PolicyFake(create_script=[None, _TEMPLATE_INCONSISTENT])
    _qc4b_create(_rs(fake, mechs=_slh_only_mechs()), "pqc", "missing_params")
    _assert_terminal_pass()
    _assert_cleaned_up(fake)


def test_qc4b_unwrap_pqc_slh_fallback_passes() -> None:
    fake = _PolicyFake(unwrap_script=[None, _TEMPLATE_INCONSISTENT])
    _qc4b_unwrap(_rs(fake, mechs=_slh_only_mechs()), "pqc", "swap_secret_class_asym_type")
    _assert_terminal_pass()
    _assert_cleaned_up(fake)


def test_qc4b_generate_pqc_slh_fallback_passes() -> None:
    fake = _PolicyFake(keypair_script=[None, _TEMPLATE_INCONSISTENT])
    _qc4b_generate(_rs(fake, mechs=_slh_only_mechs()), "pqc", "missing_params")
    _assert_terminal_pass()
    _assert_cleaned_up(fake)


# -- QC4c downstream --------------------------------------------------------------------


@pytest.mark.parametrize("malformation", _QC4C_MALS)
def test_qc4c_refused_creation_skips_inapplicable(malformation: str) -> None:
    """F13: a STANDARD refused malformed creation skips as inapplicable."""
    fake = _PolicyFake(create_script=[_TEMPLATE_INCONSISTENT])
    skipped = assert_skips(_qc4c, _rs(fake), malformation)
    assert "inapplicable: malformed object correctly refused; downstream row not exercised" in str(
        skipped
    ), str(skipped)


@pytest.mark.parametrize("malformation", _QC4C_MALS)
def test_qc4c_vendor_creation_refusal_xfails(malformation: str) -> None:
    """F13: a vendor creation refusal is a visible alternate xfail, never a skip."""
    fake = _PolicyFake(create_script=[_VENDOR_RV])
    assert_xfails(_qc4c, _rs(fake), malformation)
    record = _assert_xfail_record("nonspec_reject")
    assert record.actual_ckr == ckr_name(_VENDOR_RV), record.summary
    _assert_nothing_leaked(fake)


@pytest.mark.parametrize("malformation", _QC4C_MALS)
def test_qc4c_undefined_creation_rv_fails_metadata(malformation: str) -> None:
    """F13: an undefined creation RV fails the metadata contract, never skips."""
    fake = _PolicyFake(create_script=[_UNDEFINED_RV])
    try:
        _qc4c(_rs(fake), malformation)
    except Skipped:
        pytest.fail("undefined creation RV must fail metadata, never skip")
    except Failed as exc:
        assert not isinstance(exc, XFailed), "must fail, not xfail"
    else:
        pytest.fail("expected metadata failure")
    _assert_fail_record("self_contradiction", "metadata")
    _assert_nothing_leaked(fake)


@pytest.mark.parametrize("malformation", _QC4C_MALS)
def test_qc4c_admitted_sign_refused_xfails(malformation: str) -> None:
    """Clean refusal of the downstream sign path xfails as defense-in-depth held."""
    fake = _PolicyFake(sign_script=[_KEY_TYPE_INCONSISTENT])
    assert_xfails(_qc4c, _rs(fake), malformation)
    record = _assert_xfail_record("honest_deviation")
    assert "defense in depth" in (record.summary or "").lower(), record.summary
    assert record.actual_ckr == ckr_name(_KEY_TYPE_INCONSISTENT), record.summary
    _assert_cleaned_up(fake)


def test_qc4c_admitted_sign_vendor_refusal_xfails() -> None:
    fake = _PolicyFake(sign_script=[_VENDOR_RV])
    assert_xfails(_qc4c, _rs(fake), "swap_secret_class_asym_type")
    _assert_xfail_record("nonspec_reject")
    _assert_cleaned_up(fake)


def test_qc4c_admitted_sign_undefined_rv_fails_metadata() -> None:
    fake = _PolicyFake(sign_script=[_UNDEFINED_RV])
    _run_must_fail(_qc4c, _rs(fake), "swap_secret_class_asym_type")
    _assert_fail_record("self_contradiction", "metadata")
    _assert_cleaned_up(fake)


@pytest.mark.parametrize("malformation", _QC4C_MALS)
def test_qc4c_admitted_valid_signature_fails(malformation: str) -> None:
    """A valid signature from a malformed key fails as type-confusion exploitability."""
    fake = _PolicyFake(sign_key="rsa")
    modulus, exponent = fake.rsa_numbers()
    fake._extra_for_label = _policy_module().downstream_label(malformation).encode("utf-8")
    fake._extra_attrs = {int(CKA_MODULUS): modulus, int(CKA_PUBLIC_EXPONENT): exponent}
    _run_must_fail(_qc4c, _rs(fake), malformation)
    record = _assert_fail_record("self_contradiction", "policy")
    assert "type-confusion" in (record.summary or "").lower(), record.summary
    _assert_cleaned_up(fake)
    _assert_no_secret_bytes()


@pytest.mark.parametrize("malformation", _QC4C_MALS)
def test_qc4c_admitted_invalid_signature_fails_crypto(malformation: str) -> None:
    fake = _PolicyFake(sign_key="rsa", sign_output=b"B" * 256)
    modulus, exponent = fake.rsa_numbers()
    fake._extra_for_label = _policy_module().downstream_label(malformation).encode("utf-8")
    fake._extra_attrs = {int(CKA_MODULUS): modulus, int(CKA_PUBLIC_EXPONENT): exponent}
    _run_must_fail(_qc4c, _rs(fake), malformation)
    _assert_fail_record("wrong_result", "crypto")
    _assert_cleaned_up(fake)


@pytest.mark.parametrize("malformation", _QC4C_MALS)
def test_qc4c_admitted_public_half_missing_is_unproved(malformation: str) -> None:
    """Sign success without a verifiable public half never fails unproved."""
    fake = _PolicyFake(sign_key="rsa")
    assert_xfails(_qc4c, _rs(fake), malformation)
    record = _assert_xfail_record("honest_deviation")
    assert (record.detail or {}).get("disposition") == "unproved-effect", record.detail
    _assert_cleaned_up(fake)


@pytest.mark.parametrize("malformation", _QC4C_MALS)
def test_qc4c_sign_crash_propagates(malformation: str) -> None:
    """A crashing sign path propagates; it is never swallowed or retried to pass."""

    class _BoomError(Exception):
        pass

    fake = _PolicyFake(sign_raise=_BoomError("simulated crash"))
    with pytest.raises(_BoomError):
        _qc4c(_rs(fake), malformation)
    _assert_cleaned_up(fake)


def test_qc4c_missing_sign_mechanism_skips() -> None:
    fake = _PolicyFake()
    mechs = set(_ALL_MECHS) - {"SHA256_RSA_PKCS"}
    assert_skips(_qc4c, _rs(fake, mechs=mechs), "missing_modulus")


def test_qc4c_unsupported_create_skips() -> None:
    fake = _PolicyFake(probe_rv=_NOT_SUPPORTED)
    assert_skips(_qc4c, _rs(fake), "missing_modulus")


# -- Fix round 2 (re-review #1: N1-N10) -----------------------------------------
#
# Preemption group (N1, N2, N7): a proved finding is adjudicated at its
# witness, before any later fallible call can preempt it.


def test_qc4b_create_witnessed_aes_use_survives_vendor_halves_refusal_n1() -> None:
    """N1: EC type confusion FAILs before the halves read can xfail vendor."""
    fake = _PolicyFake(get_attr_script=[None, None, _VENDOR_RV])
    _run_must_fail(_qc4b_create, _rs(fake), "ec", "swap_secret_class_asym_type")
    record = _assert_fail_record("self_contradiction", "policy")
    assert record.label == "C_CreateObject malformed ec/swap_secret_class_asym_type", record.label
    assert record.operation == "C_CreateObject", record.operation
    assert record.actual_ckr == ckr_name(_OK), record.summary
    detail = record.detail or {}
    assert detail.get("coherent_use") == "aes", detail
    assert detail.get("performer_class") == "CKO_SECRET_KEY", detail
    assert detail.get("performer_type") == "CKK_EC", detail
    assert detail.get("performer_handle") in fake.created, detail
    assert _reported_outcome() == "fail", [rec.reason for rec in C.get_records()]
    # Fail-fast: no provider read follows the witness (identity read is the
    # only attribute read: two low-level calls for size + fetch).
    assert fake.get_attr_calls == 2, fake.get_attr_calls
    assert not [rec for rec in C.get_records() if rec.reason == "nonspec_reject"]
    _assert_cleaned_up(fake)
    _assert_no_secret_bytes()


def test_qc4b_create_witnessed_aes_use_survives_undefined_halves_refusal_n1() -> None:
    """N1: the type-confusion FAIL is reported, not a later metadata FAIL."""
    fake = _PolicyFake(get_attr_script=[None, None, _UNDEFINED_RV])
    _run_must_fail(_qc4b_create, _rs(fake), "ec", "swap_secret_class_asym_type")
    record = _assert_fail_record("self_contradiction", "policy")
    assert (record.detail or {}).get("coherent_use") == "aes", record.detail
    assert record.actual_ckr == ckr_name(_OK), record.summary
    assert _reported_outcome() == "fail", [rec.reason for rec in C.get_records()]
    assert fake.get_attr_calls == 2, fake.get_attr_calls
    assert not [rec for rec in C.get_records() if rec.kind == "metadata"]
    _assert_cleaned_up(fake)
    _assert_no_secret_bytes()


def test_qc4b_create_rsa_witnessed_aes_use_fails_before_encrypt_n1() -> None:
    """N1 (RSA branch): AES witness FAILs before the follow-on encrypt probe."""
    fake = _PolicyFake(encrypt_rv={("create", _RSA_PKCS): _VENDOR_RV})
    _run_must_fail(_qc4b_create, _rs(fake), "rsa", "swap_secret_class_asym_type")
    record = _assert_fail_record("self_contradiction", "policy")
    detail = record.detail or {}
    assert detail.get("coherent_use") == "aes", detail
    assert detail.get("performer_class") == "CKO_SECRET_KEY", detail
    assert detail.get("performer_type") == "CKK_RSA", detail
    assert detail.get("performer_handle") in fake.created, detail
    assert record.actual_ckr == ckr_name(_OK), record.summary
    assert _reported_outcome() == "fail", [rec.reason for rec in C.get_records()]
    _assert_cleaned_up(fake)
    _assert_no_secret_bytes()


def test_qc4b_create_pqc_witnessed_aes_use_fails_before_verify_n1() -> None:
    """N1 (PQC branch): AES witness FAILs before the trusted-sign setup."""
    fake = _PolicyFake(sign_script=[_VENDOR_RV])
    _run_must_fail(_qc4b_create, _rs(fake), "pqc", "swap_asym_class_secret_type")
    record = _assert_fail_record("self_contradiction", "policy")
    detail = record.detail or {}
    assert detail.get("coherent_use") == "aes", detail
    assert detail.get("performer_class") == "CKO_PUBLIC_KEY", detail
    assert detail.get("performer_type") == "CKK_AES", detail
    assert detail.get("performer_handle") in fake.created, detail
    assert record.actual_ckr == ckr_name(_OK), record.summary
    assert _reported_outcome() == "fail", [rec.reason for rec in C.get_records()]
    _assert_cleaned_up(fake)
    _assert_no_secret_bytes()


def test_qc4b_create_ec_missing_point_short_signature_fails_n2() -> None:
    """N2: known P-256 params + missing point + 63-byte Sign fails wrong_result."""
    fake = _PolicyFake(sign_output=b"B" * 63)
    _run_must_fail(_qc4b_create, _rs(fake), "ec", "missing_point")
    record = _assert_fail_record("wrong_result", "crypto")
    assert record.label == "C_CreateObject malformed ec/missing_point", record.label
    assert record.operation == "C_CreateObject", record.operation
    assert record.actual_ckr == ckr_name(_OK), record.summary
    assert (record.detail or {}).get("sig_len") == 63, record.detail
    assert (record.detail or {}).get("expected_sig_len") == 64, record.detail
    assert _reported_outcome() == "fail", [rec.reason for rec in C.get_records()]
    _assert_cleaned_up(fake)
    _assert_no_secret_bytes()


def test_use_ec_sign_missing_point_short_output_fails_n2() -> None:
    """N2 (direct): the length gate precedes the point/oracle requirement."""
    mod = _policy_module()
    fake = _PolicyFake(sign_output=b"B" * 63)
    handle = fake._store({}, role="create")
    _run_must_fail(
        mod._use_ec_sign,
        _rs(fake),
        handle,
        params=mod.QC4_P256_PARAMS,
        point=None,
        label="probe n2",
        operation="C_CreateObject",
        spec_ref="test",
    )
    record = _assert_fail_record("wrong_result", "crypto")
    assert record.actual_ckr == ckr_name(_OK), record.summary
    assert (record.detail or {}).get("sig_len") == 63, record.detail
    assert (record.detail or {}).get("expected_sig_len") == 64, record.detail


def test_use_ec_sign_unknown_params_short_output_unverifiable_n2() -> None:
    """N2 guard: unknown params + non-64-byte output stays unverifiable."""
    mod = _policy_module()
    fake = _PolicyFake(sign_output=b"B" * 63)
    handle = fake._store({}, role="create")
    point = mod._parse_ec_point(fake.ec_point_der())
    outcome = mod._use_ec_sign(
        _rs(fake),
        handle,
        params=b"\x06\x03\x2b\x65\x07",
        point=point,
        label="probe n2 guard",
        operation="C_CreateObject",
        spec_ref="test",
    )
    assert outcome.unverifiable is True
    assert outcome.coherent is False
    assert not [rec for rec in C.get_records() if rec.outcome == "fail"]


def test_use_ec_sign_missing_point_full_length_unverifiable_n2() -> None:
    """N2 guard: missing point + 64-byte output stays unverifiable (no oracle)."""
    mod = _policy_module()
    fake = _PolicyFake(sign_output=b"B" * 64)
    handle = fake._store({}, role="create")
    outcome = mod._use_ec_sign(
        _rs(fake),
        handle,
        params=mod.QC4_P256_PARAMS,
        point=None,
        label="probe n2 guard",
        operation="C_CreateObject",
        spec_ref="test",
    )
    assert outcome.unverifiable is True
    assert outcome.coherent is False
    assert not [rec for rec in C.get_records() if rec.outcome == "fail"]


def test_qc4b_create_vendor_refusal_leak_fails_n7() -> None:
    """N7: a vendor refusal that leaks is inventoried, cleaned, and FAILs."""
    label = _attempt_label("create", "rsa", "missing_modulus")
    fake = _PolicyFake(create_script=[None, _VENDOR_RV], leak_labeled=label)
    _run_must_fail(_qc4b_create, _rs(fake), "rsa", "missing_modulus")
    record = _assert_fail_record("self_contradiction", "lifecycle")
    assert record.label == "C_CreateObject malformed rsa/missing_modulus", record.label
    assert record.operation == "C_CreateObject", record.operation
    assert record.actual_ckr == ckr_name(_VENDOR_RV), record.summary
    detail = record.detail or {}
    assert detail.get("leaked_count") == 1, detail
    assert detail.get("refusal_rv") == ckr_name(_VENDOR_RV), detail
    vendor = [rec for rec in C.get_records() if rec.reason == "nonspec_reject"]
    assert len(vendor) == 1, [(rec.reason, rec.actual_ckr) for rec in C.get_records()]
    assert vendor[0].actual_ckr == ckr_name(_VENDOR_RV), vendor[0].summary
    assert _reported_outcome() == "fail", [rec.reason for rec in C.get_records()]
    assert fake._find_seq == 2, "post-refusal inventory must run"
    _assert_cleaned_up(fake)
    _assert_no_secret_bytes()


def test_qc4b_create_undefined_refusal_leak_fails_n7() -> None:
    """N7: undefined-RV metadata FAIL is retained AND the leak is recorded."""
    label = _attempt_label("create", "rsa", "missing_modulus")
    fake = _PolicyFake(create_script=[None, _UNDEFINED_RV], leak_labeled=label)
    _run_must_fail(_qc4b_create, _rs(fake), "rsa", "missing_modulus")
    record = _assert_fail_record("self_contradiction", "lifecycle")
    detail = record.detail or {}
    assert detail.get("leaked_count") == 1, detail
    assert detail.get("refusal_rv") == ckr_name(_UNDEFINED_RV), detail
    assert record.actual_ckr == ckr_name(_UNDEFINED_RV), record.summary
    metadata = [rec for rec in C.get_records() if rec.kind == "metadata" and rec.outcome == "fail"]
    assert len(metadata) == 1, [(rec.reason, rec.kind) for rec in C.get_records()]
    assert metadata[0].actual_ckr == ckr_name(_UNDEFINED_RV), metadata[0].summary
    assert _reported_outcome() == "fail", [rec.reason for rec in C.get_records()]
    assert fake._find_seq == 2, "post-refusal inventory must run"
    _assert_cleaned_up(fake)
    _assert_no_secret_bytes()


# Premise group (N3, N4, N5): qualified parameter sets and complete
# control/attempt premises.


def _n3_family(mod: Any, key_type: int, param_set: int) -> Any:
    if key_type == int(CKK_ML_DSA):
        return mod.PqcFamily(
            key="ml-dsa-probe",
            key_type=key_type,
            keygen_mech=int(CKM_ML_DSA_KEY_PAIR_GEN),
            keygen_mech_name="ML_DSA_KEY_PAIR_GEN",
            sign_mech=int(CKM_ML_DSA),
            sign_mech_name="ML_DSA",
            param_set=param_set,
        )
    return mod.PqcFamily(
        key="slh-dsa-probe",
        key_type=key_type,
        keygen_mech=int(CKM_SLH_DSA_KEY_PAIR_GEN),
        keygen_mech_name="SLH_DSA_KEY_PAIR_GEN",
        sign_mech=int(CKM_SLH_DSA),
        sign_mech_name="SLH_DSA",
        param_set=param_set,
    )


@pytest.mark.parametrize(
    ("key_type", "param_set", "expected"),
    [
        (int(CKK_ML_DSA), int(CKP_ML_DSA_44), 2420),
        (int(CKK_ML_DSA), int(CKP_ML_DSA_65), 3309),
        (int(CKK_ML_DSA), int(CKP_ML_DSA_87), 4627),
        (int(CKK_SLH_DSA), int(CKP_SLH_DSA_SHA2_128S), 7856),
    ],
)
def test_pqc_sig_shape_family_keyed_lengths_n3(
    key_type: int, param_set: int, expected: int
) -> None:
    """N3: signature length is a (family, parameter set) property."""
    mod = _policy_module()
    family = _n3_family(mod, key_type, param_set)
    mod._check_pqc_sig_shape(
        b"G" * expected, family=family, label="probe n3", operation="C_Sign", spec_ref="test"
    )
    _run_must_fail(
        mod._check_pqc_sig_shape,
        b"G" * 100,
        family=family,
        label="probe n3",
        operation="C_Sign",
        spec_ref="test",
    )
    record = _assert_fail_record("wrong_result", "crypto")
    assert record.actual_ckr == ckr_name(_OK), record.summary
    assert (record.detail or {}).get("sig_len") == 100, record.detail
    assert (record.detail or {}).get("expected_sig_len") == expected, record.detail


def test_pqc_sig_shape_ml44_and_slh_coexist_n3() -> None:
    """N3: ML-DSA-44 (2420) and SLH-DSA-128s (7856) coexist; int 1 collides not."""
    mod = _policy_module()
    ml44 = _n3_family(mod, int(CKK_ML_DSA), int(CKP_ML_DSA_44))
    slh = _n3_family(mod, int(CKK_SLH_DSA), int(CKP_SLH_DSA_SHA2_128S))
    assert int(CKP_ML_DSA_44) == int(CKP_SLH_DSA_SHA2_128S)
    mod._check_pqc_sig_shape(
        b"G" * 2420, family=ml44, label="probe n3 ml44", operation="C_Sign", spec_ref="test"
    )
    mod._check_pqc_sig_shape(
        b"G" * 7856, family=slh, label="probe n3 slh", operation="C_Sign", spec_ref="test"
    )
    _run_must_fail(
        mod._check_pqc_sig_shape,
        b"G" * 7856,
        family=ml44,
        label="probe n3 ml44",
        operation="C_Sign",
        spec_ref="test",
    )
    record = _assert_fail_record("wrong_result", "crypto")
    assert (record.detail or {}).get("expected_sig_len") == 2420, record.detail


def test_qc4b_generate_pqc_missing_params_admitted_44_not_failed_n3() -> None:
    """N3: provider-default ML-DSA-44 output is not failed against assumed 65."""
    fake = _PolicyFake(
        sign_output=b"G" * 2420,
        verify_script=[_OK],
        keypair_pub_extra={int(CKA_PARAMETER_SET): int(CKP_ML_DSA_44)},
    )
    assert_xfails(_qc4b_generate, _rs(fake), "pqc", "missing_params")
    record = _assert_xfail_record("honest_deviation")
    assert record.actual_ckr == ckr_name(_OK), record.summary
    assert (record.detail or {}).get("disposition") == "accepted-coherent", record.detail
    assert not [rec for rec in C.get_records() if rec.reason == "wrong_result"]
    assert _reported_outcome() == "xfail", [rec.reason for rec in C.get_records()]
    _assert_cleaned_up(fake)
    _assert_no_secret_bytes()


def test_qc4b_generate_pqc_missing_params_wrong_length_for_admitted_fails_n3() -> None:
    """N3: a genuinely wrong length under the qualified (read-back) set fails."""
    fake = _PolicyFake(
        sign_output=b"G" * 3309,
        verify_script=[_OK],
        keypair_pub_extra={int(CKA_PARAMETER_SET): int(CKP_ML_DSA_44)},
    )
    _run_must_fail(_qc4b_generate, _rs(fake), "pqc", "missing_params")
    record = _assert_fail_record("wrong_result", "crypto")
    assert record.actual_ckr == ckr_name(_OK), record.summary
    assert (record.detail or {}).get("sig_len") == 3309, record.detail
    assert (record.detail or {}).get("expected_sig_len") == 2420, record.detail
    assert _reported_outcome() == "fail", [rec.reason for rec in C.get_records()]
    _assert_cleaned_up(fake)
    _assert_no_secret_bytes()


def test_qc4b_generate_pqc_missing_params_unqualified_not_failed_n3() -> None:
    """N3: an unqualified admitted set is never gated as assumed ML-DSA-65."""
    fake = _PolicyFake(sign_output=b"G" * 2420, verify_script=[_OK])
    assert_xfails(_qc4b_generate, _rs(fake), "pqc", "missing_params")
    record = _assert_xfail_record("honest_deviation")
    assert (record.detail or {}).get("disposition") == "accepted-coherent", record.detail
    assert not [rec for rec in C.get_records() if rec.reason == "wrong_result"]
    notes = [note.description for note in get_notes()]
    assert any("parameter set unqualified" in text for text in notes), notes
    _assert_cleaned_up(fake)
    _assert_no_secret_bytes()


@pytest.mark.parametrize(("family", "malformation"), _CREATE_CELLS)
def test_qc4b_create_control_inherits_attempt_usage_n4(family: str, malformation: str) -> None:
    """N4: the control carries the attempt's usage/token premises verbatim."""
    fake = _PolicyFake(create_script=[None, _TEMPLATE_INCONSISTENT])
    _qc4b_create(_rs(fake), family, malformation)
    _assert_terminal_pass()
    assert len(fake.create_templates) == 2, "legal control must run before the attempt"
    control, attempt = fake.create_templates
    for attr in (int(CKA_ENCRYPT), int(CKA_VERIFY), int(CKA_TOKEN)):
        assert control.get(attr) == attempt.get(attr), (attr, control, attempt)
    _assert_cleaned_up(fake)


@pytest.mark.parametrize(
    ("family", "malformation", "attr"),
    [
        ("rsa", "missing_modulus", CKA_ENCRYPT),
        ("rsa", "swap_secret_class_asym_type", CKA_ENCRYPT),
        ("ec", "missing_params", CKA_VERIFY),
        ("ec", "swap_asym_class_secret_type", CKA_VERIFY),
        ("pqc", "missing_params", CKA_VERIFY),
        ("pqc", "swap_asym_class_secret_type", CKA_VERIFY),
    ],
)
def test_qc4b_create_permission_refusal_voids_not_passes_n4(
    family: str, malformation: str, attr: Any
) -> None:
    """N4: permission-only import refusal voids via the control, never passes."""
    fake = _PolicyFake(create_refuse_bool_attr={int(attr): _TEMPLATE_INCONSISTENT})
    assert_xfails(_qc4b_create, _rs(fake), family, malformation)
    record = _assert_xfail_record("not_operational")
    assert "legal control" in (record.label or ""), record.label
    assert record.operation == "C_CreateObject", record.operation
    assert record.actual_ckr == ckr_name(_TEMPLATE_INCONSISTENT), record.summary
    assert len(fake.create_templates) == 1, "control refusal must precede the attempt"
    assert _reported_outcome() == "xfail", [rec.reason for rec in C.get_records()]
    _assert_nothing_leaked(fake)


def test_qc4b_generate_rsa_pub_encrypt_witness_with_permission_n5() -> None:
    """N5: the generated RSA pub Encrypt witness runs with CKA_ENCRYPT requested."""
    label = _attempt_label("generate", "rsa", "swap_secret_class_asym_type")
    fake = _PolicyFake(
        keypair_pub_extra={int(CKA_CLASS): int(CKO_SECRET_KEY)},
        sign_script=[_FUNCTION_FAILED],
        enforce_rsa_encrypt_permission=True,
    )
    fake._extra_for_label = label
    fake._extra_attrs = fake.rsa_private_components()
    _run_must_fail(_qc4b_generate, _rs(fake), "rsa", "swap_secret_class_asym_type")
    record = _assert_fail_record("self_contradiction", "policy")
    detail = record.detail or {}
    assert detail.get("coherent_use") == "rsa_encrypt", detail
    assert detail.get("performer_class") == "CKO_SECRET_KEY", detail
    assert detail.get("performer_type") == "CKK_RSA", detail
    assert record.actual_ckr == ckr_name(_OK), record.summary
    assert _reported_outcome() == "fail", [rec.reason for rec in C.get_records()]
    attempt_pub = fake.keypair_calls[-1][0]
    assert attempt_pub.get(int(CKA_ENCRYPT)) == b"\x01", attempt_pub
    _assert_cleaned_up(fake)
    _assert_no_secret_bytes()


def test_qc4b_generate_rsa_pub_encrypt_genuine_refusal_unproved_n5() -> None:
    """N5 twin: a genuine Encrypt refusal with permission stays unproved."""
    label = _attempt_label("generate", "rsa", "swap_secret_class_asym_type")
    fake = _PolicyFake(
        keypair_pub_extra={int(CKA_CLASS): int(CKO_SECRET_KEY)},
        sign_script=[_FUNCTION_FAILED],
        encrypt_rv={("keypair", _RSA_PKCS): _FUNCTION_FAILED},
        enforce_rsa_encrypt_permission=True,
    )
    fake._extra_for_label = label
    fake._extra_attrs = fake.rsa_private_components()
    assert_xfails(_qc4b_generate, _rs(fake), "rsa", "swap_secret_class_asym_type")
    record = _assert_xfail_record("honest_deviation")
    assert (record.detail or {}).get("disposition") == "inspected-unusable", record.detail
    use_rvs = (record.detail or {}).get("use_rvs")
    assert isinstance(use_rvs, list) and ckr_name(_FUNCTION_FAILED) in use_rvs, record.detail
    attempt_pub = fake.keypair_calls[-1][0]
    assert attempt_pub.get(int(CKA_ENCRYPT)) == b"\x01", attempt_pub
    _assert_cleaned_up(fake)
    _assert_no_secret_bytes()


def test_qc4b_generate_rsa_control_pub_requests_encrypt_n5() -> None:
    """N5: attempt and matching control RSA pub templates both request ENCRYPT."""
    fake = _PolicyFake(keypair_script=[None, _TEMPLATE_INCONSISTENT])
    _qc4b_generate(_rs(fake), "rsa", "missing_modulus_bits")
    _assert_terminal_pass()
    assert len(fake.keypair_calls) == 2, "legal control must run before the attempt"
    control_pub = fake.keypair_calls[0][0]
    attempt_pub = fake.keypair_calls[1][0]
    assert control_pub.get(int(CKA_ENCRYPT)) == b"\x01", control_pub
    assert attempt_pub.get(int(CKA_ENCRYPT)) == b"\x01", attempt_pub
    _assert_cleaned_up(fake)


# Oracle group (N8): no manufactured oracle from substituted components.


def test_qc4b_unwrap_rsa_unreadable_admitted_other_key_sig_unproved_n8() -> None:
    """N8: valid-under-another-key sig + unreadable admitted halves is unproved."""
    mod = _policy_module()
    other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    signature = other.sign(mod.QC4_SIGN_DATA, padding.PKCS1v15(), hashes.SHA256())
    fake = _PolicyFake(sign_output=signature)
    assert_xfails(_qc4b_unwrap, _rs(fake), "rsa", "swap_secret_class_asym_type")
    record = _assert_xfail_record("honest_deviation")
    assert record.actual_ckr == ckr_name(_OK), record.summary
    assert (record.detail or {}).get("disposition") == "unproved-effect", record.detail
    assert not [rec for rec in C.get_records() if rec.reason == "wrong_result"]
    _assert_cleaned_up(fake)
    _assert_no_secret_bytes()


def test_qc4b_unwrap_ec_unreadable_admitted_other_key_sig_unproved_n8() -> None:
    """N8 (EC twin): no substituted params/point oracle for an admitted key."""
    mod = _policy_module()
    other = ec.generate_private_key(ec.SECP256R1())
    der = other.sign(mod.QC4_ECDSA_DIGEST, ec.ECDSA(utils.Prehashed(hashes.SHA256())))
    r, s = utils.decode_dss_signature(der)
    raw_sig = int(r).to_bytes(32, "big") + int(s).to_bytes(32, "big")
    fake = _PolicyFake(sign_output=raw_sig)
    assert_xfails(_qc4b_unwrap, _rs(fake), "ec", "swap_secret_class_asym_type")
    record = _assert_xfail_record("honest_deviation")
    assert record.actual_ckr == ckr_name(_OK), record.summary
    assert (record.detail or {}).get("disposition") == "unproved-effect", record.detail
    assert not [rec for rec in C.get_records() if rec.reason == "wrong_result"]
    _assert_cleaned_up(fake)
    _assert_no_secret_bytes()


def test_qc4b_unwrap_rsa_partial_admitted_oracle_unproved_n8() -> None:
    """N8: a half-qualified oracle (modulus only) is unqualified: unproved."""
    mod = _policy_module()
    other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    signature = other.sign(mod.QC4_SIGN_DATA, padding.PKCS1v15(), hashes.SHA256())
    fake = _PolicyFake(sign_output=signature)
    modulus, _exponent = fake.rsa_numbers()
    fake._extra_for_label = _attempt_label("unwrap", "rsa", "swap_secret_class_asym_type")
    fake._extra_attrs = {int(CKA_MODULUS): modulus}
    assert_xfails(_qc4b_unwrap, _rs(fake), "rsa", "swap_secret_class_asym_type")
    record = _assert_xfail_record("honest_deviation")
    assert (record.detail or {}).get("disposition") == "unproved-effect", record.detail
    assert not [rec for rec in C.get_records() if rec.reason == "wrong_result"]
    _assert_cleaned_up(fake)
    _assert_no_secret_bytes()


def test_qc4b_generate_rsa_priv_sign_survives_component_absence_n8() -> None:
    """N8 guard: an independent priv-Sign witness survives later absence.

    The private-component absence only voids the pub-half judgment that
    requires it; the already-witnessed coherent priv Sign adjudicates
    on its own evidence (accepted-coherent ceiling here).
    """
    label = _attempt_label("generate", "rsa", "swap_secret_class_asym_type")
    fake = _PolicyFake(hide_for={"keypair": {int(CKA_PRIVATE_EXPONENT)}})
    fake._extra_for_label = label
    fake._extra_attrs = fake.rsa_private_components()
    assert_xfails(_qc4b_generate, _rs(fake), "rsa", "swap_secret_class_asym_type")
    record = _assert_xfail_record("honest_deviation")
    assert (record.detail or {}).get("disposition") == "accepted-coherent", record.detail
    assert (record.detail or {}).get("coherent_uses") == ["rsa_sign"], record.detail
    _assert_cleaned_up(fake)
    _assert_no_secret_bytes()


# Paging / evidence group (N6, N9, N10).


def test_qc4b_create_short_find_page_still_catches_leak_n6() -> None:
    """N6: one-handle pages are not exhaustion; a second-page leak FAILs."""
    label = _attempt_label("create", "rsa", "swap_secret_class_asym_type")
    fake = _PolicyFake(
        create_script=[None, _TEMPLATE_INCONSISTENT], leak_labeled=label, find_page_cap=1
    )
    fake.plant_litter(label, 1)
    preexisting = set(fake.created)
    _run_must_fail(_qc4b_create, _rs(fake), "rsa", "swap_secret_class_asym_type")
    record = _assert_fail_record("self_contradiction", "lifecycle")
    assert record.operation == "C_CreateObject", record.operation
    assert record.actual_ckr == ckr_name(_TEMPLATE_INCONSISTENT), record.summary
    detail = record.detail or {}
    assert detail.get("leaked_count") == 1, detail
    assert detail.get("refusal_rv") == ckr_name(_TEMPLATE_INCONSISTENT), detail
    assert fake.find_pages == [1, 0, 1, 1, 0], fake.find_pages
    assert _reported_outcome() == "fail", [rec.reason for rec in C.get_records()]
    assert set(fake.destroyed) >= (set(fake.created) - preexisting)
    _assert_no_secret_bytes()


def test_qc4b_create_short_find_page_no_leak_passes_n6() -> None:
    """N6 twin: no leak passes only after an empty page ends each inventory."""
    label = _attempt_label("create", "rsa", "swap_secret_class_asym_type")
    fake = _PolicyFake(create_script=[None, _TEMPLATE_INCONSISTENT], find_page_cap=1)
    fake.plant_litter(label, 1)
    _qc4b_create(_rs(fake), "rsa", "swap_secret_class_asym_type")
    _assert_terminal_pass()
    record = _terminal_record()
    assert (record.detail or {}).get("inventory_delta") == 0, record.detail
    assert fake.find_pages == [1, 0, 1, 0], fake.find_pages
    _assert_no_secret_bytes()


def test_qc4a_wrap_vendor_peer_cleanup_assertion_bites_n9() -> None:
    """N9 bite: the cleanup assertion catches a missed destroy under a peer xfail."""
    fake = _PolicyFake(
        get_attr_script=[None, None, _VENDOR_RV],
        destroy_script=[RuntimeError("boom")],
    )
    assert_xfails(_qc4a_wrap, _rs(fake), "included", "classic")
    _assert_xfail_record("nonspec_reject")
    assert set(fake.destroy_calls) >= set(fake.created), (fake.created, fake.destroy_calls)
    with pytest.raises(AssertionError):
        _assert_cleaned_up(fake)


def test_qc4a_wrap_sensitive_peer_read_records_deviation_n9() -> None:
    """N9 §4(b): SENSITIVE on public peer metadata is a recorded deviation.

    Traced bucket (no production change): the hatch does not silence a
    SENSITIVE refusal, so attr_or_record records not_operational; the
    leg completes but the reported outcome through the real hook is
    xfail -- sensitive public metadata is not ordinary optional absence.
    """
    fake = _PolicyFake(get_attr_script=[None, None, _SENSITIVE_RV, _SENSITIVE_RV])
    _qc4a_wrap(_rs(fake), "included", "classic")
    sensitive = [
        rec
        for rec in C.get_records()
        if rec.reason == "not_operational" and rec.operation == "C_GetAttributeValue"
    ]
    assert len(sensitive) == 1, [(rec.reason, rec.operation, rec.label) for rec in C.get_records()]
    record = sensitive[0]
    assert record.kind == "policy", record.summary
    assert record.label == "C_WrapKey ALLOWED_MECHANISMS included (classic use): peer claim", (
        record.label
    )
    assert record.actual_ckr == ckr_name(_SENSITIVE_RV), record.summary
    assert _reported_outcome() == "xfail", [(rec.reason, rec.outcome) for rec in C.get_records()]
    _assert_cleaned_up(fake)
    _assert_no_secret_bytes()


def test_qc4a_wrap_sentinel_peer_read_records_deviation_n9() -> None:
    """N9 §4(b): CKR_OK + sentinel on the peer read is a recorded deviation.

    Traced bucket (no production change): success-without-value falls
    through the hatch and records not_operational with no invented CKR;
    the reported outcome through the real hook is xfail.
    """
    fake = _PolicyFake(sentinel_ok_label=b"qc4a-wrap-included-classic-target")
    _qc4a_wrap(_rs(fake), "included", "classic")
    sentinel = [
        rec
        for rec in C.get_records()
        if rec.reason == "not_operational" and rec.operation == "C_GetAttributeValue"
    ]
    assert len(sentinel) == 1, [(rec.reason, rec.operation, rec.label) for rec in C.get_records()]
    record = sentinel[0]
    assert record.kind == "policy", record.summary
    assert record.label == "C_WrapKey ALLOWED_MECHANISMS included (classic use): peer claim", (
        record.label
    )
    assert record.actual_ckr is None, record.summary
    attribute = (record.detail or {}).get("attribute") or {}
    assert attribute.get("name") == "CKA_ALLOWED_MECHANISMS", record.detail
    assert _reported_outcome() == "xfail", [(rec.reason, rec.outcome) for rec in C.get_records()]
    _assert_cleaned_up(fake)
    _assert_no_secret_bytes()


# PR64 review group (P2, P6): refused creation must account for every
# independently proved-new object, and inventory counts are validated.


@pytest.mark.parametrize(("family", "malformation"), _CREATE_CELLS)
def test_qc4b_create_refuse_unlabeled_leak_fails_p2(family: str, malformation: str) -> None:
    """P2: a refusal creating an unlabeled object fails, never sanctioned_refusal."""
    label = _attempt_label("create", family, malformation)
    fake = _PolicyFake(create_script=[None, _TEMPLATE_INCONSISTENT], leak_unlabeled=label)
    _run_must_fail(_qc4b_create, _rs(fake), family, malformation)
    record = _assert_fail_record("self_contradiction", "lifecycle")
    assert "leak" in (record.summary or "").lower(), record.summary
    assert (record.detail or {}).get("leaked_count") == 1, record.detail
    _assert_cleaned_up(fake)


@pytest.mark.parametrize(("family", "malformation"), _UNWRAP_CELLS)
def test_qc4b_unwrap_refuse_unlabeled_leak_fails_p2(family: str, malformation: str) -> None:
    """P2: an unwrap refusal creating an unlabeled object fails as leaked."""
    label = _attempt_label("unwrap", family, malformation)
    fake = _PolicyFake(unwrap_script=[None, _TEMPLATE_INCONSISTENT], leak_unlabeled=label)
    _run_must_fail(_qc4b_unwrap, _rs(fake), family, malformation)
    record = _assert_fail_record("self_contradiction", "lifecycle")
    assert "leak" in (record.summary or "").lower(), record.summary
    assert (record.detail or {}).get("leaked_count") == 1, record.detail
    _assert_cleaned_up(fake)


@pytest.mark.parametrize(("family", "malformation"), _GENERATE_CELLS)
def test_qc4b_generate_refuse_unlabeled_leak_fails_p2(family: str, malformation: str) -> None:
    """P2: a generate refusal creating unlabeled halves fails as leaked."""
    label = _attempt_label("generate", family, malformation)
    fake = _PolicyFake(keypair_script=[None, _TEMPLATE_INCONSISTENT], leak_unlabeled=label)
    _run_must_fail(_qc4b_generate, _rs(fake), family, malformation)
    record = _assert_fail_record("self_contradiction", "lifecycle")
    assert "leak" in (record.summary or "").lower(), record.summary
    assert (record.detail or {}).get("leaked_count") == 2, record.detail
    _assert_cleaned_up(fake)


def test_qc4b_create_unlabeled_leak_records_error_output_p2() -> None:
    """P2: the error-path handle is evidence only; the delta proves the leak."""
    label = _attempt_label("create", "rsa", "missing_modulus")
    fake = _PolicyFake(create_script=[None, _TEMPLATE_INCONSISTENT], leak_unlabeled=label)
    _run_must_fail(_qc4b_create, _rs(fake), "rsa", "missing_modulus")
    record = _assert_fail_record("self_contradiction", "lifecycle")
    leaked = fake.created[-1]
    assert int(CKA_LABEL) not in fake.objects[leaked].attrs, fake.objects[leaked].attrs
    assert (record.detail or {}).get("error_output_handles") == [leaked], record.detail
    assert (record.detail or {}).get("leaked_count") == 1, record.detail
    _assert_cleaned_up(fake)
    _assert_no_secret_bytes()


def test_qc4b_create_refusal_foreign_error_handle_not_destroyed_p2() -> None:
    """P2 guard: an unspecified error handle aliasing a foreign object is kept."""
    fake = _PolicyFake(create_script=[None, _TEMPLATE_INCONSISTENT], refusal_out_handle=100)
    fake.plant_litter(b"foreign-planted", 1)
    assert fake.created == [100]
    _qc4b_create(_rs(fake), "rsa", "missing_modulus")
    _assert_terminal_pass()
    record = _terminal_record()
    assert (record.detail or {}).get("inventory_delta") == 0, record.detail
    assert (record.detail or {}).get("error_output_handles") == [100], record.detail
    assert 100 not in fake.destroyed, fake.destroyed
    assert fake.objects[100].destroyed is False


def test_qc4b_create_refusal_foreign_delta_xfails_unproved_alive_r1() -> None:
    """R1: a delta object uncorrelated to the attempt is left alive."""
    label = _attempt_label("create", "rsa", "missing_modulus")
    fake = _PolicyFake(create_script=[None, _TEMPLATE_INCONSISTENT], foreign_delta_for_label=label)
    assert_xfails(_qc4b_create, _rs(fake), "rsa", "missing_modulus")
    record = _assert_xfail_record("honest_deviation")
    foreign = fake.foreign_delta_handle
    assert foreign is not None
    assert (record.detail or {}).get("disposition") == "unproved-effect", record.detail
    assert (record.detail or {}).get("unproved_new_handles") == [foreign], record.detail
    assert foreign not in fake.destroyed, fake.destroyed
    assert fake.objects[foreign].destroyed is False


def _over_capacity_raw(calls: list[str]) -> Any:
    """Raw stub whose Find claims CKR_OK with a count above capacity (P6)."""

    def _init(_sh: int, _tmpl: Any, _count: int) -> int:
        calls.append("init")
        return _OK

    def _find(_sh: int, _handles: Any, _size: int, found: Any) -> int:
        calls.append("find")
        _fill_ulong(found, 257)
        return _OK

    def _final(_sh: int) -> int:
        calls.append("final")
        return _OK

    return SimpleNamespace(C_FindObjectsInit=_init, C_FindObjects=_find, C_FindObjectsFinal=_final)


def test_find_by_label_over_capacity_count_fails_structured_p6() -> None:
    """P6: count 257 on a 256 buffer is a structured metadata FAIL, Final kept."""
    mod = _policy_module()
    calls: list[str] = []
    rs = SimpleNamespace(raw=_over_capacity_raw(calls), sh=1)
    with pytest.raises(Failed):
        mod._find_by_label(rs, "qc4b-over-capacity")
    record = _assert_fail_record("self_contradiction", "metadata")
    assert record.operation == "C_FindObjects", record.operation
    detail = record.detail or {}
    assert detail.get("count") == 257, detail
    assert detail.get("capacity") == mod._FIND_PAGE_SIZE, detail
    assert calls == ["init", "find", "final"], calls


def test_find_all_over_capacity_count_fails_structured_p6() -> None:
    """P6: the full-inventory twin carries the same capacity discipline."""
    mod = _policy_module()
    calls: list[str] = []
    rs = SimpleNamespace(raw=_over_capacity_raw(calls), sh=1)
    with pytest.raises(Failed):
        mod._find_all(rs)
    record = _assert_fail_record("self_contradiction", "metadata")
    assert record.operation == "C_FindObjects", record.operation
    detail = record.detail or {}
    assert detail.get("count") == 257, detail
    assert detail.get("capacity") == mod._FIND_PAGE_SIZE, detail
    assert calls == ["init", "find", "final"], calls
