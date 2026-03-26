"""Helpers for building exact raw PKCS#11 values with owned storage."""

from __future__ import annotations

import ctypes
from dataclasses import dataclass
from typing import Any

from .types_std import (
    CK_AES_CCM_PARAMS,
    CK_AES_CTR_PARAMS,
    CK_AES_GCM_PARAMS,
    CK_ATTRIBUTE,
    CK_BBOOL,
    CK_CHACHA20_PARAMS,
    CK_DATE,
    CK_ECDH1_DERIVE_PARAMS,
    CK_EDDSA_PARAMS,
    CK_HKDF_PARAMS,
    CK_KEY_DERIVATION_STRING_DATA,
    CK_MECHANISM,
    CK_PKCS5_PBKD2_PARAMS2,
    CK_RSA_PKCS_OAEP_PARAMS,
    CK_RSA_PKCS_PSS_PARAMS,
    CK_SALSA20_CHACHA20_POLY1305_PARAMS,
    CK_SSL3_KEY_MAT_OUT,
    CK_SSL3_KEY_MAT_PARAMS,
    CK_SSL3_MASTER_KEY_DERIVE_PARAMS,
    CK_SSL3_RANDOM_DATA,
    CK_TLS12_EXTENDED_MASTER_KEY_DERIVE_PARAMS,
    CK_TLS12_KEY_MAT_PARAMS,
    CK_TLS12_MASTER_KEY_DERIVE_PARAMS,
    CK_TLS_KDF_PARAMS,
    CK_TLS_MAC_PARAMS,
    CK_TLS_PRF_PARAMS,
    CK_ULONG,
    CK_VERSION,
    CK_VOID_PTR,
    CK_WTLS_KEY_MAT_OUT,
    CK_WTLS_KEY_MAT_PARAMS,
    CK_WTLS_MASTER_KEY_DERIVE_PARAMS,
    CK_WTLS_PRF_PARAMS,
    CK_WTLS_RANDOM_DATA,
    CKA,
    CKM,
    CKZ_DATA_SPECIFIED,
)


@dataclass(frozen=True)
class LengthArg:
    """Explicit or native byte length for a packed value."""

    value: int
    explicit: bool = False

    @classmethod
    def native(cls, size: int) -> LengthArg:
        return cls(value=size, explicit=False)

    @classmethod
    def explicit_value(cls, size: int) -> LengthArg:
        return cls(value=size, explicit=True)


@dataclass(frozen=True)
class PointerArg:
    """Pointer plus owned storage that must stay alive for the call."""

    pointer: Any
    storage: Any = None
    kind: str = "null"
    origin: str = "unknown"
    native_length: int | None = None
    storage_size: int | None = None
    element_count: int | None = None
    element_type: str | None = None

    @classmethod
    def null(cls, *, origin: str = "unknown") -> PointerArg:
        return cls(pointer=None, origin=origin)

    @classmethod
    def to_storage(
        cls,
        storage: Any,
        *,
        origin: str = "unknown",
        native_length: int | None = None,
    ) -> PointerArg:
        if storage is None:
            return cls.null(origin=origin)
        if isinstance(storage, ctypes.Structure):
            pointer = ctypes.cast(ctypes.pointer(storage), CK_VOID_PTR)
            kind = "struct"
            resolved_native_length = ctypes.sizeof(storage)
            storage_size = ctypes.sizeof(storage)
            element_count = 1
            element_type = type(storage).__name__
        elif isinstance(storage, ctypes.Array):
            pointer = ctypes.cast(storage, CK_VOID_PTR)
            item_type = getattr(type(storage), "_type_", None)
            byte_types = (ctypes.c_char, ctypes.c_byte, ctypes.c_ubyte)
            kind = "bytes" if item_type in byte_types else "array"
            resolved_native_length = ctypes.sizeof(storage)
            storage_size = ctypes.sizeof(storage)
            element_count = len(storage)
            fallback = type(item_type).__name__ if item_type else None
            element_type = getattr(item_type, "__name__", fallback)
        else:
            pointer = ctypes.cast(ctypes.pointer(storage), CK_VOID_PTR)
            kind = "scalar"
            resolved_native_length = ctypes.sizeof(storage)
            storage_size = ctypes.sizeof(storage)
            element_count = 1
            element_type = type(storage).__name__
        return cls(
            pointer=pointer,
            storage=storage,
            kind=kind,
            origin=origin,
            native_length=resolved_native_length if native_length is None else native_length,
            storage_size=storage_size,
            element_count=element_count,
            element_type=element_type,
        )


@dataclass(frozen=True)
class PackedAttribute:
    """A CK_ATTRIBUTE with owned backing storage."""

    attribute: CK_ATTRIBUTE
    storage: Any
    pointer_arg: PointerArg
    length_arg: LengthArg


class PackedMechanism:
    """A CK_MECHANISM with owned parameter storage.

    The params attribute holds a typed reference to the mechanism parameter struct
    (e.g. CK_AES_GCM_PARAMS) for struct-based packers. For mech_simple/mech_bytes
    it is None. Dynamic attributes (e.g. _iv_buf) keep buffer lifetime.
    """

    def __init__(
        self,
        ck: CK_MECHANISM,
        storage: Any = None,
        pointer_arg: PointerArg | None = None,
        length_arg: LengthArg | None = None,
        params: Any = None,
    ) -> None:
        self.ck = ck
        self.storage = storage
        self.pointer_arg = pointer_arg or PointerArg.null()
        self.length_arg = length_arg or LengthArg.explicit_value(0)
        self.params = params
        self._keepalive: list[Any] = []

    def byref(self) -> Any:
        return ctypes.byref(self.ck)


class TemplateArg:
    """Own a CK_ATTRIBUTE array and the buffers backing it."""

    def __init__(self, *attributes: PackedAttribute) -> None:
        self._attributes = list(attributes)
        self._storages = [attribute.storage for attribute in attributes]
        attr_type = CK_ATTRIBUTE * len(attributes)
        self.array = attr_type(*(attribute.attribute for attribute in attributes))
        self.count = len(attributes)
        self.actual_count = len(attributes)
        self.ptr = self.array

    @property
    def attributes(self) -> tuple[PackedAttribute, ...]:
        return tuple(self._attributes)


MechanismArg = PackedMechanism
CKTemplate = TemplateArg


def explicit_length(size: int) -> LengthArg:
    return LengthArg.explicit_value(size)


def _exact_byte_storage(data: bytes) -> Any:
    return ctypes.create_string_buffer(data, len(data))


def _native_length(storage: Any) -> LengthArg:
    return LengthArg.native(ctypes.sizeof(storage))


def _build_attribute(
    attr_type: int,
    pointer: PointerArg,
    length: LengthArg,
) -> PackedAttribute:
    return PackedAttribute(
        attribute=CK_ATTRIBUTE(
            type=attr_type,
            pValue=pointer.pointer,
            ulValueLen=length.value,
        ),
        storage=pointer.storage,
        pointer_arg=pointer,
        length_arg=length,
    )


def _coerce_length(length: LengthArg | None, storage: Any) -> LengthArg:
    if length is not None:
        return length
    return _native_length(storage)


def attr_bool(attr_type: CKA, value: bool, *, length: LengthArg | None = None) -> PackedAttribute:
    storage = CK_BBOOL(1 if value else 0)
    return _build_attribute(
        attr_type,
        PointerArg.to_storage(storage, origin="attr_bool"),
        _coerce_length(length, storage),
    )


def attr_ulong(attr_type: CKA, value: int, *, length: LengthArg | None = None) -> PackedAttribute:
    storage = CK_ULONG(value)
    return _build_attribute(
        attr_type,
        PointerArg.to_storage(storage, origin="attr_ulong"),
        _coerce_length(length, storage),
    )


def attr_bytes(
    attr_type: CKA,
    value: bytes | bytearray | memoryview,
    *,
    length: LengthArg | None = None,
) -> PackedAttribute:
    data = bytes(value)
    storage = _exact_byte_storage(data)
    return _build_attribute(
        attr_type,
        PointerArg.to_storage(storage, origin="attr_bytes", native_length=len(data)),
        length or LengthArg.native(len(data)),
    )


def attr_string(
    attr_type: CKA,
    value: str,
    *,
    encoding: str = "utf-8",
    length: LengthArg | None = None,
) -> PackedAttribute:
    return attr_bytes(attr_type, value.encode(encoding), length=length)


def attr_date(
    attr_type: CKA,
    year: str,
    month: str,
    day: str,
    *,
    length: LengthArg | None = None,
) -> PackedAttribute:
    storage = CK_DATE(year.encode("ascii"), month.encode("ascii"), day.encode("ascii"))
    return _build_attribute(
        attr_type,
        PointerArg.to_storage(storage, origin="attr_date"),
        _coerce_length(length, storage),
    )


def attr_array(
    attr_type: CKA,
    values: list[int] | tuple[int, ...],
    *,
    ctype: Any = CK_ULONG,
    length: LengthArg | None = None,
) -> PackedAttribute:
    storage = (ctype * len(values))(*values)
    return _build_attribute(
        attr_type,
        PointerArg.to_storage(storage, origin="attr_array"),
        _coerce_length(length, storage),
    )


def attr_template(
    attr_type: CKA,
    value: TemplateArg,
    *,
    length: LengthArg | None = None,
) -> PackedAttribute:
    native = LengthArg(value.count * ctypes.sizeof(CK_ATTRIBUTE))
    pointer_arg = PointerArg(
        pointer=ctypes.cast(value.array, CK_VOID_PTR),
        storage=value,
        kind="array",
        origin="attr_template",
        native_length=value.actual_count * ctypes.sizeof(CK_ATTRIBUTE),
        element_count=value.actual_count,
        element_type="CK_ATTRIBUTE",
    )
    chosen_length = length or native
    return PackedAttribute(
        attribute=CK_ATTRIBUTE(
            type=attr_type,
            pValue=pointer_arg.pointer,
            ulValueLen=chosen_length.value,
        ),
        storage=value,
        pointer_arg=pointer_arg,
        length_arg=chosen_length,
    )


def template(*attributes: PackedAttribute) -> TemplateArg:
    return TemplateArg(*attributes)


def attr_auto(attr_type: int, value: Any) -> PackedAttribute:
    """Pack an attribute using ATTR_VALUE_TYPES for spec-correct wire type.

    Supports all PKCS#11 attribute types:
    - 'bool': CK_BBOOL (accepts bool or int)
    - 'ulong': CK_ULONG (accepts int)
    - 'str': RFC2279 UTF-8 (accepts str or bytes)
    - 'bytes': raw byte array (accepts bytes, bytearray)
    - 'date': CK_DATE 8-byte YYYYMMDD (accepts datetime.date or str 'YYYYMMDD')
    - 'ulong_array': CK_ULONG[] (accepts list[int] or tuple[int, ...])
    - 'template': CK_ATTRIBUTE[] — not supported for auto-packing, use pack.template() directly

    For deliberate mispacking (fault tests), use attr_bool/attr_ulong/attr_bytes directly.
    """
    from .attr_metadata import ATTR_VALUE_TYPES

    vtype = ATTR_VALUE_TYPES.get(attr_type)

    if vtype == "bool":
        return attr_bool(attr_type, bool(value))
    elif vtype == "ulong":
        return attr_ulong(attr_type, int(value))
    elif vtype == "str":
        if isinstance(value, bytes):
            return attr_bytes(attr_type, value)
        return attr_bytes(attr_type, str(value).encode("utf-8"))
    elif vtype == "bytes":
        if isinstance(value, str):
            return attr_bytes(attr_type, value.encode("utf-8"))
        if isinstance(value, (bytes, bytearray, memoryview)):
            return attr_bytes(attr_type, bytes(value))
        raise TypeError(
            f"attr_auto: 'bytes' type expects bytes/bytearray, got {type(value).__name__} "
            f"for attr {attr_type:#x}"
        )
    elif vtype == "date":
        # CK_DATE is 8 bytes: YYYYMMDD in ASCII
        import datetime

        if isinstance(value, datetime.date):
            date_bytes = value.strftime("%Y%m%d").encode("ascii")
        elif isinstance(value, str):
            # Validate format
            if len(value) != 8 or not value.isdigit():
                raise ValueError(f"attr_auto: 'date' string must be 'YYYYMMDD', got {value!r}")
            date_bytes = value.encode("ascii")
        elif isinstance(value, bytes) and len(value) == 8:
            date_bytes = value
        else:
            raise TypeError(
                f"attr_auto: 'date' type expects datetime.date, 'YYYYMMDD' str, or 8 bytes, "
                f"got {type(value).__name__} for attr {attr_type:#x}"
            )
        return attr_bytes(attr_type, date_bytes)
    elif vtype == "ulong_array":
        # Pack list of ints as CK_ULONG array
        if not isinstance(value, (list, tuple)):
            raise TypeError(
                f"attr_auto: 'ulong_array' type expects list[int] or tuple[int, ...], "
                f"got {type(value).__name__} for attr {attr_type:#x}"
            )
        arr = (CK_ULONG * len(value))(*value)
        return attr_bytes(attr_type, bytes(arr))
    elif vtype == "template":
        raise TypeError(
            f"attr_auto: 'template' attributes (attr {attr_type:#x}) cannot be auto-packed. "
            f"Use pack.template() and pack.attr_template() directly."
        )
    elif vtype is None:
        # Unknown attribute not in ATTR_VALUE_TYPES — fall back to Python type inference
        # but only for vendor/unknown attrs
        if isinstance(value, bool):
            return attr_bool(attr_type, value)
        elif isinstance(value, int):
            return attr_ulong(attr_type, value)
        elif isinstance(value, str):
            return attr_bytes(attr_type, value.encode("utf-8"))
        elif isinstance(value, (bytes, bytearray)):
            return attr_bytes(attr_type, value)
        raise TypeError(
            f"attr_auto: unknown attr {attr_type:#x} not in ATTR_VALUE_TYPES, "
            f"and cannot infer type from {type(value).__name__}"
        )
    else:
        raise TypeError(f"attr_auto: unsupported value type {vtype!r} for attr {attr_type:#x}")


def template_from_dict(attrs: dict[int, Any]) -> TemplateArg:
    """Build a template from {CKA_*: value} dict with spec-correct type packing."""
    return template(*[attr_auto(k, v) for k, v in attrs.items()])


def mech_simple(mechanism_type: CKM) -> PackedMechanism:
    pointer_arg = PointerArg.null(origin="mech_simple")
    length_arg = LengthArg.explicit_value(0)
    return PackedMechanism(
        CK_MECHANISM(mechanism_type, None, 0),
        pointer_arg=pointer_arg,
        length_arg=length_arg,
    )


def mech_bytes(
    mechanism_type: CKM,
    value: bytes | bytearray | memoryview,
    *,
    length: LengthArg | None = None,
) -> PackedMechanism:
    data = bytes(value)
    storage = _exact_byte_storage(data)
    pointer_arg = PointerArg.to_storage(storage, origin="mech_bytes", native_length=len(data))
    length_arg = length if length is not None else LengthArg.native(len(data))
    return PackedMechanism(
        CK_MECHANISM(mechanism_type, pointer_arg.pointer, length_arg.value),
        storage=storage,
        pointer_arg=pointer_arg,
        length_arg=length_arg,
    )


def _pack_bytes(
    data: bytes | None,
    keepalive: list[Any],
) -> tuple[Any, int]:
    """Pack optional bytes into a ctypes buffer with lifetime tracking.

    Returns (void_ptr_or_None, length). Appends buffer to keepalive.
    """
    if data is None:
        return None, 0
    buf = (ctypes.c_ubyte * len(data))(*data)
    keepalive.append(buf)
    return ctypes.cast(buf, CK_VOID_PTR), len(data)


def _mech_struct(
    mechanism_type: CKM,
    params: ctypes.Structure,
    origin: str,
    keepalive: list[Any] | None = None,
) -> PackedMechanism:
    """Build a PackedMechanism from a pre-populated ctypes struct."""
    pointer_arg = PointerArg.to_storage(params, origin=origin)
    length_arg = LengthArg.native(ctypes.sizeof(params))
    result = PackedMechanism(
        CK_MECHANISM(mechanism_type, pointer_arg.pointer, length_arg.value),
        storage=params,
        pointer_arg=pointer_arg,
        length_arg=length_arg,
        params=params,
    )
    if keepalive:
        result._keepalive.extend(keepalive)
    return result


def mech_gcm(
    mechanism_type: CKM,
    iv: bytes,
    *,
    aad: bytes | None = None,
    aad_len: int = 0,
    tag_bits: int = 128,
) -> PackedMechanism:
    """Pack CK_AES_GCM_PARAMS.

    Pass ``aad`` for actual AAD data; ``aad_len`` is a legacy shortcut that
    sets ulAADLen without a pointer (only valid when the module ignores pAAD).
    When ``aad`` is provided its length overrides ``aad_len``.
    """
    ka: list[Any] = []
    params = CK_AES_GCM_PARAMS()
    params.pIv, params.ulIvLen = _pack_bytes(iv, ka)
    params.ulIvBits = params.ulIvLen * 8
    if aad is not None:
        params.pAAD, params.ulAADLen = _pack_bytes(aad, ka)
    else:
        params.pAAD = None
        params.ulAADLen = aad_len
    params.ulTagBits = tag_bits
    return _mech_struct(mechanism_type, params, "mech_gcm", ka)


def mech_ccm(
    mechanism_type: CKM,
    nonce: bytes,
    *,
    data_len: int = 0,
    aad: bytes | None = None,
    mac_len: int = 16,
) -> PackedMechanism:
    """Pack CK_AES_CCM_PARAMS."""
    ka: list[Any] = []
    params = CK_AES_CCM_PARAMS()
    params.ulDataLen = data_len
    params.pNonce, params.ulNonceLen = _pack_bytes(nonce, ka)
    if aad is not None:
        params.pAAD, params.ulAADLen = _pack_bytes(aad, ka)
    else:
        params.pAAD = None
        params.ulAADLen = 0
    params.ulMACLen = mac_len
    return _mech_struct(mechanism_type, params, "mech_ccm", ka)


def mech_pss(
    mechanism_type: CKM,
    *,
    hash_mech: int,
    mgf: int,
    salt_len: int,
) -> PackedMechanism:
    """Pack CK_RSA_PKCS_PSS_PARAMS."""
    params = CK_RSA_PKCS_PSS_PARAMS()
    params.hashAlg = hash_mech
    params.mgf = mgf
    params.sLen = salt_len
    return _mech_struct(mechanism_type, params, "mech_pss")


def mech_oaep(
    mechanism_type: CKM,
    *,
    hash_mech: int,
    mgf: int,
    source_data: bytes | None = None,
) -> PackedMechanism:
    """Pack CK_RSA_PKCS_OAEP_PARAMS."""
    ka: list[Any] = []
    params = CK_RSA_PKCS_OAEP_PARAMS()
    params.hashAlg = hash_mech
    params.mgf = mgf
    params.source = CKZ_DATA_SPECIFIED
    params.pSourceData, params.ulSourceDataLen = _pack_bytes(source_data, ka)
    return _mech_struct(mechanism_type, params, "mech_oaep", ka)


def mech_ecdh(
    mechanism_type: CKM,
    *,
    kdf: int,
    public_data: bytes,
    shared_data: bytes | None = None,
) -> PackedMechanism:
    """Pack CK_ECDH1_DERIVE_PARAMS."""
    ka: list[Any] = []
    params = CK_ECDH1_DERIVE_PARAMS()
    params.kdf = kdf
    params.pPublicData, params.ulPublicDataLen = _pack_bytes(public_data, ka)
    params.pSharedData, params.ulSharedDataLen = _pack_bytes(shared_data, ka)
    return _mech_struct(mechanism_type, params, "mech_ecdh", ka)


def mech_hkdf(
    mechanism_type: CKM,
    *,
    hash_mech: int,
    extract: bool = True,
    expand: bool = True,
    salt_type: int = 1,
    salt: bytes | None = None,
    salt_key: int = 0,
    info: bytes | None = None,
) -> PackedMechanism:
    """Pack CK_HKDF_PARAMS."""
    ka: list[Any] = []
    params = CK_HKDF_PARAMS()
    params.bExtract = 1 if extract else 0
    params.bExpand = 1 if expand else 0
    params.prfHashMechanism = hash_mech
    params.ulSaltType = salt_type
    params.hSaltKey = salt_key
    params.pSalt, params.ulSaltLen = _pack_bytes(salt, ka)
    params.pInfo, params.ulInfoLen = _pack_bytes(info, ka)
    return _mech_struct(mechanism_type, params, "mech_hkdf", ka)


def mech_cbc_pad(mechanism_type: CKM, iv: bytes) -> PackedMechanism:
    """Pack 16-byte IV for AES-CBC / AES-CBC-PAD (raw bytes parameter)."""
    return mech_bytes(mechanism_type, iv)


def mech_ctr(mechanism_type: CKM, bits: int = 128) -> PackedMechanism:
    """Pack CK_AES_CTR_PARAMS with ulCounterBits=bits and zeroed counter block."""
    params = CK_AES_CTR_PARAMS()
    params.ulCounterBits = bits
    for i in range(16):
        params.cb[i] = 0
    return _mech_struct(mechanism_type, params, "mech_ctr")


def mech_chacha20(
    mechanism_type: CKM,
    nonce: bytes,
    counter: int = 0,
) -> PackedMechanism:
    """Pack CK_CHACHA20_PARAMS with a counter and nonce."""
    ka: list[Any] = []
    params = CK_CHACHA20_PARAMS()
    counter_bytes = counter.to_bytes(4, "little")
    params.pBlockCounter, _ = _pack_bytes(counter_bytes, ka)
    params.blockCounterBits = 32
    params.pNonce, _ = _pack_bytes(nonce, ka)
    params.ulNonceBits = len(nonce) * 8
    return _mech_struct(mechanism_type, params, "mech_chacha20", ka)


def mech_chacha20_poly1305(
    mechanism_type: CKM,
    nonce: bytes,
    aad: bytes | None = None,
) -> PackedMechanism:
    """Pack CK_SALSA20_CHACHA20_POLY1305_PARAMS with nonce and optional AAD."""
    ka: list[Any] = []
    params = CK_SALSA20_CHACHA20_POLY1305_PARAMS()
    params.pNonce, params.ulNonceLen = _pack_bytes(nonce, ka)
    params.pAAD, params.ulAADLen = _pack_bytes(aad, ka)
    return _mech_struct(mechanism_type, params, "mech_chacha20_poly1305", ka)


def mech_eddsa(
    mechanism_type: CKM,
    *,
    context_data: bytes | None = None,
) -> PackedMechanism:
    """Pack CK_EDDSA_PARAMS; sets phFlag=1 when context_data is provided."""
    ka: list[Any] = []
    params = CK_EDDSA_PARAMS()
    params.phFlag = CK_BBOOL(1 if context_data is not None else 0)
    params.pContextData, params.ulContextDataLen = _pack_bytes(context_data, ka)
    return _mech_struct(mechanism_type, params, "mech_eddsa", ka)


def mech_pbkdf2(
    mechanism_type: CKM,
    *,
    salt: bytes,
    iterations: int,
    prf: int,
    password: bytes | None = None,
) -> PackedMechanism:
    """Pack CK_PKCS5_PBKD2_PARAMS2 (saltSource=CKZ_SALT_SPECIFIED=1)."""
    ka: list[Any] = []
    params = CK_PKCS5_PBKD2_PARAMS2()
    params.saltSource = 1  # CKZ_SALT_SPECIFIED
    params.pSaltSourceData, params.ulSaltSourceDataLen = _pack_bytes(salt, ka)
    params.iterations = iterations
    params.prf = prf
    params.pPrfData = None
    params.ulPrfDataLen = 0
    params.pPassword, params.ulPasswordLen = _pack_bytes(password, ka)
    return _mech_struct(mechanism_type, params, "mech_pbkdf2", ka)


def mech_string_data(mechanism_type: CKM, data: bytes) -> PackedMechanism:
    """Pack CK_KEY_DERIVATION_STRING_DATA for concatenation-style derivation."""
    ka: list[Any] = []
    params = CK_KEY_DERIVATION_STRING_DATA()
    params.pData, params.ulLen = _pack_bytes(data, ka)
    return _mech_struct(mechanism_type, params, "mech_string_data", ka)


# ---------------------------------------------------------------------------
# SSL3 / TLS / WTLS mechanism packers
# ---------------------------------------------------------------------------


def _fill_ssl3_random(
    random_data: CK_SSL3_RANDOM_DATA,
    client_random: bytes,
    server_random: bytes,
    keepalive: list[Any],
) -> None:
    """Populate a CK_SSL3_RANDOM_DATA struct with client/server randoms."""
    random_data.pClientRandom, random_data.ulClientRandomLen = _pack_bytes(
        client_random,
        keepalive,
    )
    random_data.pServerRandom, random_data.ulServerRandomLen = _pack_bytes(
        server_random,
        keepalive,
    )


def mech_ssl3_master_key_derive(
    mechanism_type: CKM,
    client_random: bytes,
    server_random: bytes,
    *,
    with_version: bool = True,
) -> PackedMechanism:
    """Pack CK_SSL3_MASTER_KEY_DERIVE_PARAMS.

    Used for CKM_SSL3_MASTER_KEY_DERIVE, CKM_SSL3_MASTER_KEY_DERIVE_DH,
    CKM_TLS_MASTER_KEY_DERIVE, and CKM_TLS_MASTER_KEY_DERIVE_DH.

    When *with_version* is True (default), pVersion points to a CK_VERSION
    struct that the module will fill in.  Set False for DH variants where
    the version field is unused (pVersion=NULL).
    """
    ka: list[Any] = []
    params = CK_SSL3_MASTER_KEY_DERIVE_PARAMS()
    _fill_ssl3_random(params.RandomInfo, client_random, server_random, ka)
    if with_version:
        ver = CK_VERSION(0, 0)
        ka.append(ver)
        params.pVersion = ctypes.cast(ctypes.pointer(ver), CK_VOID_PTR)
    else:
        params.pVersion = None
    return _mech_struct(mechanism_type, params, "mech_ssl3_master_key_derive", ka)


def mech_ssl3_key_mat(
    mechanism_type: CKM,
    client_random: bytes,
    server_random: bytes,
    *,
    mac_size_bits: int = 0,
    key_size_bits: int = 128,
    iv_size_bits: int = 128,
    is_export: bool = False,
) -> PackedMechanism:
    """Pack CK_SSL3_KEY_MAT_PARAMS.

    Used for CKM_SSL3_KEY_AND_MAC_DERIVE and CKM_TLS_KEY_AND_MAC_DERIVE.
    Returns a PackedMechanism whose .params.pReturnedKeyMaterial points to a
    CK_SSL3_KEY_MAT_OUT struct (accessible as pm.params._key_mat_out_ref).
    """
    ka: list[Any] = []
    params = CK_SSL3_KEY_MAT_PARAMS()
    params.ulMacSizeInBits = mac_size_bits
    params.ulKeySizeInBits = key_size_bits
    params.ulIVSizeInBits = iv_size_bits
    params.bIsExport = CK_BBOOL(1 if is_export else 0)
    _fill_ssl3_random(params.RandomInfo, client_random, server_random, ka)

    # Allocate output struct
    key_mat_out = CK_SSL3_KEY_MAT_OUT()
    iv_bytes = iv_size_bits // 8 if iv_size_bits else 0
    if iv_bytes:
        iv_client = (ctypes.c_ubyte * iv_bytes)()
        iv_server = (ctypes.c_ubyte * iv_bytes)()
        key_mat_out.pIVClient = ctypes.cast(iv_client, CK_VOID_PTR)
        key_mat_out.pIVServer = ctypes.cast(iv_server, CK_VOID_PTR)
        ka.extend([iv_client, iv_server])
    ka.append(key_mat_out)
    params.pReturnedKeyMaterial = ctypes.cast(
        ctypes.pointer(key_mat_out),
        CK_VOID_PTR,
    )
    result = _mech_struct(mechanism_type, params, "mech_ssl3_key_mat", ka)
    # Stash for callers to read output key handles
    result._key_mat_out_ref = key_mat_out  # type: ignore[attr-defined]
    return result


def mech_tls12_master_key_derive(
    mechanism_type: CKM,
    client_random: bytes,
    server_random: bytes,
    hash_mech: int,
    *,
    with_version: bool = True,
) -> PackedMechanism:
    """Pack CK_TLS12_MASTER_KEY_DERIVE_PARAMS.

    Used for CKM_TLS12_MASTER_KEY_DERIVE and CKM_TLS12_MASTER_KEY_DERIVE_DH.
    *hash_mech* is the PRF hash mechanism (e.g. CKM_SHA256).
    """
    ka: list[Any] = []
    params = CK_TLS12_MASTER_KEY_DERIVE_PARAMS()
    _fill_ssl3_random(params.RandomInfo, client_random, server_random, ka)
    if with_version:
        ver = CK_VERSION(0, 0)
        ka.append(ver)
        params.pVersion = ctypes.cast(ctypes.pointer(ver), CK_VOID_PTR)
    else:
        params.pVersion = None
    params.prfHashMechanism = hash_mech
    return _mech_struct(mechanism_type, params, "mech_tls12_master_key_derive", ka)


def mech_tls12_key_mat(
    mechanism_type: CKM,
    client_random: bytes,
    server_random: bytes,
    hash_mech: int,
    *,
    mac_size_bits: int = 0,
    key_size_bits: int = 128,
    iv_size_bits: int = 128,
    is_export: bool = False,
) -> PackedMechanism:
    """Pack CK_TLS12_KEY_MAT_PARAMS.

    Used for CKM_TLS12_KEY_AND_MAC_DERIVE and CKM_TLS12_KEY_SAFE_DERIVE.
    """
    ka: list[Any] = []
    params = CK_TLS12_KEY_MAT_PARAMS()
    params.ulMacSizeInBits = mac_size_bits
    params.ulKeySizeInBits = key_size_bits
    params.ulIVSizeInBits = iv_size_bits
    params.bIsExport = CK_BBOOL(1 if is_export else 0)
    _fill_ssl3_random(params.RandomInfo, client_random, server_random, ka)

    key_mat_out = CK_SSL3_KEY_MAT_OUT()
    iv_bytes = iv_size_bits // 8 if iv_size_bits else 0
    if iv_bytes:
        iv_client = (ctypes.c_ubyte * iv_bytes)()
        iv_server = (ctypes.c_ubyte * iv_bytes)()
        key_mat_out.pIVClient = ctypes.cast(iv_client, CK_VOID_PTR)
        key_mat_out.pIVServer = ctypes.cast(iv_server, CK_VOID_PTR)
        ka.extend([iv_client, iv_server])
    ka.append(key_mat_out)
    params.pReturnedKeyMaterial = ctypes.cast(
        ctypes.pointer(key_mat_out),
        CK_VOID_PTR,
    )
    params.prfHashMechanism = hash_mech
    result = _mech_struct(mechanism_type, params, "mech_tls12_key_mat", ka)
    result._key_mat_out_ref = key_mat_out  # type: ignore[attr-defined]
    return result


def mech_tls12_extended_master_key_derive(
    mechanism_type: CKM,
    hash_mech: int,
    session_hash: bytes,
    *,
    with_version: bool = True,
) -> PackedMechanism:
    """Pack CK_TLS12_EXTENDED_MASTER_KEY_DERIVE_PARAMS.

    Used for CKM_TLS12_EXTENDED_MASTER_KEY_DERIVE and the DH variant.
    """
    ka: list[Any] = []
    params = CK_TLS12_EXTENDED_MASTER_KEY_DERIVE_PARAMS()
    params.prfHashMechanism = hash_mech
    params.pSessionHash, params.ulSessionHashLen = _pack_bytes(session_hash, ka)
    if with_version:
        ver = CK_VERSION(0, 0)
        ka.append(ver)
        params.pVersion = ctypes.cast(ctypes.pointer(ver), CK_VOID_PTR)
    else:
        params.pVersion = None
    return _mech_struct(
        mechanism_type,
        params,
        "mech_tls12_extended_master_key_derive",
        ka,
    )


def mech_tls_prf(
    mechanism_type: CKM,
    seed: bytes,
    label: bytes,
    output_len: int,
) -> PackedMechanism:
    """Pack CK_TLS_PRF_PARAMS.

    Used for CKM_TLS_PRF. Allocates an output buffer of *output_len* bytes
    and a CK_ULONG for pulOutputLen.
    """
    ka: list[Any] = []
    params = CK_TLS_PRF_PARAMS()
    params.pSeed, params.ulSeedLen = _pack_bytes(seed, ka)
    params.pLabel, params.ulLabelLen = _pack_bytes(label, ka)
    out_buf = (ctypes.c_ubyte * output_len)()
    ka.append(out_buf)
    params.pOutput = ctypes.cast(out_buf, CK_VOID_PTR)
    out_len = CK_ULONG(output_len)
    ka.append(out_len)
    params.pulOutputLen = ctypes.cast(ctypes.pointer(out_len), CK_VOID_PTR)
    result = _mech_struct(mechanism_type, params, "mech_tls_prf", ka)
    result._output_buf = out_buf  # type: ignore[attr-defined]
    result._output_len = out_len  # type: ignore[attr-defined]
    return result


def mech_tls_kdf(
    mechanism_type: CKM,
    prf_mechanism: int,
    label: bytes,
    client_random: bytes,
    server_random: bytes,
    *,
    context_data: bytes | None = None,
) -> PackedMechanism:
    """Pack CK_TLS_KDF_PARAMS.

    Used for CKM_TLS12_KDF and CKM_TLS_KDF.
    """
    ka: list[Any] = []
    params = CK_TLS_KDF_PARAMS()
    params.prfMechanism = prf_mechanism
    params.pLabel, params.ulLabelLength = _pack_bytes(label, ka)
    _fill_ssl3_random(params.RandomInfo, client_random, server_random, ka)
    params.pContextData, params.ulContextDataLength = _pack_bytes(context_data, ka)
    return _mech_struct(mechanism_type, params, "mech_tls_kdf", ka)


def mech_tls_mac(
    mechanism_type: CKM,
    prf_hash_mechanism: int,
    mac_length: int,
    server_or_client: int,
) -> PackedMechanism:
    """Pack CK_TLS_MAC_PARAMS.

    Used for CKM_TLS12_MAC and CKM_TLS_MAC.
    *server_or_client*: 1=server, 2=client.
    """
    params = CK_TLS_MAC_PARAMS()
    params.prfHashMechanism = prf_hash_mechanism
    params.ulMacLength = mac_length
    params.ulServerOrClient = server_or_client
    return _mech_struct(mechanism_type, params, "mech_tls_mac")


def _fill_wtls_random(
    random_data: CK_WTLS_RANDOM_DATA,
    client_random: bytes,
    server_random: bytes,
    keepalive: list[Any],
) -> None:
    """Populate a CK_WTLS_RANDOM_DATA struct with client/server randoms."""
    random_data.pClientRandom, random_data.ulClientRandomLen = _pack_bytes(
        client_random,
        keepalive,
    )
    random_data.pServerRandom, random_data.ulServerRandomLen = _pack_bytes(
        server_random,
        keepalive,
    )


def mech_wtls_master_key_derive(
    mechanism_type: CKM,
    digest_mechanism: int,
    client_random: bytes,
    server_random: bytes,
    *,
    with_version: bool = True,
) -> PackedMechanism:
    """Pack CK_WTLS_MASTER_KEY_DERIVE_PARAMS.

    Used for CKM_WTLS_MASTER_KEY_DERIVE and CKM_WTLS_MASTER_KEY_DERIVE_DH_ECC.
    """
    ka: list[Any] = []
    params = CK_WTLS_MASTER_KEY_DERIVE_PARAMS()
    params.DigestMechanism = digest_mechanism
    _fill_wtls_random(params.RandomInfo, client_random, server_random, ka)
    if with_version:
        ver = CK_VERSION(0, 0)
        ka.append(ver)
        params.pVersion = ctypes.cast(ctypes.pointer(ver), CK_VOID_PTR)
    else:
        params.pVersion = None
    return _mech_struct(mechanism_type, params, "mech_wtls_master_key_derive", ka)


def mech_wtls_key_mat(
    mechanism_type: CKM,
    digest_mechanism: int,
    client_random: bytes,
    server_random: bytes,
    *,
    mac_size_bits: int = 0,
    key_size_bits: int = 128,
    iv_size_bits: int = 0,
    sequence_number: int = 0,
    is_export: bool = False,
) -> PackedMechanism:
    """Pack CK_WTLS_KEY_MAT_PARAMS.

    Used for CKM_WTLS_SERVER_KEY_AND_MAC_DERIVE and
    CKM_WTLS_CLIENT_KEY_AND_MAC_DERIVE.
    """
    ka: list[Any] = []
    params = CK_WTLS_KEY_MAT_PARAMS()
    params.DigestMechanism = digest_mechanism
    params.ulMacSizeInBits = mac_size_bits
    params.ulKeySizeInBits = key_size_bits
    params.ulIVSizeInBits = iv_size_bits
    params.ulSequenceNumber = sequence_number
    params.bIsExport = CK_BBOOL(1 if is_export else 0)
    _fill_wtls_random(params.RandomInfo, client_random, server_random, ka)

    key_mat_out = CK_WTLS_KEY_MAT_OUT()
    iv_bytes = iv_size_bits // 8 if iv_size_bits else 0
    if iv_bytes:
        iv_buf = (ctypes.c_ubyte * iv_bytes)()
        key_mat_out.pIV = ctypes.cast(iv_buf, CK_VOID_PTR)
        ka.append(iv_buf)
    ka.append(key_mat_out)
    params.pReturnedKeyMaterial = ctypes.cast(
        ctypes.pointer(key_mat_out),
        CK_VOID_PTR,
    )
    result = _mech_struct(mechanism_type, params, "mech_wtls_key_mat", ka)
    result._key_mat_out_ref = key_mat_out  # type: ignore[attr-defined]
    return result


def mech_wtls_prf(
    mechanism_type: CKM,
    digest_mechanism: int,
    seed: bytes,
    label: bytes,
    output_len: int,
) -> PackedMechanism:
    """Pack CK_WTLS_PRF_PARAMS.

    Used for CKM_WTLS_PRF.
    """
    ka: list[Any] = []
    params = CK_WTLS_PRF_PARAMS()
    params.DigestMechanism = digest_mechanism
    params.pSeed, params.ulSeedLen = _pack_bytes(seed, ka)
    params.pLabel, params.ulLabelLen = _pack_bytes(label, ka)
    out_buf = (ctypes.c_ubyte * output_len)()
    ka.append(out_buf)
    params.pOutput = ctypes.cast(out_buf, CK_VOID_PTR)
    out_len = CK_ULONG(output_len)
    ka.append(out_len)
    params.pulOutputLen = ctypes.cast(ctypes.pointer(out_len), CK_VOID_PTR)
    result = _mech_struct(mechanism_type, params, "mech_wtls_prf", ka)
    result._output_buf = out_buf  # type: ignore[attr-defined]
    result._output_len = out_len  # type: ignore[attr-defined]
    return result
