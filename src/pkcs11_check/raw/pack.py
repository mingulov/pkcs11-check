"""Helpers for building exact raw PKCS#11 values with owned storage."""

from __future__ import annotations

import ctypes
from dataclasses import dataclass
from typing import Any

from .types_std import (
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
    CK_ULONG,
    CK_VOID_PTR,
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
    aad_len: int = 0,
    tag_bits: int = 128,
) -> PackedMechanism:
    """Pack CK_AES_GCM_PARAMS."""
    ka: list[Any] = []
    params = CK_AES_GCM_PARAMS()
    params.pIv, params.ulIvLen = _pack_bytes(iv, ka)
    params.ulIvBits = params.ulIvLen * 8
    params.pAAD = None
    params.ulAADLen = aad_len
    params.ulTagBits = tag_bits
    return _mech_struct(mechanism_type, params, "mech_gcm", ka)


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
    params.pSourceData, params.ulSourceDataLen = _pack_bytes(
        source_data, ka
    )
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
    params.pPublicData, params.ulPublicDataLen = _pack_bytes(
        public_data, ka
    )
    params.pSharedData, params.ulSharedDataLen = _pack_bytes(
        shared_data, ka
    )
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
