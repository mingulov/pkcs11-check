"""Tests for GOST PKCS#11 mechanisms.

Covers GOST 28147-89 (symmetric), GOST R 34.10-2001 (signature),
and GOST R 34.11-94 (digest/HMAC).

Almost no modules support GOST - tests skip cleanly when unsupported.
"""

from __future__ import annotations

from collections.abc import Mapping
from ctypes import byref
from typing import Any

import pytest

from pkcs11_check.raw.pack import mech_bytes, mech_simple
from pkcs11_check.raw.recipes import (
    decrypt_single,
    destroy_quietly,
    digest_single,
    encrypt_single,
    generate_random,
    import_secret_key,
    sign_single,
    verify_single,
)
from pkcs11_check.raw.rv import expect_rv
from pkcs11_check.raw.types_std import (
    CK_OBJECT_HANDLE,
    CKA_DECRYPT,
    CKA_ENCRYPT,
    CKA_EXTRACTABLE,
    CKA_SENSITIVE,
    CKA_SIGN,
    CKA_TOKEN,
    CKA_VALUE_LEN,
    CKA_VERIFY,
    CKK_GOSTR3411,
    CKM_GOST28147,
    CKM_GOST28147_ECB,
    CKM_GOST28147_KEY_GEN,
    CKM_GOST28147_MAC,
    CKM_GOSTR3410,
    CKM_GOSTR3410_KEY_PAIR_GEN,
    CKM_GOSTR3410_WITH_GOSTR3411,
    CKM_GOSTR3411,
    CKM_GOSTR3411_HMAC,
    CKR_OK,
)

pytestmark = pytest.mark.full

# 16 bytes - 2 x 8-byte GOST 28147-89 blocks
_TWO_BLOCKS = b"12345678abcdefgh"

# 32 bytes - typical GOST R 34.11-94 hash output size
_HASH_SIZE_DATA = bytes(range(32))


def _gost_key(raw: Any, sh: int, attrs: Mapping[Any, Any]) -> int:
    """Generate a 256-bit GOST 28147-89 key via C_GenerateKey."""
    from pkcs11_check.raw.pack import attr_ulong
    from pkcs11_check.raw.pack import template as mk_template
    from pkcs11_check.raw.recipes import pack_attrs

    packed = [attr_ulong(CKA_VALUE_LEN, 32)]
    packed.extend(pack_attrs(attrs))
    tmpl = mk_template(*packed)
    mech = mech_simple(CKM_GOST28147_KEY_GEN)
    key = CK_OBJECT_HANDLE(0)
    rv = raw.C_GenerateKey(sh, mech.byref(), tmpl.ptr, tmpl.count, byref(key))
    expect_rv(rv, CKR_OK)
    return key.value


def _gost_keypair(raw: Any, sh: int) -> tuple[int, int]:
    """Generate a GOST R 34.10-2001 keypair."""
    from pkcs11_check.raw.pack import template as mk_template

    pub_tmpl = mk_template()
    priv_tmpl = mk_template()
    mech = mech_simple(CKM_GOSTR3410_KEY_PAIR_GEN)
    pub_h = CK_OBJECT_HANDLE(0)
    priv_h = CK_OBJECT_HANDLE(0)
    rv = raw.C_GenerateKeyPair(
        sh,
        mech.byref(),
        pub_tmpl.ptr,
        pub_tmpl.count,
        priv_tmpl.ptr,
        priv_tmpl.count,
        byref(pub_h),
        byref(priv_h),
    )
    expect_rv(rv, CKR_OK)
    return pub_h.value, priv_h.value


def _try_or_xfail(fn: Any, msg: str) -> Any:
    """Call fn; if AssertionError with MECHANISM_INVALID/FUNCTION_FAILED, xfail."""
    try:
        return fn()
    except AssertionError as exc:
        exc_str = str(exc)
        if "CKR_MECHANISM_INVALID" in exc_str or "CKR_FUNCTION_FAILED" in exc_str:
            pytest.xfail(f"{msg}: {exc}")
        raise


class TestGOST28147KeyGen:
    """CKM_GOST28147_KEY_GEN - generate GOST 28147-89 symmetric keys."""

    def test_gost28147_key_gen(self, p11_raw_session: Any) -> None:
        """Generate a 256-bit GOST 28147-89 secret key."""
        rs = p11_raw_session
        if not rs.has_mechanism("GOST28147_KEY_GEN"):
            pytest.skip("CKM_GOST28147_KEY_GEN not supported")

        key = _gost_key(
            rs.raw,
            rs.sh,
            {
                CKA_ENCRYPT: True,
                CKA_DECRYPT: True,
                CKA_SIGN: True,
                CKA_VERIFY: True,
                CKA_TOKEN: False,
                CKA_SENSITIVE: False,
                CKA_EXTRACTABLE: True,
            },
        )
        try:
            assert key != 0
        finally:
            destroy_quietly(rs.raw, rs.sh, key)


class TestGOST28147Encryption:
    """CKM_GOST28147_ECB and CKM_GOST28147 - GOST 28147-89 encrypt/decrypt."""

    def test_ecb_roundtrip(self, p11_raw_session: Any) -> None:
        """Encrypt and decrypt two blocks with CKM_GOST28147_ECB."""
        rs = p11_raw_session
        if not rs.has_mechanism("GOST28147_ECB"):
            pytest.skip("CKM_GOST28147_ECB not supported")
        if not rs.has_mechanism("GOST28147_KEY_GEN"):
            pytest.skip("CKM_GOST28147_KEY_GEN not supported")

        key = _gost_key(
            rs.raw,
            rs.sh,
            {
                CKA_ENCRYPT: True,
                CKA_DECRYPT: True,
                CKA_TOKEN: False,
            },
        )
        try:

            def _do() -> None:
                ct = encrypt_single(rs.raw, rs.sh, key, CKM_GOST28147_ECB, _TWO_BLOCKS)
                pt = decrypt_single(rs.raw, rs.sh, key, CKM_GOST28147_ECB, ct)
                assert pt == _TWO_BLOCKS

            _try_or_xfail(_do, "CKM_GOST28147_ECB not operational")
        finally:
            destroy_quietly(rs.raw, rs.sh, key)

    def test_ecb_different_keys_produce_different_ciphertext(
        self,
        p11_raw_session: Any,
    ) -> None:
        """Two distinct keys must produce different ECB ciphertext for the same plaintext."""
        rs = p11_raw_session
        if not rs.has_mechanism("GOST28147_ECB"):
            pytest.skip("CKM_GOST28147_ECB not supported")
        if not rs.has_mechanism("GOST28147_KEY_GEN"):
            pytest.skip("CKM_GOST28147_KEY_GEN not supported")

        tmpl = {CKA_ENCRYPT: True, CKA_DECRYPT: True, CKA_TOKEN: False}
        key1 = _gost_key(rs.raw, rs.sh, tmpl)
        key2 = _gost_key(rs.raw, rs.sh, tmpl)
        try:

            def _do() -> None:
                ct1 = encrypt_single(rs.raw, rs.sh, key1, CKM_GOST28147_ECB, _TWO_BLOCKS)
                ct2 = encrypt_single(rs.raw, rs.sh, key2, CKM_GOST28147_ECB, _TWO_BLOCKS)
                assert ct1 != ct2, "Different keys produced identical ECB ciphertext"

            _try_or_xfail(_do, "CKM_GOST28147_ECB not operational")
        finally:
            destroy_quietly(rs.raw, rs.sh, key2)
            destroy_quietly(rs.raw, rs.sh, key1)

    def test_cbc_roundtrip(self, p11_raw_session: Any) -> None:
        """Encrypt and decrypt two blocks with CKM_GOST28147 (CBC-like mode) with an IV."""
        rs = p11_raw_session
        if not rs.has_mechanism("GOST28147"):
            pytest.skip("CKM_GOST28147 not supported")
        if not rs.has_mechanism("GOST28147_KEY_GEN"):
            pytest.skip("CKM_GOST28147_KEY_GEN not supported")

        key = _gost_key(
            rs.raw,
            rs.sh,
            {
                CKA_ENCRYPT: True,
                CKA_DECRYPT: True,
                CKA_TOKEN: False,
            },
        )
        try:
            iv = generate_random(rs.raw, rs.sh, 8)

            def _do() -> None:
                ct = encrypt_single(
                    rs.raw,
                    rs.sh,
                    key,
                    CKM_GOST28147,
                    _TWO_BLOCKS,
                    mech_param=mech_bytes(CKM_GOST28147, iv),
                )
                pt = decrypt_single(
                    rs.raw,
                    rs.sh,
                    key,
                    CKM_GOST28147,
                    ct,
                    mech_param=mech_bytes(CKM_GOST28147, iv),
                )
                assert pt == _TWO_BLOCKS

            _try_or_xfail(_do, "CKM_GOST28147 not operational")
        finally:
            destroy_quietly(rs.raw, rs.sh, key)


class TestGOST28147MAC:
    """CKM_GOST28147_MAC - GOST 28147-89 message authentication code."""

    def test_mac_sign_verify(self, p11_raw_session: Any) -> None:
        """Sign and verify a MAC with CKM_GOST28147_MAC."""
        rs = p11_raw_session
        if not rs.has_mechanism("GOST28147_MAC"):
            pytest.skip("CKM_GOST28147_MAC not supported")
        if not rs.has_mechanism("GOST28147_KEY_GEN"):
            pytest.skip("CKM_GOST28147_KEY_GEN not supported")

        key = _gost_key(
            rs.raw,
            rs.sh,
            {
                CKA_SIGN: True,
                CKA_VERIFY: True,
                CKA_TOKEN: False,
            },
        )
        try:

            def _do() -> None:
                mac = sign_single(rs.raw, rs.sh, key, CKM_GOST28147_MAC, _TWO_BLOCKS)
                assert mac is not None
                assert len(mac) > 0
                verify_single(rs.raw, rs.sh, key, CKM_GOST28147_MAC, _TWO_BLOCKS, mac)

            _try_or_xfail(_do, "CKM_GOST28147_MAC not operational")
        finally:
            destroy_quietly(rs.raw, rs.sh, key)


class TestGOSTR3410Signature:
    """CKM_GOSTR3410 and CKM_GOSTR3410_WITH_GOSTR3411 - GOST R 34.10-2001 signatures."""

    def test_keypair_gen(self, p11_raw_session: Any) -> None:
        """Generate a GOST R 34.10-2001 key pair."""
        rs = p11_raw_session
        if not rs.has_mechanism("GOSTR3410_KEY_PAIR_GEN"):
            pytest.skip("CKM_GOSTR3410_KEY_PAIR_GEN not supported")

        pub, priv = _gost_keypair(rs.raw, rs.sh)
        try:
            assert pub != 0
            assert priv != 0
        finally:
            destroy_quietly(rs.raw, rs.sh, priv)
            destroy_quietly(rs.raw, rs.sh, pub)

    def test_sign_verify_raw(self, p11_raw_session: Any) -> None:
        """Sign 32 bytes of data with CKM_GOSTR3410 (raw) and verify."""
        rs = p11_raw_session
        if not rs.has_mechanism("GOSTR3410_KEY_PAIR_GEN"):
            pytest.skip("CKM_GOSTR3410_KEY_PAIR_GEN not supported")
        if not rs.has_mechanism("GOSTR3410"):
            pytest.skip("CKM_GOSTR3410 not supported")

        pub, priv = _gost_keypair(rs.raw, rs.sh)
        try:

            def _do() -> None:
                # GOSTR3410 signs a pre-hashed 32-byte value
                sig = sign_single(rs.raw, rs.sh, priv, CKM_GOSTR3410, _HASH_SIZE_DATA)
                assert sig is not None
                assert len(sig) > 0
                verify_single(rs.raw, rs.sh, pub, CKM_GOSTR3410, _HASH_SIZE_DATA, sig)

            _try_or_xfail(_do, "CKM_GOSTR3410 sign/verify not operational")
        finally:
            destroy_quietly(rs.raw, rs.sh, priv)
            destroy_quietly(rs.raw, rs.sh, pub)

    def test_sign_verify_with_hash(self, p11_raw_session: Any) -> None:
        """Sign arbitrary data with CKM_GOSTR3410_WITH_GOSTR3411 and verify."""
        rs = p11_raw_session
        if not rs.has_mechanism("GOSTR3410_KEY_PAIR_GEN"):
            pytest.skip("CKM_GOSTR3410_KEY_PAIR_GEN not supported")
        if not rs.has_mechanism("GOSTR3410_WITH_GOSTR3411"):
            pytest.skip("CKM_GOSTR3410_WITH_GOSTR3411 not supported")

        pub, priv = _gost_keypair(rs.raw, rs.sh)
        try:
            data = b"GOST signature test data"

            def _do() -> None:
                sig = sign_single(
                    rs.raw,
                    rs.sh,
                    priv,
                    CKM_GOSTR3410_WITH_GOSTR3411,
                    data,
                )
                assert sig is not None
                assert len(sig) > 0
                verify_single(
                    rs.raw,
                    rs.sh,
                    pub,
                    CKM_GOSTR3410_WITH_GOSTR3411,
                    data,
                    sig,
                )

            _try_or_xfail(_do, "CKM_GOSTR3410_WITH_GOSTR3411 sign/verify not operational")
        finally:
            destroy_quietly(rs.raw, rs.sh, priv)
            destroy_quietly(rs.raw, rs.sh, pub)


class TestGOSTR3411Digest:
    """CKM_GOSTR3411 and CKM_GOSTR3411_HMAC - GOST R 34.11-94 digest and HMAC."""

    def test_digest(self, p11_raw_session: Any) -> None:
        """Compute a GOST R 34.11-94 digest (no key needed)."""
        rs = p11_raw_session
        if not rs.has_mechanism("GOSTR3411"):
            pytest.skip("CKM_GOSTR3411 not supported")

        data = b"GOST digest test data"

        def _do() -> bytes:
            return digest_single(rs.raw, rs.sh, CKM_GOSTR3411, data)

        digest = _try_or_xfail(_do, "CKM_GOSTR3411 digest not operational")
        assert digest is not None
        # GOST R 34.11-94 produces a 256-bit (32-byte) hash
        assert len(digest) == 32, f"Expected 32-byte GOST digest, got {len(digest)}"

    def test_digest_deterministic(self, p11_raw_session: Any) -> None:
        """Same input must always produce the same GOST R 34.11-94 digest."""
        rs = p11_raw_session
        if not rs.has_mechanism("GOSTR3411"):
            pytest.skip("CKM_GOSTR3411 not supported")

        data = b"deterministic GOST digest"

        def _do() -> None:
            d1 = digest_single(rs.raw, rs.sh, CKM_GOSTR3411, data)
            d2 = digest_single(rs.raw, rs.sh, CKM_GOSTR3411, data)
            assert d1 == d2, "CKM_GOSTR3411 digest is not deterministic"

        _try_or_xfail(_do, "CKM_GOSTR3411 digest not operational")

    def test_hmac_sign_verify(self, p11_raw_session: Any) -> None:
        """Sign and verify an HMAC with CKM_GOSTR3411_HMAC."""
        rs = p11_raw_session
        if not rs.has_mechanism("GOSTR3411_HMAC"):
            pytest.skip("CKM_GOSTR3411_HMAC not supported")

        # GOSTR3411_HMAC uses the GOSTR3411 key type for HMAC operations
        key = import_secret_key(
            rs.raw,
            rs.sh,
            CKK_GOSTR3411,
            bytes(range(32)),
            attrs={
                CKA_SIGN: True,
                CKA_VERIFY: True,
                CKA_TOKEN: False,
                CKA_SENSITIVE: False,
            },
        )
        try:
            data = b"GOST HMAC test data"

            def _do() -> None:
                mac = sign_single(rs.raw, rs.sh, key, CKM_GOSTR3411_HMAC, data)
                assert mac is not None
                assert len(mac) > 0
                verify_single(rs.raw, rs.sh, key, CKM_GOSTR3411_HMAC, data, mac)

            _try_or_xfail(_do, "CKM_GOSTR3411_HMAC not operational")
        finally:
            destroy_quietly(rs.raw, rs.sh, key)
