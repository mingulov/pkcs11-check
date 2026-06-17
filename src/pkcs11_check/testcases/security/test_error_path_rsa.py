"""RSA PKCS#1 v1.5 and OAEP error path exercisers.

All tests run in subprocess for crash safety. Each test generates an RSA 2048-bit
keypair, crafts a malformed ciphertext or signature, and calls C_Decrypt / C_Verify.
The module must return an error code cleanly -- never crash.

Covers:
- PKCS#1 v1.5: random bytes, truncated, extended, all-zeros, all-0xFF
- OAEP: random bytes, truncated
- Verify: corrupted (bit-flipped) signature
"""

from __future__ import annotations

from textwrap import indent
from typing import Any

import pytest

from pkcs11_check.raw.recipes import destroy_quietly
from pkcs11_check.raw.types_std import (
    CKA_DECRYPT,
    CKA_ENCRYPT,
    CKA_SIGN,
    CKA_TOKEN,
    CKA_VERIFY,
)
from pkcs11_check.testcases._subprocess_preamble import (
    pin_from_config,
    run_with_coverage,
    subprocess_session_preamble,
)
from pkcs11_check.testcases.conftest import gen_rsa_keypair_or_xfail
from pkcs11_check.testcases.security.conftest import assert_subprocess_no_crash

pytestmark = [pytest.mark.security, pytest.mark.subprocess]


def _preamble(p11_config: Any) -> str:
    """Build subprocess session preamble from p11_config."""
    return subprocess_session_preamble(
        str(p11_config.module),
        pin=p11_config.pin.get_secret_value() if p11_config.pin else None,
        slot_label="pkcs11-check",
    )


# ---------------------------------------------------------------------------
# Shared script fragments
# ---------------------------------------------------------------------------

_RSA_KEYGEN = """\
from pkcs11_check.raw.recipes import gen_rsa_keypair, read_attributes, destroy_quietly
from pkcs11_check.raw.types_std import (
    CKA_MODULUS, CKA_TOKEN, CKA_ENCRYPT, CKA_DECRYPT, CKA_TOKEN,
)

pub, priv = gen_rsa_keypair(
    raw, sh, 2048,
    private_attrs={int(CKA_DECRYPT): True, int(CKA_TOKEN): False},
    public_attrs={int(CKA_ENCRYPT): True, int(CKA_TOKEN): False},
)
try:
    attrs = read_attributes(raw, sh, pub, [int(CKA_MODULUS)])
    mod_bytes = attrs[int(CKA_MODULUS)]
    mod_len = len(mod_bytes)
"""

_RSA_CLEANUP = """\
finally:
    destroy_quietly(raw, sh, pub)
    destroy_quietly(raw, sh, priv)
cleanup()
"""

_PKCS_DECRYPT_BODY = """\
import ctypes
from pkcs11_check.raw.types_std import CK_MECHANISM, CK_ULONG, CKM_RSA_PKCS

mech = CK_MECHANISM()
mech.mechanism = CKM_RSA_PKCS
mech.pParameter = None
mech.ulParameterLen = 0
rv = raw.C_DecryptInit(sh, ctypes.byref(mech), priv)
if rv != 0:
    print(f"decrypt_init_rv={rv}")
else:
    ct_buf = (ctypes.c_ubyte * len(bad_ct))(*bad_ct)
    out_buf = (ctypes.c_ubyte * (mod_len + 16))()
    out_len = CK_ULONG(mod_len + 16)
    rv = raw.C_Decrypt(sh, ct_buf, len(bad_ct), out_buf, ctypes.byref(out_len))
    print(f"decrypt_rv={rv}")
"""

_OAEP_DECRYPT_BODY = """\
import ctypes
from pkcs11_check.raw.types_std import (
    CK_MECHANISM, CK_ULONG, CK_RSA_PKCS_OAEP_PARAMS,
    CKM_RSA_PKCS_OAEP, CKM_SHA256, CKG_MGF1_SHA256,
)

params = CK_RSA_PKCS_OAEP_PARAMS()
params.hashAlg = CKM_SHA256
params.mgf = CKG_MGF1_SHA256
params.source = 0
params.pSourceData = None
params.ulSourceDataLen = 0

mech = CK_MECHANISM()
mech.mechanism = CKM_RSA_PKCS_OAEP
mech.pParameter = ctypes.cast(ctypes.pointer(params), ctypes.c_void_p)
mech.ulParameterLen = ctypes.sizeof(params)

rv = raw.C_DecryptInit(sh, ctypes.byref(mech), priv)
if rv != 0:
    print(f"decrypt_init_rv={rv}")
else:
    ct_buf = (ctypes.c_ubyte * len(bad_ct))(*bad_ct)
    out_buf = (ctypes.c_ubyte * (mod_len + 16))()
    out_len = CK_ULONG(mod_len + 16)
    rv = raw.C_Decrypt(sh, ct_buf, len(bad_ct), out_buf, ctypes.byref(out_len))
    print(f"decrypt_rv={rv}")
"""


def _require_rsa_decrypt_setup(rs: Any) -> None:
    """Ensure the provider can create the setup key before spawning a crash probe."""
    pub = priv = 0
    try:
        pub, priv = gen_rsa_keypair_or_xfail(
            rs,
            2048,
            private_attrs={CKA_DECRYPT: True, CKA_TOKEN: False},
            public_attrs={CKA_ENCRYPT: True, CKA_TOKEN: False},
        )
    finally:
        destroy_quietly(rs.raw, rs.sh, pub)
        destroy_quietly(rs.raw, rs.sh, priv)


def _require_rsa_verify_setup(rs: Any) -> None:
    """Ensure the provider can create the setup key before spawning a crash probe."""
    pub = priv = 0
    try:
        pub, priv = gen_rsa_keypair_or_xfail(
            rs,
            2048,
            private_attrs={CKA_SIGN: True, CKA_TOKEN: False},
            public_attrs={CKA_VERIFY: True, CKA_TOKEN: False},
        )
    finally:
        destroy_quietly(rs.raw, rs.sh, pub)
        destroy_quietly(rs.raw, rs.sh, priv)


def _build_decrypt_script(
    p11_config: Any,
    *,
    bad_ct_code: str,
    body: str,
) -> str:
    """Assemble RSA decrypt error-path child script."""
    return _preamble(p11_config) + _RSA_KEYGEN + indent(bad_ct_code + body, "    ") + _RSA_CLEANUP


# ---------------------------------------------------------------------------
# RSA PKCS#1 v1.5 decrypt error paths
# ---------------------------------------------------------------------------


class TestRsaPkcsDecryptErrorPaths:
    """RSA PKCS#1 v1.5 decrypt with malformed ciphertext -- 5 corruption variants.

    Each test generates a fresh RSA 2048-bit keypair, crafts malformed input
    sized relative to the actual modulus, and calls C_DecryptInit + C_Decrypt.
    The module must return a CKR error, not crash.

    PKCS#11 v3.2: modules must validate ciphertext length and
    format before performing any decryption. Crashes are bugs.
    """

    def test_rsa_pkcs_decrypt_random_ciphertext(
        self,
        p11_raw_session: Any,
        p11_config: Any,
    ) -> None:
        """Random bytes (no PKCS#1 v1.5 0x00 0x02 header) -> C_Decrypt must error, not crash."""
        rs = p11_raw_session
        if not rs.has_mechanism("RSA_PKCS"):
            pytest.skip("CKM_RSA_PKCS not supported")
        _require_rsa_decrypt_setup(rs)

        bad_ct_code = "import os\nbad_ct = os.urandom(mod_len)\n"
        script = _build_decrypt_script(p11_config, bad_ct_code=bad_ct_code, body=_PKCS_DECRYPT_BODY)
        rc, stdout, stderr = run_with_coverage(script, timeout=15, pin=pin_from_config(p11_config))
        assert_subprocess_no_crash(
            rc, stdout, stderr, context="RSA_PKCS decrypt: random ciphertext"
        )

    def test_rsa_pkcs_decrypt_truncated(
        self,
        p11_raw_session: Any,
        p11_config: Any,
    ) -> None:
        """Ciphertext shorter than modulus (half length) -> C_Decrypt must error, not crash."""
        rs = p11_raw_session
        if not rs.has_mechanism("RSA_PKCS"):
            pytest.skip("CKM_RSA_PKCS not supported")
        _require_rsa_decrypt_setup(rs)

        bad_ct_code = "import os\nbad_ct = os.urandom(mod_len // 2)\n"
        script = _build_decrypt_script(p11_config, bad_ct_code=bad_ct_code, body=_PKCS_DECRYPT_BODY)
        rc, stdout, stderr = run_with_coverage(script, timeout=15, pin=pin_from_config(p11_config))
        assert_subprocess_no_crash(
            rc, stdout, stderr, context="RSA_PKCS decrypt: truncated ciphertext (half modulus)"
        )

    def test_rsa_pkcs_decrypt_extended(
        self,
        p11_raw_session: Any,
        p11_config: Any,
    ) -> None:
        """Ciphertext longer than modulus (modulus+16 bytes) -> C_Decrypt must error, not crash."""
        rs = p11_raw_session
        if not rs.has_mechanism("RSA_PKCS"):
            pytest.skip("CKM_RSA_PKCS not supported")
        _require_rsa_decrypt_setup(rs)

        bad_ct_code = "import os\nbad_ct = os.urandom(mod_len + 16)\n"
        script = _build_decrypt_script(p11_config, bad_ct_code=bad_ct_code, body=_PKCS_DECRYPT_BODY)
        rc, stdout, stderr = run_with_coverage(script, timeout=15, pin=pin_from_config(p11_config))
        assert_subprocess_no_crash(
            rc, stdout, stderr, context="RSA_PKCS decrypt: extended ciphertext (modulus + 16)"
        )

    def test_rsa_pkcs_decrypt_all_zeros(
        self,
        p11_raw_session: Any,
        p11_config: Any,
    ) -> None:
        """Modulus-length all-zero ciphertext (no 0x00 0x02 header) -> must error, not crash."""
        rs = p11_raw_session
        if not rs.has_mechanism("RSA_PKCS"):
            pytest.skip("CKM_RSA_PKCS not supported")
        _require_rsa_decrypt_setup(rs)

        bad_ct_code = "bad_ct = bytes(mod_len)\n"
        script = _build_decrypt_script(p11_config, bad_ct_code=bad_ct_code, body=_PKCS_DECRYPT_BODY)
        rc, stdout, stderr = run_with_coverage(script, timeout=15, pin=pin_from_config(p11_config))
        assert_subprocess_no_crash(
            rc, stdout, stderr, context="RSA_PKCS decrypt: all-zero ciphertext"
        )

    def test_rsa_pkcs_decrypt_all_ff(
        self,
        p11_raw_session: Any,
        p11_config: Any,
    ) -> None:
        """Modulus-length 0xFF ciphertext -> must error, not crash."""
        rs = p11_raw_session
        if not rs.has_mechanism("RSA_PKCS"):
            pytest.skip("CKM_RSA_PKCS not supported")
        _require_rsa_decrypt_setup(rs)

        bad_ct_code = "bad_ct = b'\\xff' * mod_len\n"
        script = _build_decrypt_script(p11_config, bad_ct_code=bad_ct_code, body=_PKCS_DECRYPT_BODY)
        rc, stdout, stderr = run_with_coverage(script, timeout=15, pin=pin_from_config(p11_config))
        assert_subprocess_no_crash(
            rc, stdout, stderr, context="RSA_PKCS decrypt: all-0xFF ciphertext"
        )


# ---------------------------------------------------------------------------
# RSA OAEP decrypt error paths
# ---------------------------------------------------------------------------


class TestRsaOaepDecryptErrorPaths:
    """RSA OAEP decrypt with malformed ciphertext -- 2 corruption variants.

    Each test generates a fresh RSA 2048-bit keypair and crafts malformed
    OAEP input. The module must return a CKR error, not crash.

    PKCS#11 v3.2: OAEP ciphertext validation must not cause
    heap overflow or undefined behaviour on invalid input.
    """

    def test_rsa_oaep_decrypt_random_ciphertext(
        self,
        p11_raw_session: Any,
        p11_config: Any,
    ) -> None:
        """Random bytes -> OAEP C_Decrypt must error, not crash."""
        rs = p11_raw_session
        if not rs.has_mechanism("RSA_PKCS_OAEP"):
            pytest.skip("CKM_RSA_PKCS_OAEP not supported")
        _require_rsa_decrypt_setup(rs)

        bad_ct_code = "import os\nbad_ct = os.urandom(mod_len)\n"
        script = _build_decrypt_script(p11_config, bad_ct_code=bad_ct_code, body=_OAEP_DECRYPT_BODY)
        rc, stdout, stderr = run_with_coverage(script, timeout=15, pin=pin_from_config(p11_config))
        assert_subprocess_no_crash(
            rc, stdout, stderr, context="RSA_PKCS_OAEP decrypt: random ciphertext"
        )

    def test_rsa_oaep_decrypt_truncated(
        self,
        p11_raw_session: Any,
        p11_config: Any,
    ) -> None:
        """Truncated OAEP ciphertext (half modulus length) -> must error, not crash."""
        rs = p11_raw_session
        if not rs.has_mechanism("RSA_PKCS_OAEP"):
            pytest.skip("CKM_RSA_PKCS_OAEP not supported")
        _require_rsa_decrypt_setup(rs)

        bad_ct_code = "import os\nbad_ct = os.urandom(mod_len // 2)\n"
        script = _build_decrypt_script(p11_config, bad_ct_code=bad_ct_code, body=_OAEP_DECRYPT_BODY)
        rc, stdout, stderr = run_with_coverage(script, timeout=15, pin=pin_from_config(p11_config))
        assert_subprocess_no_crash(
            rc, stdout, stderr, context="RSA_PKCS_OAEP decrypt: truncated ciphertext (half modulus)"
        )


# ---------------------------------------------------------------------------
# RSA signature verify with corrupted signature
# ---------------------------------------------------------------------------


class TestRsaVerifyCorruptedSignature:
    """RSA verify with a bit-flipped signature -- must return verification failure, not crash.

    Signs valid data, flips the first bit of the signature, then calls
    C_VerifyInit + C_Verify. The module must return CKR_SIGNATURE_INVALID
    or CKR_SIGNATURE_LEN_RANGE cleanly.

    PKCS#11 v3.2: C_Verify must validate the signature and return
    CKR_SIGNATURE_INVALID for a non-matching signature -- never crash.
    """

    def test_rsa_verify_corrupted_signature(
        self,
        p11_raw_session: Any,
        p11_config: Any,
    ) -> None:
        """Sign valid data, flip a bit in signature, verify -> must return error, not crash."""
        rs = p11_raw_session
        if not rs.has_mechanism("SHA256_RSA_PKCS"):
            pytest.skip("CKM_SHA256_RSA_PKCS not supported")
        _require_rsa_verify_setup(rs)

        preamble = _preamble(p11_config)
        body = """\
from pkcs11_check.raw.recipes import gen_rsa_keypair, read_attributes, destroy_quietly
from pkcs11_check.raw.recipes import sign_single
from pkcs11_check.raw.types_std import (
    CKA_MODULUS, CKA_TOKEN, CKA_SIGN, CKA_VERIFY,
    CK_MECHANISM, CK_ULONG, CKM_SHA256_RSA_PKCS,
)
import ctypes

pub, priv = gen_rsa_keypair(
    raw, sh, 2048,
    private_attrs={int(CKA_SIGN): True, int(CKA_TOKEN): False},
    public_attrs={int(CKA_VERIFY): True, int(CKA_TOKEN): False},
)
try:
    # Sign valid data to get a well-formed signature
    sig = sign_single(raw, sh, priv, CKM_SHA256_RSA_PKCS, b"test data for verification")

    # Flip first bit in signature to corrupt it
    bad_sig = bytearray(sig)
    bad_sig[0] ^= 0x01
    bad_sig_bytes = bytes(bad_sig)

    # Attempt verify with corrupted signature
    data = b"test data for verification"
    mech = CK_MECHANISM()
    mech.mechanism = CKM_SHA256_RSA_PKCS
    mech.pParameter = None
    mech.ulParameterLen = 0
    rv = raw.C_VerifyInit(sh, ctypes.byref(mech), pub)
    if rv != 0:
        print(f"verify_init_rv={rv}")
    else:
        data_buf = (ctypes.c_ubyte * len(data))(*data)
        sig_buf = (ctypes.c_ubyte * len(bad_sig_bytes))(*bad_sig_bytes)
        rv = raw.C_Verify(sh, data_buf, len(data), sig_buf, len(bad_sig_bytes))
        print(f"verify_rv={rv}")
finally:
    destroy_quietly(raw, sh, pub)
    destroy_quietly(raw, sh, priv)
cleanup()
"""
        script = preamble + body
        rc, stdout, stderr = run_with_coverage(script, timeout=15, pin=pin_from_config(p11_config))
        assert_subprocess_no_crash(
            rc,
            stdout,
            stderr,
            context="RSA SHA256_RSA_PKCS verify: corrupted (bit-flipped) signature",
        )
