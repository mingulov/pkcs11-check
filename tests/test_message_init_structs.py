"""Init-arm struct regression tests (sibling Wave 3 §7.3 CCM claim)."""

from __future__ import annotations

from types import SimpleNamespace


def _ccm_entry() -> SimpleNamespace:
    recipe = SimpleNamespace(style="ccm", defaults={"nonce_len": 12, "data_len": 32, "mac_len": 16})
    config = SimpleNamespace(param_required=True, param_recipe=recipe)
    from pkcs11_check.raw.types_std import CKM_AES_CCM

    return SimpleNamespace(config=config, mech_id=int(CKM_AES_CCM), mech_name="AES_CCM")


def test_message_init_ccm_arm_packs_message_struct() -> None:
    from pkcs11_check.raw.types_std import CK_CCM_MESSAGE_PARAMS
    from pkcs11_check.testcases.test_mech_message import _message_init_mech_or_skip

    packed = _message_init_mech_or_skip(_ccm_entry())
    assert isinstance(packed.params, CK_CCM_MESSAGE_PARAMS)
    assert packed.params.ulNonceLen == 12
    assert packed.params.ulMACLen == 16


def _chacha_entry() -> SimpleNamespace:
    recipe = SimpleNamespace(style="chacha20_poly1305", defaults={"nonce_len": 12})
    config = SimpleNamespace(param_required=True, param_recipe=recipe)
    from pkcs11_check.raw.types_std import CKM_CHACHA20_POLY1305

    return SimpleNamespace(
        config=config, mech_id=int(CKM_CHACHA20_POLY1305), mech_name="CHACHA20_POLY1305"
    )


def test_message_init_chacha_arm_packs_message_struct() -> None:
    from pkcs11_check.raw.types_std import CK_SALSA20_CHACHA20_POLY1305_MSG_PARAMS
    from pkcs11_check.testcases.test_mech_message import _message_init_mech_or_skip

    packed = _message_init_mech_or_skip(_chacha_entry())
    assert isinstance(packed.params, CK_SALSA20_CHACHA20_POLY1305_MSG_PARAMS)
    assert packed.params.ulNonceLen == 12
    assert packed.buffer_bytes("tag") == b"\x00" * 16


def _salsa_entry() -> SimpleNamespace:
    recipe = SimpleNamespace(style="salsa20_poly1305", defaults={"nonce_len": 8})
    config = SimpleNamespace(param_required=True, param_recipe=recipe)
    from pkcs11_check.raw.types_std import CKM_SALSA20_POLY1305

    return SimpleNamespace(
        config=config, mech_id=int(CKM_SALSA20_POLY1305), mech_name="SALSA20_POLY1305"
    )


def test_message_init_salsa_arm_packs_message_struct() -> None:
    from pkcs11_check.raw.types_std import CK_SALSA20_CHACHA20_POLY1305_MSG_PARAMS
    from pkcs11_check.testcases.test_mech_message import _message_init_mech_or_skip

    packed = _message_init_mech_or_skip(_salsa_entry())
    assert isinstance(packed.params, CK_SALSA20_CHACHA20_POLY1305_MSG_PARAMS)
    assert packed.params.ulNonceLen == 8
    assert packed.buffer_bytes("tag") == b"\x00" * 16
